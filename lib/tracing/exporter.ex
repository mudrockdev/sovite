defmodule Sovite.Tracing.Exporter do
  @moduledoc false
  # The process behind `Sovite.Tracing`: attaches the handlers, buffers
  # the spans they cast, and posts them in batches from a task, one at a
  # time, so the buffer keeps filling while a request is in flight.

  use GenServer

  alias Sovite.Tracing.{Handler, OTLP}

  @doc false
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: opts[:name])

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    uri = URI.parse(opts[:endpoint])
    {:ok, _} = Application.ensure_all_started(:inets)
    if uri.scheme == "https", do: {:ok, _} = Application.ensure_all_started(:ssl)

    definitions = Enum.with_index(opts[:spans], fn definition, id -> %{definition | id: id} end)

    handlers =
      Handler.attach(opts[:name], definitions, Handler.threshold(opts[:sample_ratio] * 1.0))

    config = %{
      name: opts[:name],
      url: String.to_charlist(opts[:endpoint]),
      headers:
        [{~c"user-agent", ~c"sovite"}] ++
          for({name, value} <- opts[:headers], do: {to_charlist(name), to_charlist(value)}),
      ssl: ssl(uri, opts[:cacerts]),
      timeout: opts[:timeout],
      resource: resource(opts[:service_name], opts[:resource]),
      scope: opts[:scope]
    }

    state = %{
      config: config,
      handlers: handlers,
      max_queue: opts[:max_queue],
      batch_size: opts[:batch_size],
      interval: opts[:interval],
      shutdown_timeout: opts[:shutdown_timeout],
      queue: :queue.new(),
      count: 0,
      dropped: 0,
      task: nil,
      task_size: 0,
      due: false,
      accepted: 0,
      done: 0,
      waiters: []
    }

    schedule(state)
    {:ok, state}
  end

  defp ssl(%URI{scheme: "https", host: host}, cacerts) do
    [
      ssl:
        Sovite.TLS.client_options(
          verify: :peer,
          hostname: host,
          cacerts: cacerts || :public_key.cacerts_get()
        )
    ]
  end

  defp ssl(_uri, _cacerts), do: []

  defp resource(service_name, resource) do
    resource
    |> Map.new(fn {key, value} -> {to_string(key), value} end)
    |> Map.put("service.name", service_name)
  end

  defp schedule(state), do: Process.send_after(self(), :tick, state.interval)

  @impl true
  def handle_cast({:span, span}, state), do: {:noreply, state |> buffer(span) |> maybe_export()}

  @impl true
  def handle_call(:flush, _from, %{done: done, accepted: accepted} = state) when done >= accepted,
    do: {:reply, :ok, state}

  def handle_call(:flush, from, state),
    do: {:noreply, maybe_export(%{state | waiters: [{state.accepted, from} | state.waiters]})}

  @impl true
  def handle_info(:tick, state) do
    schedule(state)
    state = report_dropped(state)
    {:noreply, maybe_export(%{state | due: state.count > 0})}
  end

  def handle_info({ref, _result}, %{task: %Task{ref: ref}} = state) do
    Process.demonitor(ref, [:flush])
    {:noreply, exported(state)}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{task: %Task{ref: ref}} = state),
    do: {:noreply, exported(state)}

  # The export task's link.
  def handle_info({:EXIT, _pid, _reason}, state), do: {:noreply, state}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    Handler.detach(state.handlers)
    deadline = System.monotonic_time(:millisecond) + state.shutdown_timeout
    state = drain(state)

    if state.task, do: Task.yield(state.task, remaining(deadline)) || Task.shutdown(state.task)

    state |> report_dropped() |> final_export(deadline)
  end

  # Spans cast before the exit signal arrived.
  defp drain(state) do
    receive do
      {:"$gen_cast", {:span, span}} -> state |> buffer(span) |> drain()
    after
      0 -> state
    end
  end

  defp final_export(%{count: 0}, _deadline), do: :ok

  defp final_export(state, deadline) do
    case remaining(deadline) do
      0 ->
        :ok

      time_left ->
        {batch, state} = take(state)
        export(batch, state.config, min(time_left, state.config.timeout))
        final_export(state, deadline)
    end
  end

  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)

  ## Buffer

  defp buffer(%{count: count, max_queue: max} = state, _span) when count >= max,
    do: %{state | dropped: state.dropped + 1}

  defp buffer(state, span) do
    %{
      state
      | queue: :queue.in(span, state.queue),
        count: state.count + 1,
        accepted: state.accepted + 1
    }
  end

  defp take(state) do
    size = min(state.count, state.batch_size)
    {batch, queue} = :queue.split(size, state.queue)
    {:queue.to_list(batch), %{state | queue: queue, count: state.count - size}}
  end

  defp report_dropped(%{dropped: 0} = state), do: state

  defp report_dropped(state) do
    :telemetry.execute([:sovite, :tracing, :spans, :dropped], %{spans: state.dropped}, %{
      name: state.config.name
    })

    %{state | dropped: 0}
  end

  ## Export

  defp maybe_export(%{task: nil, count: count} = state) when count > 0 do
    if count >= state.batch_size or state.due or state.waiters != [] do
      {batch, state} = take(state)
      config = state.config
      task = Task.async(fn -> export(batch, config, config.timeout) end)
      %{state | task: task, task_size: length(batch), due: false}
    else
      state
    end
  end

  defp maybe_export(state), do: state

  defp exported(state) do
    done = state.done + state.task_size
    {ready, waiting} = Enum.split_with(state.waiters, fn {target, _from} -> target <= done end)
    for {_target, from} <- ready, do: GenServer.reply(from, :ok)
    maybe_export(%{state | task: nil, task_size: 0, done: done, waiters: waiting})
  end

  defp export(spans, config, timeout) do
    start = System.monotonic_time()

    result =
      try do
        post(OTLP.encode(spans, config.resource, config.scope), config, timeout)
      catch
        kind, reason -> {:error, {kind, reason}}
      end

    case result do
      :ok ->
        :telemetry.execute(
          [:sovite, :tracing, :export, :stop],
          %{spans: length(spans), duration: System.monotonic_time() - start},
          %{name: config.name}
        )

      {:error, reason} ->
        :telemetry.execute([:sovite, :tracing, :export, :error], %{spans: length(spans)}, %{
          name: config.name,
          reason: reason
        })
    end
  end

  defp post(body, config, timeout) do
    request = {config.url, config.headers, ~c"application/json", body}
    http_opts = [timeout: timeout, connect_timeout: timeout, autoredirect: false] ++ config.ssl

    case :httpc.request(:post, request, http_opts, body_format: :binary) do
      {:ok, {{_, status, _}, _headers, _body}} when status in 200..299 -> :ok
      {:ok, {{_, status, _}, _headers, _body}} -> {:error, {:http_status, status}}
      {:error, reason} -> {:error, reason}
    end
  end
end
