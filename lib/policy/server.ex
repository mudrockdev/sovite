defmodule Sovite.Policy.Server do
  @moduledoc """
  A policy server: a `Sovite.Listener` whose connections speak the policy
  delegation protocol, with the decisions made by a
  `Sovite.Policy.Handler`.

      children = [
        {Sovite.Policy.Server, port: 10023, ip: {127, 0, 0, 1}, handler: {Greylist, []}}
      ]

  Postfix can then ask it with `check_policy_service inet:127.0.0.1:10023`.
  The server is also a `Sovite.Listener.Handler`, so it can be given to
  a listener directly, with the server options as `:handler_opts`:

      {Sovite.Listener, port: 10023, handler: Sovite.Policy.Server, handler_opts: [handler: {Greylist, []}]}

  Each connection serves requests one after the other until the client
  closes it. A request that is malformed (a line that is not
  `name=value`, or an empty one), has a line over `:max_line` bytes or
  more than `:max_attributes` attributes, or is not complete within
  `:idle_timeout` of the previous reply (or of the connection), closes
  the connection without a reply. When a name comes more than once in a
  request, the last value wins.

  ## Options

  Listener options (see `Sovite.Listener`): `:port`, `:ip`, `:id`,
  `:name`, `:acceptors`, `:max_connections`, `:max_connections_per_ip`.

    * `:handler` - `{module, opts}` or `module`, a `Sovite.Policy.Handler`.
      Required.
    * `:max_line` - bytes of a request line. Defaults to 8192.
    * `:max_attributes` - attributes of a request. Defaults to 100.
    * `:idle_timeout` - milliseconds. Defaults to 300 seconds, like
      Postfix's `max_idle`.

  ## Telemetry

    * `[:sovite, :policy, :server, :request, :stop]` - `%{duration}`,
      `%{listener, remote_ip, attributes, action}`, for each request.
      `duration` is the time spent in the handler, `attributes` the
      request, and `action` the text sent, or `nil` when the handler
      closed the connection.
    * `[:sovite, :policy, :server, :error]` - `%{}`, `%{listener,
      remote_ip, reason}`, when a request closes the connection.
      `reason` is `:malformed`, `:line_too_long`, `:too_many_attributes`,
      or `:timeout`.
  """

  @behaviour Sovite.Listener.Handler

  alias Sovite.Policy
  alias Sovite.Policy.{Action, Codec}

  @listener_keys [:port, :ip, :id, :name, :acceptors, :max_connections, :max_connections_per_ip]
  @defaults [max_line: 8192, max_attributes: 100, idle_timeout: 300_000]

  @doc false
  def child_spec(opts), do: opts |> listener_opts() |> Sovite.Listener.child_spec()

  @doc "Starts the server. See the module docs for options."
  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts), do: opts |> listener_opts() |> Sovite.Listener.start_link()

  defp listener_opts(opts) do
    {listener, server} = Keyword.split(opts, @listener_keys)
    Keyword.merge(listener, handler: __MODULE__, handler_opts: server_opts(server))
  end

  defp server_opts(opts) do
    opts = Keyword.validate!(opts, [:handler] ++ @defaults)

    case Keyword.fetch(opts, :handler) do
      {:ok, {module, _handler_opts}} when is_atom(module) -> opts
      {:ok, module} when is_atom(module) -> Keyword.put(opts, :handler, {module, []})
      _ -> raise ArgumentError, "missing or invalid option :handler"
    end
  end

  @impl Sovite.Listener.Handler
  def start_link(info, opts) do
    opts = server_opts(opts)
    {:ok, spawn_link(fn -> serve(info, opts) end)}
  end

  defp serve(info, opts) do
    with {:ok, info} <- Sovite.Listener.handshake(info) do
      {module, handler_opts} = opts[:handler]
      {:ok, state} = module.init(Map.delete(info, :socket), handler_opts)

      context = %{
        socket: info.socket,
        module: module,
        idle_timeout: opts[:idle_timeout],
        limits: %{
          max_line: opts[:max_line],
          max_attributes: opts[:max_attributes],
          max_size: :infinity
        },
        metadata: %{listener: info.listener, remote_ip: info.remote_ip}
      }

      loop(context, Codec.new(), state)
    end

    :gen_tcp.close(info.socket)
  end

  defp loop(context, reader, state) do
    deadline = System.monotonic_time(:millisecond) + context.idle_timeout

    case read(context, Codec.read(reader, "", context.limits), deadline) do
      {:ok, attrs, reader} when map_size(attrs) > 0 ->
        case handle(context, attrs, state) do
          {:ok, state} -> loop(context, reader, state)
          :close -> :ok
        end

      {:ok, _empty, _reader} ->
        error(context, :malformed)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        error(context, reason)
    end
  end

  defp read(context, {:more, reader}, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    case :gen_tcp.recv(context.socket, 0, remaining) do
      {:ok, data} -> read(context, Codec.read(reader, data, context.limits), deadline)
      {:error, :timeout} -> {:error, :timeout}
      {:error, _reason} -> {:error, :closed}
    end
  end

  defp read(_context, result, _deadline), do: result

  defp handle(context, attrs, state) do
    started = System.monotonic_time()

    {action, result} =
      case context.module.handle_request(attrs, state) do
        {:close, _state} -> {nil, :close}
        {action, state} when is_binary(action) -> {action, {:ok, state}}
        {action, state} -> {Action.encode(action), {:ok, state}}
      end

    :telemetry.execute(
      [:sovite, :policy, :server, :request, :stop],
      %{duration: System.monotonic_time() - started},
      Map.merge(context.metadata, %{attributes: attrs, action: action})
    )

    cond do
      action == nil -> :close
      :gen_tcp.send(context.socket, Policy.encode_reply(action)) == :ok -> result
      true -> :close
    end
  end

  defp error(context, reason) do
    :telemetry.execute(
      [:sovite, :policy, :server, :error],
      %{},
      Map.put(context.metadata, :reason, reason)
    )
  end
end
