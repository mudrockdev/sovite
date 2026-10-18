defmodule Sovite.Core.Control do
  @moduledoc """
  Runs the MTA as a whole: reloads the configuration, drains the server
  before it stops, and reports its status. Started last by
  `Sovite.Core.Supervisor`, so it stops first.

  ## Reload

  `reload/1`, `SIGHUP`, `sovitectl config reload`, and `systemctl
  reload sovite` read the config file again and apply it without
  stopping (see "Reloading" in `Sovite.Core.Supervisor`). An invalid
  file changes nothing: the errors are returned and logged.

  ## Drain

  When the MTA stops (`SIGTERM`, `systemctl stop`), the SMTP listeners
  stop accepting connections, idle sessions are closed with `421`, and
  sessions in a transaction get to finish it; no new deliveries start,
  and the running ones get to end. After `server.shutdown_timeout`,
  whatever is left is cut off: messages being delivered stay queued and
  are delivered after the next start.

  ## systemd

  Under systemd (`Type=notify`), the service manager is told when the
  MTA is ready, reloading, and stopping, with a status line.

  ## Telemetry

    * `[:sovite, :config, :reloaded]` - `%{}`, `%{path, changed}`:
      `changed` is the IDs of the children that were started, updated,
      restarted, or stopped.
    * `[:sovite, :config, :reload_failed]` - `%{}`, `%{path, reason}`.
    * `[:sovite, :server, :drain, :start]` - `%{connections}`, `%{}`.
    * `[:sovite, :server, :drain, :stop]` - `%{duration, connections}`,
      `%{deliveries}` (`:ok` or `:timeout`). `connections` is the number
      of SMTP connections still open.
  """

  use GenServer

  require Logger

  alias Sovite.Core.{Config, Logging, QueueInfo, QueueManager}
  alias Sovite.Core.Control.Signals
  alias Sovite.Listener
  alias Sovite.Systemd

  @version Mix.Project.config()[:version]

  # The listeners that are drained: those that receive mail.
  @not_drained ["mta-sts/"]

  @poll_interval 100

  @doc false
  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      shutdown: Keyword.fetch!(opts, :config).server.shutdown_timeout + 5_000
    }
  end

  @doc false
  def start_link(opts) do
    runtime = Keyword.fetch!(opts, :runtime)
    GenServer.start_link(__MODULE__, opts, name: runtime.control)
  end

  @doc """
  Reloads the config file. Returns `:ok`, `{:error, errors}` with the
  `Sovite.Core.Config.Error`s of an invalid file, or `{:error, reason}`
  for a change that needs a restart (`{:restart_required, keys}`) or a
  server started without a config file (`:no_config_file`).
  """
  @spec reload(GenServer.server()) :: :ok | {:error, term()}
  def reload(control), do: GenServer.call(control, :reload, :infinity)

  @doc "Drains the server, see the module docs. Returns when done."
  @spec drain(GenServer.server()) :: :ok
  def drain(control), do: GenServer.call(control, :drain, :infinity)

  @doc """
  The status of the MTA: version, host name, start time, config file
  and last reload, listeners and their connections, queue sizes, and
  deliveries.
  """
  @spec status(GenServer.server()) :: map()
  def status(control), do: GenServer.call(control, :status, 30_000)

  @doc "The listeners of `supervisor` and their open connections, as `{id, count}`."
  @spec listener_connections(Supervisor.supervisor()) :: [{String.t(), non_neg_integer()}]
  def listener_connections(supervisor) do
    for {id, pid} <- listeners(supervisor), do: {id, safe_count(pid)}
  end

  defp listeners(supervisor) do
    for {{Listener, id}, pid, _type, _modules} <- Supervisor.which_children(supervisor),
        is_pid(pid),
        do: {to_string(id), pid}
  end

  defp safe_count(pid) do
    Listener.connection_count(pid)
  catch
    :exit, _reason -> 0
  end

  ## Server

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    runtime = Keyword.fetch!(opts, :runtime)

    state = %{
      runtime: runtime,
      config: Keyword.fetch!(opts, :config),
      listeners: [],
      drained: false,
      last_reload: nil
    }

    {:ok, state, {:continue, :started}}
  end

  @impl true
  def handle_continue(:started, state) do
    # The registered MTA handles SIGHUP; extra ones (tests, embedding)
    # are reloaded through reload/1.
    if state.runtime.args.name == state.runtime.args.module, do: Signals.install(self())

    _ = Systemd.ready(status: "accepting mail")
    {:noreply, %{state | listeners: listeners(state.runtime.supervisor)}}
  end

  @impl true
  def handle_call(:reload, _from, state) do
    {result, state} = do_reload(state)
    {:reply, result, state}
  end

  def handle_call(:drain, _from, state),
    do: {:reply, :ok, do_drain(state, listeners(state.runtime.supervisor))}

  def handle_call(:status, _from, state), do: {:reply, build_status(state), state}

  @impl true
  def handle_info(:sighup, state) do
    {_result, state} = do_reload(state)
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(reason, state) do
    if reason == :shutdown or match?({:shutdown, _}, reason) do
      # The supervisor is stopping its children and cannot be asked for
      # them: drain the listeners known since the start or last reload.
      _ = do_drain(state, state.listeners)
      Signals.remove(self())
      tree(state).erase_specs(state.runtime.instance)
      Config.erase(state.runtime.instance)
    end

    :ok
  end

  # Sovite.Core.Supervisor, which starts this process: given in its
  # options, so the two do not depend on each other at compile time.
  defp tree(state), do: state.runtime.args.module

  ## Status

  defp build_status(state) do
    config = state.config
    runtime = state.runtime
    stats = queue_stats(runtime.queue_manager)
    counts = QueueInfo.counts(config.queue.directory)

    %{
      version: @version,
      hostname: config.server.hostname,
      started_at: DateTime.to_iso8601(DateTime.from_unix!(runtime.started_at)),
      uptime: System.os_time(:second) - runtime.started_at,
      config_path: runtime.config_path,
      last_reload: state.last_reload,
      draining: state.drained,
      listeners:
        for(
          {id, count} <- listener_connections(runtime.supervisor),
          do: %{id: id, connections: count}
        ),
      queue: %{counts | active: stats[:active] || counts.active},
      deliveries: %{running: stats[:deliveries] || 0, ready: stats[:ready] || 0},
      vm: %{
        memory: :erlang.memory(:total),
        processes: :erlang.system_info(:process_count),
        otp_release: List.to_string(:erlang.system_info(:otp_release))
      }
    }
  end

  defp queue_stats(manager) do
    QueueManager.stats(manager)
  catch
    :exit, _reason -> %{}
  end

  ## Reload

  defp do_reload(state) do
    path = state.runtime.config_path

    result =
      with path when is_binary(path) <- path || {:error, :no_config_file},
           {:ok, config} <- Config.load(path),
           :ok <- check_restart(state.config, config) do
        _ = Systemd.reloading(status: "reloading the configuration")
        {:ok, config, apply_config(state, config)}
      end

    case result do
      {:ok, config, changed} ->
        _ = Systemd.ready(status: "accepting mail")

        :telemetry.execute([:sovite, :config, :reloaded], %{}, %{
          path: path,
          changed: Enum.map(changed, &format_id/1)
        })

        {:ok,
         %{
           state
           | config: config,
             last_reload: last_reload(:ok),
             listeners: listeners(state.runtime.supervisor)
         }}

      {:error, reason} ->
        :telemetry.execute([:sovite, :config, :reload_failed], %{}, %{
          path: path,
          reason: reload_reason(reason)
        })

        {{:error, reason}, %{state | last_reload: last_reload(reload_reason(reason))}}
    end
  end

  defp last_reload(result),
    do: %{
      at: DateTime.to_iso8601(DateTime.utc_now()),
      result: if(result == :ok, do: "ok", else: result)
    }

  defp reload_reason(errors) when is_list(errors),
    do: Enum.map_join(errors, "; ", &Exception.message/1)

  defp reload_reason({:restart_required, keys}), do: "needs a restart: " <> Enum.join(keys, ", ")
  defp reload_reason(:no_config_file), do: "started without a config file"
  defp reload_reason(reason), do: inspect(reason)

  # Partisan keeps running with the settings it started with.
  @cluster_restart [:enabled, :node_name, :address, :port, :cert_file, :key_file, :ca_file]

  defp check_restart(old, new) do
    keys =
      [
        old.database != new.database && "database",
        old.queue.directory != new.queue.directory && "queue.directory"
      ]
      |> Kernel.++(
        for key <- @cluster_restart,
            Map.fetch!(old.cluster, key) != Map.fetch!(new.cluster, key),
            do: "cluster.#{key}"
      )
      |> Enum.filter(& &1)

    if keys == [], do: :ok, else: {:error, {:restart_required, keys}}
  end

  # Starts, updates, restarts, and stops children for `config`. Returns
  # the IDs of those that changed.
  defp apply_config(state, config) do
    runtime = tree(state).runtime(config, state.runtime.args)
    instance = runtime.instance
    supervisor = runtime.supervisor
    old = tree(state).specs(instance)
    new = tree(state).children(config, runtime)
    new_ids = MapSet.new(new, & &1.id)

    Config.put(config, instance)
    Logging.configure(config.log)
    tree(state).put_specs(instance, new)

    running = Map.new(Supervisor.which_children(supervisor), fn {id, pid, _, _} -> {id, pid} end)

    # Stopped first, so their ports are free for new listeners.
    removed =
      for {id, _spec} <- old, not MapSet.member?(new_ids, id), id != __MODULE__ do
        stop_child(supervisor, id, running[id], config)
        id
      end

    changed =
      for spec <- new, spec.id != __MODULE__, old[spec.id] != spec do
        update_child(
          supervisor,
          {tree(state), instance},
          spec,
          old[spec.id],
          running[spec.id],
          config
        )

        spec.id
      end

    removed ++ changed
  end

  defp update_child(supervisor, {tree, instance}, spec, nil, _pid, _config) do
    case Supervisor.start_child(supervisor, tree.indirect_spec(spec, instance)) do
      {:ok, _pid} ->
        :ok

      {:ok, _pid, _info} ->
        :ok

      {:error, {:already_started, _pid}} ->
        :ok

      # Not running, but known: started with its new spec.
      {:error, :already_present} ->
        restart(supervisor, spec.id)

      {:error, reason} ->
        Logger.error("reload: cannot start #{format_id(spec.id)}: #{inspect(reason)}")
    end
  end

  defp update_child(_supervisor, _instance, %{id: QueueManager} = spec, _old, pid, _config)
       when is_pid(pid) do
    {_module, _function, [opts]} = spec.start
    QueueManager.reconfigure(pid, opts)
  end

  defp update_child(
         supervisor,
         _instance,
         %{start: {Listener, _, [opts]}} = spec,
         old,
         pid,
         config
       )
       when is_pid(pid) do
    {Listener, _, [old_opts]} = old.start
    live = Listener.Server.live_keys()

    cond do
      Keyword.drop(opts, live) == Keyword.drop(old_opts, live) ->
        Listener.update(pid, Keyword.take(opts, live))

      # An inherited socket cannot be opened again.
      Keyword.get(old_opts, :fd) != nil ->
        Logger.warning(
          "reload: listener #{format_id(spec.id)} needs a restart for its new options"
        )

      true ->
        drain_listener(pid, config.server.shutdown_timeout)
        restart(supervisor, spec.id)
    end
  end

  defp update_child(supervisor, _instance, spec, _old, _pid, _config) do
    if spec[:restart] == :temporary, do: :ok, else: restart(supervisor, spec.id)
  end

  defp restart(supervisor, id) do
    _ = Supervisor.terminate_child(supervisor, id)

    case Supervisor.restart_child(supervisor, id) do
      {:ok, _pid} ->
        :ok

      {:ok, _pid, _info} ->
        :ok

      {:error, reason} ->
        Logger.error("reload: cannot restart #{format_id(id)}: #{inspect(reason)}")
    end
  end

  defp stop_child(supervisor, {Listener, _} = id, pid, config) when is_pid(pid) do
    # Closed now, so its port is free; removed once its sessions end.
    Listener.drain(pid)
    timeout = config.server.shutdown_timeout

    Task.start(fn ->
      drain_listener(pid, timeout)
      remove_child(supervisor, id)
    end)
  end

  defp stop_child(supervisor, id, _pid, _config), do: remove_child(supervisor, id)

  defp remove_child(supervisor, id) do
    _ = Supervisor.terminate_child(supervisor, id)
    _ = Supervisor.delete_child(supervisor, id)
    :ok
  end

  defp drain_listener(pid, timeout) do
    Listener.drain(pid)
    wait_connections([pid], System.monotonic_time(:millisecond) + timeout)
  catch
    :exit, _reason -> 0
  end

  defp format_id({module, id}) when is_atom(module), do: "#{inspect(module)} #{format_id(id)}"
  defp format_id(id) when is_binary(id), do: id
  defp format_id(id) when is_atom(id), do: inspect(id)
  defp format_id(id), do: inspect(id)

  ## Drain

  defp do_drain(%{drained: true} = state, _listeners), do: state

  defp do_drain(state, listeners) do
    started = System.monotonic_time()
    timeout = state.config.server.shutdown_timeout
    deadline = System.monotonic_time(:millisecond) + timeout
    _ = Systemd.stopping(status: "draining")

    pids = for {id, pid} <- listeners, not String.starts_with?(id, @not_drained), do: pid

    :telemetry.execute([:sovite, :server, :drain, :start], %{connections: count(pids)}, %{})

    for pid <- pids do
      try do
        Listener.drain(pid)
      catch
        :exit, _reason -> :ok
      end
    end

    manager = state.runtime.queue_manager
    deliveries = Task.async(fn -> QueueManager.drain(manager, timeout) end)
    left = wait_connections(pids, deadline)

    result =
      case Task.yield(deliveries, max(deadline - System.monotonic_time(:millisecond), 0) + 1_000) do
        {:ok, result} -> if result == :ok, do: :ok, else: :timeout
        _ -> :timeout
      end

    :telemetry.execute(
      [:sovite, :server, :drain, :stop],
      %{duration: System.monotonic_time() - started, connections: left},
      %{deliveries: result}
    )

    %{state | drained: true}
  catch
    :exit, _reason -> %{state | drained: true}
  end

  defp wait_connections(pids, deadline) do
    case count(pids) do
      0 ->
        0

      left ->
        if System.monotonic_time(:millisecond) >= deadline do
          left
        else
          Process.sleep(@poll_interval)
          wait_connections(pids, deadline)
        end
    end
  end

  defp count(pids), do: pids |> Enum.map(&safe_count/1) |> Enum.sum()
end
