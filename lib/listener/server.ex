defmodule Sovite.Listener.Server do
  @moduledoc false
  # Owns the listen socket and the per-IP connection counts, runs the
  # acceptors, and monitors connections to release their counts. The
  # options update/2 can change live in the counts table, under
  # :context, so acceptors pick them up for the next connection.

  use GenServer

  alias Sovite.Net

  @accept_error_backoff 100

  # Options update/2 changes. Changing the others needs a new listener.
  @live_keys [
    :handler_opts,
    :max_connections_per_ip,
    :proxy_protocol,
    :proxy_networks,
    :proxy_timeout
  ]

  def live_keys, do: @live_keys

  def start_link({listener, opts}), do: GenServer.start_link(__MODULE__, {listener, opts})

  @impl true
  def init({listener, opts}) do
    Process.flag(:trap_exit, true)

    case listen(opts) do
      {:ok, socket} ->
        {:ok, {ip, port}} = :inet.sockname(socket)
        counts = :ets.new(__MODULE__, [:set, :public, write_concurrency: true])
        :ets.insert(counts, {:context, live_context(opts)})

        state = %{
          listener: listener,
          socket: socket,
          opts: opts,
          id: opts[:id] || "#{:inet.ntoa(ip)}:#{port}",
          handler: opts[:handler],
          acceptors: opts[:acceptors],
          counts: counts,
          connections: nil,
          monitors: %{}
        }

        {:ok, state, {:continue, :start_acceptors}}

      {:error, reason} ->
        {:stop, {:listen_failed, reason}}
    end
  end

  defp listen(opts) do
    ip = opts[:ip]

    socket_opts = [
      :binary,
      active: false,
      packet: :raw,
      reuseaddr: true,
      backlog: 1024,
      nodelay: true,
      keepalive: true,
      send_timeout: 30_000,
      send_timeout_close: true
    ]

    family = if tuple_size(ip) == 8, do: [:inet6], else: []

    case opts[:fd] do
      # A socket systemd (or another parent) opened: bound and listening.
      fd when is_integer(fd) ->
        :gen_tcp.listen(0, family ++ [{:fd, fd} | socket_opts])

      nil ->
        v6only = if family == [], do: [], else: [ipv6_v6only: true]
        :gen_tcp.listen(opts[:port], family ++ v6only ++ [{:ip, ip} | socket_opts])
    end
  end

  defp live_context(opts) do
    %{
      handler_opts: opts[:handler_opts],
      max_per_ip: opts[:max_connections_per_ip],
      proxy: opts[:proxy_protocol] && {opts[:proxy_networks], opts[:proxy_timeout]}
    }
  end

  @impl true
  def handle_continue(:start_acceptors, state) do
    # The connection supervisor is a sibling. Looking it up here instead of
    # in init/1 avoids calling the parent while it is starting us.
    connections =
      state.listener
      |> Supervisor.which_children()
      |> Enum.find_value(fn {id, pid, _type, _modules} -> id == :connections && pid end)

    state = %{state | connections: connections}
    for _ <- 1..state.acceptors, do: start_acceptor(state)
    {:noreply, state}
  end

  @impl true
  def handle_call(:sockname, _from, %{socket: nil} = state),
    do: {:reply, {:error, :closed}, state}

  def handle_call(:sockname, _from, state), do: {:reply, :inet.sockname(state.socket), state}

  def handle_call({:update, opts}, _from, state) do
    opts = Keyword.merge(state.opts, opts)
    :ets.insert(state.counts, {:context, live_context(opts)})
    {:reply, :ok, %{state | opts: opts}}
  end

  def handle_call(:drain, _from, %{socket: nil} = state), do: {:reply, :ok, state}

  def handle_call(:drain, _from, state) do
    # The acceptors see the socket closed and stop.
    :gen_tcp.close(state.socket)

    for {_ref, {pid, _ip, _port, _started, _claimed}} <- state.monitors,
        do: send(pid, {:sovite_listener, :drain})

    {:reply, :ok, %{state | socket: nil}}
  end

  @impl true
  def handle_info({:track, pid, ip, port, started_at, claimed}, state) do
    ref = Process.monitor(pid)

    # Drained while the connection was being handed over.
    if state.socket == nil, do: send(pid, {:sovite_listener, :drain})
    {:noreply, put_in(state.monitors[ref], {pid, ip, port, started_at, claimed})}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    {{_pid, ip, port, started_at, claimed}, monitors} = Map.pop(state.monitors, ref)
    if claimed, do: release(state.counts, ip)

    :telemetry.execute(
      [:sovite, :listener, :connection, :stop],
      %{duration: System.monotonic_time() - started_at},
      %{listener: state.id, remote_ip: ip, remote_port: port}
    )

    {:noreply, %{state | monitors: monitors}}
  end

  # An acceptor crashed; replace it, unless the listener is draining.
  def handle_info({:EXIT, _pid, reason}, state) when reason != :normal do
    if state.socket, do: start_acceptor(state)
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{socket: nil}), do: :ok
  def terminate(_reason, state), do: :gen_tcp.close(state.socket)

  ## Acceptors

  defp start_acceptor(state) do
    context = Map.take(state, [:socket, :id, :handler, :counts, :connections])

    server = self()
    spawn_link(fn -> accept_loop(Map.put(context, :server, server)) end)
  end

  defp accept_loop(context) do
    case :gen_tcp.accept(context.socket) do
      {:ok, socket} ->
        serve(socket, context)
        accept_loop(context)

      {:error, :closed} ->
        :ok

      # For example :emfile. Back off instead of spinning.
      {:error, _reason} ->
        Process.sleep(@accept_error_backoff)
        accept_loop(context)
    end
  end

  defp serve(socket, context) do
    context = Map.merge(context, :ets.lookup_element(context.counts, :context, 2))

    with {:ok, {remote_ip, remote_port}} <- :inet.peername(socket),
         {:ok, {local_ip, local_port}} <- :inet.sockname(socket) do
      remote_ip = Net.normalize(remote_ip)

      info = %{
        listener: context.id,
        socket: socket,
        remote_ip: remote_ip,
        remote_port: remote_port,
        local_ip: Net.normalize(local_ip),
        local_port: local_port,
        peer_ip: remote_ip,
        peer_port: remote_port,
        proxy: nil
      }

      case claim(context, remote_ip) do
        :refused -> reject(socket, info, :max_connections_per_ip, context)
        claimed -> start_connection(socket, info, Map.put(context, :claimed, claimed))
      end
    else
      _ -> :gen_tcp.close(socket)
    end
  end

  defp start_connection(socket, info, context) do
    spec = %{
      id: :connection,
      start: {context.handler, :start_link, [info, context.handler_opts]},
      restart: :temporary
    }

    case DynamicSupervisor.start_child(context.connections, spec) do
      {:ok, pid} ->
        started_at = System.monotonic_time()

        send(
          context.server,
          {:track, pid, info.remote_ip, info.remote_port, started_at, context.claimed}
        )

        :telemetry.execute(
          [:sovite, :listener, :connection, :start],
          %{system_time: System.system_time()},
          %{listener: context.id, remote_ip: info.remote_ip, remote_port: info.remote_port}
        )

        case :gen_tcp.controlling_process(socket, pid) do
          :ok ->
            send(pid, {:sovite_listener, :ready, socket, proxy_timeout(context, info.peer_ip)})

          # The connection process is gone already; the socket is still ours.
          {:error, _reason} ->
            Process.exit(pid, :kill)
            :gen_tcp.close(socket)
        end

      {:error, :max_children} ->
        if context.claimed, do: release(context.counts, info.remote_ip)
        reject(socket, info, :max_connections, context)

      _error ->
        if context.claimed, do: release(context.counts, info.remote_ip)
        :gen_tcp.close(socket)
    end
  end

  defp reject(socket, info, reason, context) do
    :telemetry.execute(
      [:sovite, :listener, :connection, :rejected],
      %{},
      %{listener: context.id, remote_ip: info.remote_ip, reason: reason}
    )

    if Code.ensure_loaded?(context.handler) and function_exported?(context.handler, :reject, 3) do
      try do
        context.handler.reject(socket, reason, context.handler_opts)
      catch
        _kind, _reason -> :ok
      end
    end

    :gen_tcp.close(socket)
  end

  # The PROXY header timeout if this peer must send one, otherwise nil.
  defp proxy_timeout(%{proxy: {nil, timeout}}, _ip), do: timeout

  defp proxy_timeout(%{proxy: {networks, timeout}}, ip),
    do: if(Net.in_networks?(ip, networks), do: timeout)

  defp proxy_timeout(_context, _ip), do: nil

  ## Per-IP counts

  # Whether the connection counts against its IP (`true`), does not
  # (`false`, without a limit), or is over the limit (`:refused`). The
  # flag goes with the connection, so a limit changed by update/2 never
  # releases a count that was not taken.
  defp claim(%{max_per_ip: nil}, _ip), do: false

  defp claim(context, ip) do
    if :ets.update_counter(context.counts, ip, {2, 1}, {ip, 0}) <= context.max_per_ip do
      true
    else
      release(context.counts, ip)
      :refused
    end
  end

  defp release(counts, ip) do
    # Delete the row only if it is still zero, so the table stays small.
    if :ets.update_counter(counts, ip, {2, -1}) <= 0,
      do: :ets.delete_object(counts, {ip, 0})

    :ok
  end
end
