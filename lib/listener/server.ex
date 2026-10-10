defmodule Sovite.Listener.Server do
  @moduledoc false
  # Owns the listen socket and the per-IP connection counts, runs the
  # acceptors, and monitors connections to release their counts.

  use GenServer

  alias Sovite.Net

  @accept_error_backoff 100

  def start_link({listener, opts}), do: GenServer.start_link(__MODULE__, {listener, opts})

  @impl true
  def init({listener, opts}) do
    Process.flag(:trap_exit, true)
    ip = opts[:ip]

    socket_opts = [
      :binary,
      ip: ip,
      active: false,
      packet: :raw,
      reuseaddr: true,
      backlog: 1024,
      nodelay: true,
      keepalive: true,
      send_timeout: 30_000,
      send_timeout_close: true
    ]

    socket_opts =
      if tuple_size(ip) == 8, do: [:inet6, {:ipv6_v6only, true} | socket_opts], else: socket_opts

    case :gen_tcp.listen(opts[:port], socket_opts) do
      {:ok, socket} ->
        {:ok, {ip, port}} = :inet.sockname(socket)

        state = %{
          listener: listener,
          socket: socket,
          id: opts[:id] || "#{:inet.ntoa(ip)}:#{port}",
          handler: opts[:handler],
          handler_opts: opts[:handler_opts],
          acceptors: opts[:acceptors],
          max_per_ip: opts[:max_connections_per_ip],
          proxy: opts[:proxy_protocol] && {opts[:proxy_networks], opts[:proxy_timeout]},
          counts: :ets.new(__MODULE__, [:set, :public, write_concurrency: true]),
          connections: nil,
          monitors: %{}
        }

        {:ok, state, {:continue, :start_acceptors}}

      {:error, reason} ->
        {:stop, {:listen_failed, reason}}
    end
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
  def handle_call(:sockname, _from, state), do: {:reply, :inet.sockname(state.socket), state}

  @impl true
  def handle_info({:track, pid, ip, port, started_at}, state) do
    ref = Process.monitor(pid)
    {:noreply, put_in(state.monitors[ref], {ip, port, started_at})}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    {{ip, port, started_at}, monitors} = Map.pop(state.monitors, ref)
    release(state, ip)

    :telemetry.execute(
      [:sovite, :listener, :connection, :stop],
      %{duration: System.monotonic_time() - started_at},
      %{listener: state.id, remote_ip: ip, remote_port: port}
    )

    {:noreply, %{state | monitors: monitors}}
  end

  # An acceptor crashed; replace it.
  def handle_info({:EXIT, _pid, reason}, state) when reason != :normal do
    start_acceptor(state)
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    :gen_tcp.close(state.socket)
  end

  ## Acceptors

  defp start_acceptor(state) do
    context =
      Map.take(state, [
        :socket,
        :id,
        :handler,
        :handler_opts,
        :max_per_ip,
        :proxy,
        :counts,
        :connections
      ])

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

      if claim(context, remote_ip),
        do: start_connection(socket, info, context),
        else: reject(socket, info, :max_connections_per_ip, context)
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
        send(context.server, {:track, pid, info.remote_ip, info.remote_port, started_at})

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
        release(context, info.remote_ip)
        reject(socket, info, :max_connections, context)

      _error ->
        release(context, info.remote_ip)
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

  defp claim(%{max_per_ip: nil}, _ip), do: true

  defp claim(context, ip) do
    if :ets.update_counter(context.counts, ip, {2, 1}, {ip, 0}) <= context.max_per_ip do
      true
    else
      release(context, ip)
      false
    end
  end

  defp release(%{max_per_ip: nil}, _ip), do: :ok

  defp release(context, ip) do
    # Delete the row only if it is still zero, so the table stays small.
    if :ets.update_counter(context.counts, ip, {2, -1}) <= 0,
      do: :ets.delete_object(context.counts, {ip, 0})

    :ok
  end
end
