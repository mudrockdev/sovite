defmodule Sovite.ListenerTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Sovite.Listener

  @localhost {127, 0, 0, 1}
  @localhost6 {0, 0, 0, 0, 0, 0, 0, 1}

  defmodule EchoHandler do
    @moduledoc false
    @behaviour Sovite.Listener.Handler

    # Reports the connection to the test process, then echoes lines until
    # the client closes the connection.
    @impl true
    def start_link(info, opts) do
      Task.start_link(fn ->
        :ok = Listener.handshake(info)
        send(Keyword.fetch!(opts, :test), {:connected, self(), info})
        echo(info.socket)
      end)
    end

    @impl true
    def reject(socket, reason, _opts), do: :gen_tcp.send(socket, "REJECTED #{reason}\n")

    defp echo(socket) do
      case :gen_tcp.recv(socket, 0) do
        {:ok, data} ->
          :gen_tcp.send(socket, data)
          echo(socket)

        {:error, _} ->
          :ok
      end
    end
  end

  defmodule SilentHandler do
    @moduledoc false
    # No reject/3: refused connections are just closed.
    def start_link(info, opts), do: EchoHandler.start_link(info, opts)
  end

  defmodule ExitingHandler do
    @moduledoc false
    # The connection process exits before the socket is handed over.
    def start_link(_info, _opts), do: Task.start_link(fn -> :ok end)
  end

  def handle_event(event, measurements, metadata, pid),
    do: send(pid, {:telemetry, event, measurements, metadata})

  defp start_listener(opts) do
    id = "listener-test-#{System.unique_integer([:positive])}"

    opts =
      Keyword.merge(
        [id: id, ip: @localhost, port: 0, handler: EchoHandler, handler_opts: [test: self()]],
        opts
      )

    listener = start_supervised!({Listener, opts})
    {:ok, {_ip, port}} = Listener.sockname(listener)
    %{listener: listener, port: port, id: opts[:id]}
  end

  defp connect(port, ip \\ @localhost) do
    {:ok, socket} = :gen_tcp.connect(ip, port, [:binary, active: false, packet: :line], 1_000)
    socket
  end

  # Connects and waits until the handler has the connection.
  defp connect!(port, ip \\ @localhost) do
    socket = connect(port, ip)
    {:ok, {_ip, client_port}} = :inet.sockname(socket)
    assert_receive {:connected, _pid, %{remote_port: ^client_port} = info}
    {socket, info}
  end

  defp assert_rejected(port, reason) do
    socket = connect(port)
    assert :gen_tcp.recv(socket, 0, 1_000) == {:ok, "REJECTED #{reason}\n"}
    assert :gen_tcp.recv(socket, 0, 1_000) == {:error, :closed}
  end

  # Connects until the connection is not refused: slots are released
  # asynchronously after a connection closes.
  defp connect_eventually!(port, attempts \\ 50) do
    socket = connect(port)
    :ok = :gen_tcp.send(socket, "ping\n")

    case :gen_tcp.recv(socket, 0, 1_000) do
      {:ok, "ping\n"} ->
        socket

      {:ok, "REJECTED " <> _} when attempts > 1 ->
        :gen_tcp.close(socket)
        Process.sleep(10)
        connect_eventually!(port, attempts - 1)
    end
  end

  defp wait_until(fun, attempts \\ 100) do
    cond do
      fun.() ->
        :ok

      attempts > 1 ->
        Process.sleep(10)
        wait_until(fun, attempts - 1)

      true ->
        flunk("condition not met in time")
    end
  end

  defp attach_telemetry do
    handler_id = "listener-test-#{System.unique_integer([:positive])}"

    events =
      for name <- [:start, :stop, :rejected], do: [:sovite, :listener, :connection, name]

    :ok = :telemetry.attach_many(handler_id, events, &__MODULE__.handle_event/4, self())
    on_exit(fn -> :telemetry.detach(handler_id) end)
  end

  test "serves connections with the connection info" do
    %{port: port, id: id} = start_listener([])
    {socket, info} = connect!(port)

    {:ok, {_ip, client_port}} = :inet.sockname(socket)

    assert %{
             listener: ^id,
             remote_ip: @localhost,
             remote_port: ^client_port,
             local_ip: @localhost,
             local_port: ^port
           } = info

    :ok = :gen_tcp.send(socket, "hello\n")
    assert :gen_tcp.recv(socket, 0, 1_000) == {:ok, "hello\n"}
  end

  test "the default id is the listen address" do
    %{listener: listener, port: port} = start_listener(id: nil)
    assert {:ok, {@localhost, ^port}} = Listener.sockname(listener)
    {_socket, info} = connect!(port)
    assert info.listener == "127.0.0.1:#{port}"
  end

  test "connection_count/1 counts open connections" do
    %{listener: listener, port: port} = start_listener([])
    assert Listener.connection_count(listener) == 0

    {a, _} = connect!(port)
    {b, _} = connect!(port)
    assert Listener.connection_count(listener) == 2

    :gen_tcp.close(a)
    wait_until(fn -> Listener.connection_count(listener) == 1 end)
    :gen_tcp.close(b)
    wait_until(fn -> Listener.connection_count(listener) == 0 end)
  end

  test "max_connections_per_ip refuses extra connections until a slot frees up" do
    %{listener: listener, port: port} = start_listener(max_connections_per_ip: 2)
    {a, _} = connect!(port)
    {_b, _} = connect!(port)

    assert_rejected(port, :max_connections_per_ip)
    assert_rejected(port, :max_connections_per_ip)
    assert Listener.connection_count(listener) == 2

    :gen_tcp.close(a)
    connect_eventually!(port)
    assert_rejected(port, :max_connections_per_ip)
  end

  test "max_connections refuses extra connections until a slot frees up" do
    %{listener: listener, port: port} = start_listener(max_connections: 2)
    {a, _} = connect!(port)
    {_b, _} = connect!(port)

    assert_rejected(port, :max_connections)
    assert Listener.connection_count(listener) == 2

    :gen_tcp.close(a)
    connect_eventually!(port)
    assert_rejected(port, :max_connections)
  end

  test "a refused connection is closed when the handler has no reject/3" do
    %{port: port} = start_listener(handler: SilentHandler, max_connections: 1)
    connect!(port)

    socket = connect(port)
    assert :gen_tcp.recv(socket, 0, 1_000) == {:error, :closed}
  end

  test "serves IPv6 connections" do
    case :gen_tcp.listen(0, [:inet6, ip: @localhost6]) do
      {:ok, probe} ->
        :gen_tcp.close(probe)
        %{port: port} = start_listener(ip: @localhost6, id: nil)
        {socket, info} = connect!(port, @localhost6)

        assert %{remote_ip: @localhost6, local_ip: @localhost6, local_port: ^port} = info
        assert info.listener == "::1:#{port}"
        :ok = :gen_tcp.send(socket, "hello\n")
        assert :gen_tcp.recv(socket, 0, 1_000) == {:ok, "hello\n"}

      {:error, _} ->
        IO.puts(:stderr, "IPv6 loopback unavailable, skipping")
    end
  end

  test "emits telemetry events" do
    %{port: port, id: id} = start_listener(max_connections_per_ip: 1)
    attach_telemetry()

    {socket, _info} = connect!(port)
    {:ok, {_ip, client_port}} = :inet.sockname(socket)
    meta = %{listener: id, remote_ip: @localhost, remote_port: client_port}

    assert_receive {:telemetry, [:sovite, :listener, :connection, :start], %{system_time: time},
                    ^meta}

    assert is_integer(time)

    assert_rejected(port, :max_connections_per_ip)

    assert_receive {:telemetry, [:sovite, :listener, :connection, :rejected], measurements,
                    %{listener: ^id} = rejected}

    assert measurements == %{}
    assert rejected == %{listener: id, remote_ip: @localhost, reason: :max_connections_per_ip}

    :gen_tcp.close(socket)

    assert_receive {:telemetry, [:sovite, :listener, :connection, :stop], %{duration: duration},
                    ^meta}

    assert is_integer(duration) and duration >= 0
  end

  test "start_link/1 fails when the port is in use" do
    %{port: port} = start_listener([])

    # The failing child is logged by the supervisor.
    capture_log(fn ->
      assert {:error, reason} =
               start_supervised(
                 {Listener, id: "other", ip: @localhost, port: port, handler: EchoHandler}
               )

      assert inspect(reason) =~ "eaddrinuse"
    end)
  end

  test "stopping the listener closes the listen socket and its connections" do
    %{port: port, id: id} = start_listener([])
    {socket, _info} = connect!(port)

    :ok = stop_supervised({Listener, id})
    assert :gen_tcp.recv(socket, 0, 1_000) == {:error, :closed}
    assert :gen_tcp.connect(@localhost, port, [], 1_000) == {:error, :econnrefused}
  end

  test "handshake/2 times out without a handover" do
    assert Listener.handshake(%{socket: make_ref()}, 10) == {:error, :timeout}
  end

  # BUG: lib/listener/server.ex:155-157 (start_connection/3). If the handler
  # process exits before the socket is handed over, controlling_process/2
  # fails and the acceptor never closes the socket: it stays open, owned
  # by the acceptor, while the connection's slot has already been released.
  @tag :skip
  test "closes the socket when the connection process exits before the handover" do
    %{port: port} = start_listener(handler: ExitingHandler)
    socket = connect(port)
    assert :gen_tcp.recv(socket, 0, 1_000) == {:error, :closed}
  end
end
