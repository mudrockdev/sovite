defmodule Sovite.Policy.ServerTest do
  use ExUnit.Case, async: true

  alias Sovite.Policy.Server
  alias Sovite.Test.TelemetryForwarder

  defmodule TestHandler do
    @moduledoc false
    @behaviour Sovite.Policy.Handler

    # Reports each request to the test process, and answers with the
    # `want` attribute: an action text, a term name, or "close".
    @impl true
    def init(connection, test) do
      send(test, {:init, connection})
      {:ok, %{test: test, count: 0}}
    end

    @impl true
    def handle_request(attrs, state) do
      send(state.test, {:request, attrs})
      state = %{state | count: state.count + 1}

      case attrs["want"] do
        "close" -> {:close, state}
        "reject" -> {{:reject, "no #{state.count}"}, state}
        "count" -> {"DUNNO #{state.count}", state}
        "newline" -> {"REJECT a\nb", state}
        nil -> {:dunno, state}
        text -> {text, state}
      end
    end
  end

  defmodule BareHandler do
    @moduledoc false
    @behaviour Sovite.Policy.Handler

    # Accepts everything.
    @impl true
    def init(_connection, opts), do: {:ok, opts}

    @impl true
    def handle_request(_attrs, state), do: {:ok, state}
  end

  defp start_server(opts \\ []) do
    id = "policy-server-#{System.unique_integer([:positive])}"

    opts =
      Keyword.merge(
        [id: id, ip: {127, 0, 0, 1}, port: 0, handler: {TestHandler, self()}],
        opts
      )

    listener = start_supervised!({Server, opts})
    {:ok, {_ip, port}} = Sovite.Listener.sockname(listener)
    %{port: port, id: id}
  end

  defp connect(port) do
    {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)
    socket
  end

  defp ask(socket, request) do
    :ok = :gen_tcp.send(socket, request)
    recv_reply(socket, "")
  end

  defp recv_reply(socket, acc) do
    if String.ends_with?(acc, "\n\n") do
      acc
    else
      {:ok, data} = :gen_tcp.recv(socket, 0, 1_000)
      recv_reply(socket, acc <> data)
    end
  end

  test "serves several requests on one connection" do
    %{port: port, id: id} = start_server()
    socket = connect(port)

    assert ask(socket, "request=smtpd_access_policy\nsender=a@example.com\n\n") ==
             "action=DUNNO\n\n"

    assert_receive {:init, %{listener: ^id, remote_ip: {127, 0, 0, 1}} = connection}
    refute Map.has_key?(connection, :socket)

    assert_receive {:request, %{"request" => "smtpd_access_policy", "sender" => "a@example.com"}}

    assert ask(socket, "want=reject\n\n") == "action=REJECT no 2\n\n"
    assert ask(socket, "want=count\r\nx=1\r\n\r\n") == "action=DUNNO 3\n\n"
    assert ask(socket, "want=newline\n\n") == "action=REJECT a b\n\n"
    assert ask(socket, "want=550 5.7.1 Nope\n\n") == "action=550 5.7.1 Nope\n\n"
    :gen_tcp.close(socket)
  end

  test "answers pipelined requests in order, and keeps the last of duplicate names" do
    %{port: port} = start_server()
    socket = connect(port)
    :ok = :gen_tcp.send(socket, "want=count\n\nwant=DUNNO\nwant=count\n\n")
    assert recv_all(socket, "", 2) == "action=DUNNO 1\n\naction=DUNNO 2\n\n"
    assert_receive {:request, %{"want" => "count"}}
    assert_receive {:request, %{"want" => "count"}}
  end

  defp recv_all(socket, acc, replies) do
    if length(String.split(acc, "\n\n", trim: true)) == replies and String.ends_with?(acc, "\n\n") do
      acc
    else
      {:ok, data} = :gen_tcp.recv(socket, 0, 1_000)
      recv_all(socket, acc <> data, replies)
    end
  end

  test "closes the connection when the handler says so" do
    %{port: port, id: id} = start_server()
    TelemetryForwarder.attach([[:sovite, :policy, :server, :request, :stop]])
    socket = connect(port)
    :ok = :gen_tcp.send(socket, "want=close\n\n")
    assert :gen_tcp.recv(socket, 0, 1_000) == {:error, :closed}

    assert_receive {:telemetry, [:sovite, :policy, :server, :request, :stop], %{duration: _},
                    %{listener: ^id, action: nil, attributes: %{"want" => "close"}}}
  end

  test "reports requests" do
    %{port: port, id: id} = start_server()
    TelemetryForwarder.attach([[:sovite, :policy, :server, :request, :stop]])
    socket = connect(port)
    ask(socket, "want=reject\n\n")

    assert_receive {:telemetry, [:sovite, :policy, :server, :request, :stop], %{duration: d},
                    %{
                      listener: ^id,
                      remote_ip: {127, 0, 0, 1},
                      attributes: %{"want" => "reject"},
                      action: "REJECT no 1"
                    }}

    assert is_integer(d)
  end

  describe "limits" do
    setup do
      TelemetryForwarder.attach([[:sovite, :policy, :server, :error]])
      :ok
    end

    defp assert_closed(socket, id, reason) do
      assert :gen_tcp.recv(socket, 0, 2_000) == {:error, :closed}

      assert_receive {:telemetry, [:sovite, :policy, :server, :error], %{},
                      %{listener: ^id, remote_ip: {127, 0, 0, 1}, reason: ^reason}}
    end

    test "long lines" do
      %{port: port, id: id} = start_server(max_line: 100)
      socket = connect(port)
      assert ask(socket, "a=#{String.duplicate("x", 98)}\n\n") == "action=DUNNO\n\n"
      :ok = :gen_tcp.send(socket, "a=#{String.duplicate("x", 99)}\n\n")
      assert_closed(socket, id, :line_too_long)

      # Without a newline yet.
      socket = connect(port)
      :ok = :gen_tcp.send(socket, "a=" <> String.duplicate("x", 200))
      assert_closed(socket, id, :line_too_long)
    end

    test "too many attributes" do
      %{port: port, id: id} = start_server(max_attributes: 3)
      socket = connect(port)
      assert ask(socket, "a=1\nb=2\nc=3\n\n") == "action=DUNNO\n\n"
      :ok = :gen_tcp.send(socket, "a=1\nb=2\nc=3\nd=4\n\n")
      assert_closed(socket, id, :too_many_attributes)
    end

    test "malformed requests" do
      %{port: port, id: id} = start_server()
      socket = connect(port)
      :ok = :gen_tcp.send(socket, "garbage\n\n")
      assert_closed(socket, id, :malformed)

      socket = connect(port)
      :ok = :gen_tcp.send(socket, "\n")
      assert_closed(socket, id, :malformed)
    end

    test "idle timeout" do
      %{port: port, id: id} = start_server(idle_timeout: 100)
      socket = connect(port)
      assert ask(socket, "a=1\n\n") == "action=DUNNO\n\n"
      # A request that never ends.
      :ok = :gen_tcp.send(socket, "a=1\n")
      assert_closed(socket, id, :timeout)
    end
  end

  test "the client closing the connection is not an error" do
    %{port: port} = start_server()
    TelemetryForwarder.attach([[:sovite, :policy, :server, :error]])
    socket = connect(port)
    :ok = :gen_tcp.send(socket, "a=1\n")
    assert_receive {:init, _}
    :gen_tcp.close(socket)
    refute_receive {:telemetry, [:sovite, :policy, :server, :error], _, _}, 100
  end

  test "can be given to a listener, with a module as handler" do
    listener =
      start_supervised!(
        {Sovite.Listener,
         ip: {127, 0, 0, 1}, port: 0, handler: Server, handler_opts: [handler: BareHandler]}
      )

    {:ok, {_ip, port}} = Sovite.Listener.sockname(listener)
    assert ask(connect(port), "a=1\n\n") == "action=OK\n\n"
  end

  test "start_link/1 starts a listener" do
    {:ok, pid} = Server.start_link(ip: {127, 0, 0, 1}, port: 0, handler: {TestHandler, self()})
    {:ok, {_ip, port}} = Sovite.Listener.sockname(pid)
    assert ask(connect(port), "a=1\n\n") == "action=DUNNO\n\n"
    Supervisor.stop(pid)
  end

  test "checks options" do
    assert_raise ArgumentError, ~r/:handler/, fn -> Server.child_spec(port: 0) end
    assert_raise ArgumentError, ~r/:handler/, fn -> Server.child_spec(port: 0, handler: "x") end
    assert_raise ArgumentError, fn -> Server.child_spec(port: 0, handler: TestHandler, bad: 1) end
  end
end
