defmodule Sovite.Policy.ClientTest do
  use ExUnit.Case, async: true

  alias Sovite.Policy.{Client, Server}
  alias Sovite.Test.TelemetryForwarder

  doctest Sovite.Policy.Client

  defmodule EchoHandler do
    @moduledoc false
    @behaviour Sovite.Policy.Handler

    # Answers with the `want` attribute, and reports the request.
    @impl true
    def init(_connection, test), do: {:ok, test}

    @impl true
    def handle_request(attrs, test) do
      send(test, {:request, self(), attrs})
      {Map.get(attrs, "want", "DUNNO"), test}
    end
  end

  # A server on a TCP port or a Unix socket that runs `serve` on each
  # accepted connection.
  defp fake_server(kind, serve) do
    {listen_opts, address} =
      case kind do
        :unix ->
          path = "/tmp/sovite-policy-#{System.unique_integer([:positive])}.sock"
          on_exit(fn -> File.rm(path) end)
          {[ifaddr: {:local, path}], {:unix, path}}

        :inet ->
          {[ip: {127, 0, 0, 1}], nil}
      end

    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true] ++ listen_opts)
    pid = spawn_link(fn -> accept(listen, serve) end)
    :ok = :gen_tcp.controlling_process(listen, pid)

    case address do
      nil ->
        {:ok, {_ip, port}} = :inet.sockname(listen)
        {:inet, "127.0.0.1", port}

      address ->
        address
    end
  end

  defp accept(listen, serve) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        pid = spawn(fn -> receive(do: (:go -> serve.(socket))) end)
        :ok = :gen_tcp.controlling_process(socket, pid)
        send(pid, :go)
        accept(listen, serve)

      _ ->
        :ok
    end
  end

  # Reads one request block.
  defp read_request(socket, acc \\ "") do
    case Sovite.Policy.decode(acc) do
      {:ok, attrs, _rest} ->
        {:ok, attrs}

      {:error, :incomplete} ->
        case :gen_tcp.recv(socket, 0, 5_000) do
          {:ok, data} -> read_request(socket, acc <> data)
          error -> error
        end
    end
  end

  # Answers every request with `reply`, reporting it to `test`.
  defp replying(test, reply) do
    fn socket -> reply_loop(socket, test, reply) end
  end

  defp reply_loop(socket, test, reply) do
    case read_request(socket) do
      {:ok, attrs} ->
        send(test, {:fake_request, attrs})
        :gen_tcp.send(socket, reply)
        reply_loop(socket, test, reply)

      _ ->
        :gen_tcp.close(socket)
    end
  end

  defp start_server do
    listener =
      start_supervised!({Server, ip: {127, 0, 0, 1}, port: 0, handler: {EchoHandler, self()}})

    {:ok, {_ip, port}} = Sovite.Listener.sockname(listener)
    port
  end

  describe "parse_address/1" do
    test "accepts Postfix-style addresses" do
      assert Client.parse_address("inet:localhost:10023") == {:ok, {:inet, "localhost", 10_023}}
      assert Client.parse_address("inet:[2001:db8::1]:1") == {:ok, {:inet, "2001:db8::1", 1}}
      assert Client.parse_address("unix:private/policy") == {:ok, {:unix, "private/policy"}}
      assert Client.parse_address("unix:/run/p.sock") == {:ok, {:unix, "/run/p.sock"}}

      assert Client.parse_address("spawn:  /usr/bin/prog\t-v  x ") ==
               {:ok, {:command, ["/usr/bin/prog", "-v", "x"]}}
    end

    test "refuses invalid addresses" do
      for address <- [
            "inet:host",
            "inet::10023",
            "inet:host:0",
            "inet:host:65536",
            "inet:host:port",
            "inet:host:10023x",
            "inet:2001:db8::1:25",
            "inet:[]:25",
            "inet:a b:25",
            "unix:",
            "unix:a\0b",
            "spawn:",
            "spawn:   ",
            "tcp:host:25",
            "/path"
          ] do
        assert Client.parse_address(address) == {:error, :invalid_address}, address
      end
    end
  end

  describe "over TCP" do
    test "sends several requests on one connection" do
      port = start_server()
      TelemetryForwarder.attach([[:sovite, :policy, :client, :request, :stop]])
      address = {:inet, "127.0.0.1", port}

      {:ok, conn} = Client.connect(address, timeout: 1_000)

      assert {:ok, "DUNNO", conn} =
               Client.request(conn, protocol_state: "RCPT", client_address: {192, 0, 2, 7})

      assert_receive {:request, server, attrs}

      assert attrs == %{
               "request" => "smtpd_access_policy",
               "protocol_state" => "RCPT",
               "client_address" => "192.0.2.7"
             }

      assert {:ok, "REJECT go away", conn} = Client.request(conn, %{"want" => "REJECT go away"})
      assert {:ok, "550 5.7.1 x", conn} = Client.request(conn, %{"want" => "550 5.7.1 x"})
      assert_receive {:request, ^server, _}
      assert_receive {:request, ^server, _}

      assert_receive {:telemetry, [:sovite, :policy, :client, :request, :stop], %{duration: _},
                      %{address: ^address, action: "REJECT go away"}}

      assert Client.close(conn) == :ok
      assert Client.close(conn) == :ok
    end

    test "connects to IP address tuples and IPv6" do
      listener =
        start_supervised!(
          {Server, ip: {0, 0, 0, 0, 0, 0, 0, 1}, port: 0, handler: {EchoHandler, self()}}
        )

      {:ok, {_ip, port}} = Sovite.Listener.sockname(listener)
      {:ok, address} = Client.parse_address("inet:[::1]:#{port}")
      assert Client.check(address, want: "OK") == {:ok, "OK"}
      assert Client.check({:inet, {0, 0, 0, 0, 0, 0, 0, 1}, port}, []) == {:ok, "DUNNO"}

      port = start_server()
      assert Client.check({:inet, {127, 0, 0, 1}, port}, []) == {:ok, "DUNNO"}
      assert Client.check({:inet, "localhost", port}, []) == {:ok, "DUNNO"}
    end

    test "check/3 asks once" do
      port = start_server()

      assert Client.check({:inet, "127.0.0.1", port}, want: "DEFER_IF_PERMIT Greylisted") ==
               {:ok, "DEFER_IF_PERMIT Greylisted"}
    end

    test "reports connection failures" do
      TelemetryForwarder.attach([[:sovite, :policy, :client, :error]])
      {:ok, listen} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
      {:ok, {_ip, port}} = :inet.sockname(listen)
      :gen_tcp.close(listen)
      address = {:inet, "127.0.0.1", port}

      assert Client.connect(address) == {:error, :econnrefused}
      assert Client.check(address, []) == {:error, :econnrefused}

      assert_receive {:telemetry, [:sovite, :policy, :client, :error], %{duration: _},
                      %{address: ^address, reason: :econnrefused}}
    end
  end

  describe "over a Unix socket" do
    test "sends requests and reads replies" do
      address = fake_server(:unix, replying(self(), "action=OK\nextra=ignored\n\n"))
      {:ok, conn} = Client.connect(address)

      assert {:ok, "OK", conn} = Client.request(conn, sender: "a@example.com")
      assert_receive {:fake_request, %{"request" => "smtpd_access_policy", "sender" => _}}
      assert {:ok, "OK", conn} = Client.request(conn, sender: "b@example.com")
      assert_receive {:fake_request, %{"sender" => "b@example.com"}}
      Client.close(conn)
    end

    test "reports a missing socket" do
      assert Client.connect({:unix, "/tmp/sovite-policy-nonexistent.sock"}) == {:error, :enoent}
    end
  end

  describe "replies" do
    test "split across packets, with CRLF line ends" do
      serve = fn socket ->
        {:ok, _} = read_request(socket)

        for part <- ["act", "ion=DU", "NNO\r", "\n", "\r\n"] do
          :gen_tcp.send(socket, part)
          Process.sleep(5)
        end

        Process.sleep(1_000)
      end

      assert Client.check(fake_server(:inet, serve), []) == {:ok, "DUNNO"}
    end

    test "two replies in one packet" do
      serve = fn socket ->
        {:ok, _} = read_request(socket)
        :gen_tcp.send(socket, "action=OK\n\naction=DUNNO\n\n")
        {:ok, _} = read_request(socket)
        Process.sleep(1_000)
      end

      {:ok, conn} = Client.connect(fake_server(:inet, serve))
      assert {:ok, "OK", conn} = Client.request(conn, [])
      assert {:ok, "DUNNO", _conn} = Client.request(conn, [])
    end

    test "timeouts close the connection" do
      TelemetryForwarder.attach([[:sovite, :policy, :client, :error]])
      address = fake_server(:inet, fn socket -> read_request(socket) && Process.sleep(2_000) end)
      {:ok, conn} = Client.connect(address, timeout: 2_000)

      assert Client.request(conn, [], timeout: 50) == {:error, :timeout}

      assert_receive {:telemetry, [:sovite, :policy, :client, :error], %{duration: _},
                      %{address: ^address, reason: :timeout}}

      assert Client.request(conn, []) == {:error, :closed}
    end

    test "the server closing the connection" do
      serve = fn socket ->
        {:ok, _} = read_request(socket)
        :gen_tcp.send(socket, "action=DUNNO\n\n")
        :gen_tcp.close(socket)
      end

      {:ok, conn} = Client.connect(fake_server(:inet, serve))
      assert {:ok, "DUNNO", conn} = Client.request(conn, [])
      Process.sleep(50)
      assert Client.request(conn, []) == {:error, :closed}

      # Closed in the middle of a reply.
      serve = fn socket ->
        {:ok, _} = read_request(socket)
        :gen_tcp.send(socket, "action=DU")
        :gen_tcp.close(socket)
      end

      assert Client.check(fake_server(:unix, serve), []) == {:error, :closed}
    end

    test "oversize replies" do
      long = "action=REJECT " <> String.duplicate("x", 5_000) <> "\n\n"
      address = fake_server(:inet, replying(self(), long))
      assert Client.check(address, []) == {:error, :response_too_large}
      assert Client.check(address, [], max_response: 6_000) == {:ok, binary_part(long, 7, 5_007)}

      many = String.duplicate("x=1\n", 2_000) <> "action=OK\n\n"
      address = fake_server(:inet, replying(self(), many))
      assert Client.check(address, []) == {:error, :response_too_large}

      {:ok, conn} = Client.connect(address, max_response: 100_000)
      assert {:ok, "OK", conn} = Client.request(conn, [])
      assert Client.request(conn, [], max_response: 100) == {:error, :response_too_large}
    end

    test "invalid replies" do
      for reply <- ["garbage\n\n", "result=OK\n\n", "\n"] do
        address = fake_server(:inet, replying(self(), reply))
        assert Client.check(address, []) == {:error, :invalid_response}, inspect(reply)
      end
    end
  end

  describe "over a command" do
    @describetag :tmp_dir

    # Answers each request with DUNNO and its number of attributes.
    @script """
    #!/bin/sh
    n=0
    while IFS= read -r line; do
      if [ -z "$line" ]; then
        printf 'action=DUNNO %s\\nignored=1\\n\\n' "$n"
        n=0
      else
        n=$((n + 1))
      fi
    done
    """

    setup %{tmp_dir: dir} do
      script = Path.join(dir, "policy.sh")
      File.write!(script, @script)
      File.chmod!(script, 0o755)
      %{script: script}
    end

    test "speaks over standard input and output", %{script: script} do
      {:ok, conn} = Client.connect({:command, [script]})
      assert {:ok, "DUNNO 3", conn} = Client.request(conn, sender: "a@example.com", size: 10)
      assert {:ok, "DUNNO 1", conn} = Client.request(conn, [])
      assert {:ok, "DUNNO 2", conn} = Client.request(conn, recipient: "b\nc")
      assert Client.close(conn) == :ok
      assert Client.close(conn) == :ok

      assert Client.check({:command, ["sh", script]}, a: 1) == {:ok, "DUNNO 2"}
      {:ok, address} = Client.parse_address("spawn:/bin/sh #{script}")
      assert Client.check(address, []) == {:ok, "DUNNO 1"}
    end

    test "reports programs that cannot run", %{script: script, tmp_dir: dir} do
      assert Client.connect({:command, [Path.join(dir, "missing")]}) == {:error, :enoent}
      assert Client.connect({:command, ["sovite-no-such-program"]}) == {:error, :enoent}
      assert Client.connect({:command, [dir]}) == {:error, :eacces}

      File.chmod!(script, 0o644)
      assert Client.connect({:command, [script]}) == {:error, :eacces}
    end

    test "programs that exit or do not answer" do
      {:ok, conn} = Client.connect({:command, ["/bin/sh", "-c", "exit 0"]})
      assert Client.request(conn, []) == {:error, :closed}
      assert Client.request(conn, []) == {:error, :closed}

      # Closes its standard input but keeps running: writes fail.
      {:ok, conn} = Client.connect({:command, ["/bin/sh", "-c", "exec 0<&-; sleep 1"]})
      Process.sleep(100)

      assert Client.request(conn, [x: String.duplicate("x", 200_000)], timeout: 2_000) ==
               {:error, :closed}

      {:ok, conn} = Client.connect({:command, ["/bin/sh", "-c", "cat >/dev/null"]})
      assert Client.request(conn, [], timeout: 50) == {:error, :timeout}
    end

    test "closes the program when the owner exits", %{script: script} do
      test = self()

      owner =
        spawn(fn ->
          {:ok, conn} = Client.connect({:command, [script]})
          send(test, {:conn, conn})
          receive(do: (:stop -> :ok))
        end)

      assert_receive {:conn, %Client{io: {:port, port, _ref}}}
      assert Port.info(port) != nil
      send(owner, :stop)
      wait_until(fn -> Port.info(port) == nil end)
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
end
