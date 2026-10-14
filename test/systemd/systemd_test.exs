defmodule Sovite.SystemdTest do
  use ExUnit.Case, async: true

  alias Sovite.Systemd
  alias Sovite.Systemd.Watchdog

  # A bound datagram socket standing in for systemd's notify socket.
  defp notify_socket(_context) do
    path = Path.join(System.tmp_dir!(), "sovite-sd-#{System.unique_integer([:positive])}")
    {:ok, socket} = :socket.open(:local, :dgram, :default)
    :ok = :socket.bind(socket, %{family: :local, path: path})

    on_exit(fn ->
      :socket.close(socket)
      File.rm(path)
    end)

    %{socket: socket, env: %{"NOTIFY_SOCKET" => path}}
  end

  defp receive_datagram(socket, timeout \\ 1000) do
    case :socket.recvfrom(socket, 0, timeout) do
      {:ok, {_source, data}} -> data
      {:error, reason} -> flunk("no datagram: #{inspect(reason)}")
    end
  end

  defp pid, do: System.pid()

  def forward_event(_event, measurements, metadata, owner),
    do: send(owner, {:skipped, measurements, metadata})

  describe "notify/2" do
    setup :notify_socket

    test "sends the state as a datagram", %{socket: socket, env: env} do
      assert :ok = Systemd.notify("READY=1", env: env)
      assert receive_datagram(socket) == "READY=1"

      assert :ok = Systemd.notify([ready: 1, status: "Up\nand running", errno: 0], env: env)
      assert receive_datagram(socket) == "READY=1\nSTATUS=Up and running\nERRNO=0\n"

      assert :ok = Systemd.notify([{"MAINPID", 42}], env: env)
      assert receive_datagram(socket) == "MAINPID=42\n"
    end

    test "returns an error without a usable socket", %{env: env} do
      assert {:error, :no_socket} = Systemd.notify("READY=1", env: %{})
      assert {:error, :no_socket} = Systemd.notify("READY=1", env: %{"NOTIFY_SOCKET" => ""})
      assert {:error, :invalid_socket} = Systemd.ready(env: %{"NOTIFY_SOCKET" => "run/notify"})
      assert {:error, :unsupported} = Systemd.ready(env: %{"NOTIFY_SOCKET" => "vsock:2:1234"})

      missing = env["NOTIFY_SOCKET"] <> "-missing"
      assert {:error, :enoent} = Systemd.ready(env: %{"NOTIFY_SOCKET" => missing})

      too_long = "/" <> String.duplicate("a", 200)
      assert {:error, _reason} = Systemd.ready(env: %{"NOTIFY_SOCKET" => too_long})
    end

    test "reaches a socket in the abstract namespace" do
      name = "sovite-test-#{System.unique_integer([:positive])}"
      {:ok, socket} = :socket.open(:local, :dgram, :default)
      :ok = :socket.bind(socket, %{family: :local, path: <<0, name::binary>>})

      try do
        assert :ok = Systemd.watchdog(env: %{"NOTIFY_SOCKET" => "@" <> name})
        assert receive_datagram(socket) == "WATCHDOG=1"
      after
        :socket.close(socket)
      end
    end

    test "helpers send their fields", %{socket: socket, env: env} do
      assert :ok = Systemd.ready(env: env)
      assert receive_datagram(socket) == "READY=1\n"

      assert :ok = Systemd.ready(status: "Accepting mail", env: env)
      assert receive_datagram(socket) == "READY=1\nSTATUS=Accepting mail\n"

      assert :ok = Systemd.stopping(env: env)
      assert receive_datagram(socket) == "STOPPING=1\n"

      assert :ok = Systemd.status("line one\r\nline two", env: env)
      assert receive_datagram(socket) == "STATUS=line one line two\n"

      assert :ok = Systemd.watchdog(env: env)
      assert receive_datagram(socket) == "WATCHDOG=1"

      assert :ok = Systemd.extend_timeout(5_000_000, env: env)
      assert receive_datagram(socket) == "EXTEND_TIMEOUT_USEC=5000000\n"
    end

    test "reloading/1 sends the CLOCK_MONOTONIC time", %{socket: socket, env: env} do
      assert :ok = Systemd.reloading(status: "Reloading", env: env)
      data = receive_datagram(socket)

      case Systemd.monotonic_usec() do
        {:ok, now} ->
          assert ["RELOADING=1", "MONOTONIC_USEC=" <> usec, "STATUS=Reloading", ""] =
                   String.split(data, "\n")

          assert String.to_integer(usec) <= now
          assert now - String.to_integer(usec) < 5_000_000

        :error ->
          assert data == "RELOADING=1\nSTATUS=Reloading\n"
      end
    end
  end

  test "monotonic_usec/0 follows the OS monotonic clock" do
    if :os.type() == {:unix, :linux} do
      assert {:ok, first} = Systemd.monotonic_usec()
      Process.sleep(20)
      assert {:ok, second} = Systemd.monotonic_usec()
      assert second - first >= 20_000

      # CLOCK_MONOTONIC counts from boot, minus time suspended, so it is
      # no later than /proc/uptime's CLOCK_BOOTTIME.
      [uptime | _] = "/proc/uptime" |> File.read!() |> String.split()
      {uptime, ""} = Float.parse(uptime)
      assert second <= round((uptime + 1) * 1_000_000)
    end
  end

  test "notify_socket?/1" do
    assert Systemd.notify_socket?(env: %{"NOTIFY_SOCKET" => "/run/systemd/notify"})
    refute Systemd.notify_socket?(env: %{"NOTIFY_SOCKET" => ""})
    refute Systemd.notify_socket?(env: %{})
  end

  test "watchdog_interval/1" do
    assert {:ok, 30_000} = Systemd.watchdog_interval(env: %{"WATCHDOG_USEC" => "30000000"})
    assert {:ok, 1} = Systemd.watchdog_interval(env: %{"WATCHDOG_USEC" => "10"})

    assert {:ok, 100} =
             Systemd.watchdog_interval(
               env: %{"WATCHDOG_USEC" => "100000", "WATCHDOG_PID" => pid()}
             )

    other = Integer.to_string(String.to_integer(pid()) + 1)

    for env <- [
          %{},
          %{"WATCHDOG_USEC" => "0"},
          %{"WATCHDOG_USEC" => "-5"},
          %{"WATCHDOG_USEC" => "10s"},
          %{"WATCHDOG_USEC" => ""},
          %{"WATCHDOG_USEC" => "100000", "WATCHDOG_PID" => other},
          %{"WATCHDOG_USEC" => "100000", "WATCHDOG_PID" => "self"}
        ] do
      assert Systemd.watchdog_interval(env: env) == :disabled, inspect(env)
    end
  end

  describe "listen_fds/1" do
    test "returns the passed sockets with their names" do
      env = %{"LISTEN_PID" => pid(), "LISTEN_FDS" => "2", "LISTEN_FDNAMES" => "smtp:submission"}
      assert Systemd.listen_fds(env: env) == [{"smtp", 3}, {"submission", 4}]

      env = %{"LISTEN_PID" => pid(), "LISTEN_FDS" => "3"}
      assert Systemd.listen_fds(env: env) == [{"unknown", 3}, {"unknown", 4}, {"unknown", 5}]

      env = Map.put(env, "LISTEN_FDNAMES", "a:b")
      assert Systemd.listen_fds(env: env) == [{"unknown", 3}, {"unknown", 4}, {"unknown", 5}]

      assert Systemd.listen_fds(env: %{"LISTEN_PID" => pid(), "LISTEN_FDS" => "0"}) == []
    end

    test "ignores sockets for another process or invalid counts" do
      other = Integer.to_string(String.to_integer(pid()) + 1)

      for env <- [
            %{},
            %{"LISTEN_FDS" => "1"},
            %{"LISTEN_PID" => other, "LISTEN_FDS" => "1"},
            %{"LISTEN_PID" => "", "LISTEN_FDS" => "1"},
            %{"LISTEN_PID" => pid()},
            %{"LISTEN_PID" => pid(), "LISTEN_FDS" => "-1"},
            %{"LISTEN_PID" => pid(), "LISTEN_FDS" => "two"}
          ] do
        assert Systemd.listen_fds(env: env) == [], inspect(env)
      end
    end

    test "can unset the variables" do
      System.put_env(%{"LISTEN_PID" => pid(), "LISTEN_FDS" => "1", "LISTEN_FDNAMES" => "smtp"})

      assert Systemd.listen_fds() == [{"smtp", 3}]
      assert System.get_env("LISTEN_FDS") == "1"

      assert Systemd.listen_fds(unset: true) == [{"smtp", 3}]
      assert System.get_env("LISTEN_PID") == nil
      assert System.get_env("LISTEN_FDS") == nil
      assert System.get_env("LISTEN_FDNAMES") == nil
      assert Systemd.listen_fds() == []
    after
      Enum.each(["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"], &System.delete_env/1)
    end
  end

  describe "listen_socket/2" do
    # A real inherited fd is owned by no port. Passing a socket's fd to
    # ourselves over SCM_RIGHTS makes such a duplicate, so the port from
    # listen_socket/2 is its only owner and closes it.
    defp inherited_fd(socket) do
      path = Path.join(System.tmp_dir!(), "sovite-sd-#{System.unique_integer([:positive])}")
      {:ok, receiver} = :socket.open(:local, :dgram, :default)
      :ok = :socket.bind(receiver, %{family: :local, path: path})
      {:ok, sender} = :socket.open(:local, :dgram, :default)
      {:ok, fd} = :socket.getopt(socket, {:otp, :fd})

      :ok =
        :socket.sendmsg(sender, %{
          addr: %{family: :local, path: path},
          iov: ["fd"],
          ctrl: [%{level: :socket, type: :rights, data: <<fd::native-32>>}]
        })

      {:ok, %{ctrl: [%{data: <<passed::native-32>>}]}} = :socket.recvmsg(receiver, 0, 0, [], 1000)
      :socket.close(sender)
      :socket.close(receiver)
      File.rm(path)
      :socket.close(socket)
      passed
    end

    defp listening(family, address) do
      {:ok, socket} = :socket.open(family, :stream, :default)
      :ok = :socket.bind(socket, address)
      :ok = :socket.listen(socket)
      socket
    end

    defp assert_serves(listen, address, port, family) do
      {:ok, client} = :gen_tcp.connect(address, port, [family, :binary, active: false])
      {:ok, server} = :gen_tcp.accept(listen, 1000)
      :ok = :gen_tcp.send(client, "hello")
      assert {:ok, "hello"} = :gen_tcp.recv(server, 5, 1000)
      :gen_tcp.close(client)
      :gen_tcp.close(server)
    end

    test "opens inherited IPv4 and IPv6 sockets" do
      for {family, ip} <- [{:inet, {127, 0, 0, 1}}, {:inet6, {0, 0, 0, 0, 0, 0, 0, 1}}] do
        fd = inherited_fd(listening(family, %{family: family, addr: ip, port: 0}))
        assert {:ok, listen} = Systemd.listen_socket(fd, [:binary, active: false])

        try do
          assert {:ok, {^ip, port}} = :inet.sockname(listen)
          assert_serves(listen, ip, port, family)
        after
          :gen_tcp.close(listen)
        end
      end
    end

    test "opens an inherited unix socket" do
      path = Path.join(System.tmp_dir!(), "sovite-sd-#{System.unique_integer([:positive])}")
      fd = inherited_fd(listening(:local, %{family: :local, path: path}))

      try do
        assert {:ok, listen} = Systemd.listen_socket(fd, [:binary, active: false])
        assert_serves(listen, {:local, path}, 0, :local)
        :gen_tcp.close(listen)
      after
        File.rm(path)
      end
    end

    test "uses the family it is given" do
      fd = inherited_fd(listening(:inet6, %{family: :inet6, addr: :loopback, port: 0}))
      assert {:error, :einval} = Systemd.listen_socket(fd, [:inet])
      assert {:ok, listen} = Systemd.listen_socket(fd, [:inet6])
      :gen_tcp.close(listen)
    end

    test "returns an error for a bad fd" do
      assert {:error, :ebadf} = Systemd.listen_socket(100_000)
    end
  end

  describe "Watchdog" do
    setup :notify_socket

    defp watchdog_env(env), do: Map.put(env, "WATCHDOG_USEC", "100000")

    test "pings every half interval", %{socket: socket, env: env} do
      start_supervised!({Watchdog, env: watchdog_env(env)})
      started = System.monotonic_time(:millisecond)

      for _ <- 1..3, do: assert(receive_datagram(socket) == "WATCHDOG=1")

      # The first ping is immediate, then one every 50 ms.
      elapsed = System.monotonic_time(:millisecond) - started
      assert elapsed >= 90 and elapsed < 1000
    end

    test "skips the ping when the check fails", %{socket: socket, env: env} do
      handler = "watchdog-skipped-#{System.unique_integer([:positive])}"

      :ok =
        :telemetry.attach(
          handler,
          [:sovite, :systemd, :watchdog, :skipped],
          &__MODULE__.forward_event/4,
          self()
        )

      on_exit(fn -> :telemetry.detach(handler) end)

      {:ok, healthy} = Agent.start_link(fn -> false end)

      check = fn ->
        case Agent.get(healthy, & &1) do
          :raise -> raise "boom"
          value -> value
        end
      end

      start_supervised!({Watchdog, env: watchdog_env(env), check: check})

      assert_receive {:skipped, %{}, %{reason: false}}, 1000
      assert {:error, :timeout} = :socket.recvfrom(socket, 0, 0)

      Agent.update(healthy, fn _ -> :raise end)
      assert_receive {:skipped, %{}, %{reason: {:error, %RuntimeError{message: "boom"}}}}, 1000

      Agent.update(healthy, fn _ -> true end)
      assert receive_datagram(socket) == "WATCHDOG=1"
    end

    test "is ignored when the watchdog is disabled", %{env: env} do
      assert :ignore = Watchdog.start_link(env: env)
      assert :ignore = Watchdog.start_link(env: %{})
    end

    test "registers its name", %{env: env} do
      name = :"watchdog_#{System.unique_integer([:positive])}"
      start_supervised!({Watchdog, env: watchdog_env(env), name: name})
      assert is_pid(Process.whereis(name))
    end
  end
end
