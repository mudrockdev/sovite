defmodule Sovite.Core.Logging.SyslogHandlerTest do
  # Adds a global :logger handler.
  use ExUnit.Case, async: false

  require Logger

  alias Sovite.Core.Logging
  alias Sovite.Core.Logging.SyslogHandler

  @time ~U[2026-10-04 09:05:07.123456Z]

  defp config(fields \\ %{}),
    do:
      Map.merge(
        %{facility: :mail, format: :rfc3164, hostname: "mx1", local: true, pid: "812", utc: true},
        fields
      )

  test "encodes RFC 3164 messages, local and remote" do
    assert SyslogHandler.encode(:info, @time, "hello\n", config()) ==
             "<22>Oct  4 09:05:07 sovite[812]: hello"

    assert SyslogHandler.encode(
             :warning,
             @time,
             ["a", "b"],
             config(%{local: false, facility: :local3})
           ) ==
             "<156>Oct  4 09:05:07 mx1 sovite[812]: ab"
  end

  test "encodes RFC 5424 messages" do
    assert SyslogHandler.encode(:error, @time, "boom", config(%{format: :rfc5424})) ==
             "<19>1 2026-10-04T09:05:07.123456Z mx1 sovite 812 - - boom"
  end

  test "cuts long messages at a character boundary" do
    message = String.duplicate("é", 5000)
    encoded = SyslogHandler.encode(:debug, @time, message, config())
    assert byte_size(encoded) <= 8192
    assert String.valid?(encoded)
  end

  test "sends log events to a local socket" do
    path = Path.join(System.tmp_dir!(), "sovite-syslog-#{System.unique_integer([:positive])}")
    {:ok, daemon} = :socket.open(:local, :dgram, :default)
    :ok = :socket.bind(daemon, %{family: :local, path: path})
    on_exit(fn -> File.rm(path) end)

    [spec] =
      Logging.child_specs(%{
        directory: nil,
        format: :text,
        syslog: true,
        syslog_address: {:unix, path},
        syslog_facility: :daemon,
        syslog_format: :rfc3164
      })

    {SyslogHandler, opts} = spec
    assert opts[:replace] == :default
    # Leave the test runner's handler alone.
    start_supervised!({SyslogHandler, Keyword.delete(opts, :replace)})

    Logger.info("queued", queue_id: "Q1", event: "queue.message.enqueued")

    assert {:ok, {_from, datagram}} = :socket.recvfrom(daemon, 0, [], 2_000)
    assert datagram =~ ~r/\A<30>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d sovite\[\d+\]: /
    assert datagram =~ "queue_id=Q1 event=queue.message.enqueued queued"

    stop_supervised!({SyslogHandler, :sovite_syslog})
    assert {:error, {:not_found, :sovite_syslog}} = :logger.get_handler_config(:sovite_syslog)
  end

  test "a daemon that is not running drops lines without blocking" do
    path = Path.join(System.tmp_dir!(), "sovite-missing-#{System.unique_integer([:positive])}")

    start_supervised!(
      {SyslogHandler,
       id: :sovite_syslog_missing, address: {:unix, path}, formatter: Logging.formatter(:text)}
    )

    Logger.info("nobody listens")
  end

  test "UDP to a remote daemon" do
    {:ok, daemon} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(daemon)

    start_supervised!(
      {SyslogHandler,
       id: :sovite_syslog_udp,
       address: {:udp, {127, 0, 0, 1}, port},
       format: :rfc5424,
       hostname: "mx1",
       formatter: Logging.formatter(:json)}
    )

    Logger.warning("remote")
    assert {:ok, {_ip, _port, datagram}} = :gen_udp.recv(daemon, 0, 2_000)
    assert datagram =~ ~r/\A<20>1 \S+ mx1 sovite \d+ - - \{/
    assert datagram =~ ~s("msg":"remote")
  end
end
