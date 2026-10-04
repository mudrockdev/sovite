defmodule Sovite.Core.TelemetryTest do
  # Attaches a global telemetry handler and changes the log level.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Sovite.Core.Telemetry

  setup do
    Telemetry.attach_logger()
    on_exit(&Telemetry.detach_logger/0)
  end

  test "logs message lifecycle events at info with the queue ID" do
    log =
      capture_log([level: :info, metadata: [:queue_id]], fn ->
        :telemetry.execute(
          [:sovite, :queue, :message, :enqueued],
          %{size: 1024, recipients: 2},
          %{queue_id: "Q42", sender: "a@example.com"}
        )
      end)

    assert log =~ "queue_id=Q42"
    assert log =~ "queue.message.enqueued: recipients=2, sender=a@example.com, size=1024"
  end

  test "quotes untrusted values so they cannot forge log lines" do
    log =
      capture_log(fn ->
        :telemetry.execute([:sovite, :queue, :message, :removed], %{}, %{
          queue_id: "Q1",
          reason: "x\r\n12:00:00 [info] fake line"
        })
      end)

    assert log =~ ~s(reason="x\\r\\n12:00:00 [info] fake line")
    # Count only this event's lines: other tests' processes may log too.
    assert log |> String.split("\n", trim: true) |> Enum.count(&(&1 =~ "fake line")) == 1
  end

  test "logs other events at debug" do
    measurements = %{duration: System.convert_time_unit(15, :millisecond, :native)}
    metadata = %{session_id: "S1", command: "EHLO", reply_code: 250}

    assert capture_log([level: :info], fn ->
             :telemetry.execute(
               [:sovite, :smtp, :server, :command, :stop],
               measurements,
               metadata
             )
           end) == ""

    log =
      capture_log([level: :debug], fn ->
        Logger.put_process_level(self(), :debug)
        :telemetry.execute([:sovite, :smtp, :server, :command, :stop], measurements, metadata)
        Logger.delete_process_level(self())
      end)

    assert log =~ "smtp.server.command.stop: command=EHLO, duration=15, reply_code=250"
  end

  test "attaching twice does not duplicate log lines" do
    Telemetry.attach_logger()

    log =
      capture_log(fn ->
        :telemetry.execute([:sovite, :queue, :message, :removed], %{}, %{
          queue_id: "Q1",
          reason: :delivered
        })
      end)

    assert log |> String.split("\n", trim: true) |> Enum.count(&(&1 =~ "reason=delivered")) == 1
  end

  test "logs failed logins as warnings, ready for fail2ban" do
    log =
      capture_log([level: :warning, metadata: [:remote_ip]], fn ->
        :telemetry.execute([:sovite, :auth, :failure], %{}, %{
          session_id: "S1",
          remote_ip: {192, 0, 2, 7},
          mechanism: "PLAIN",
          username: "alice",
          reason: :invalid_credentials
        })
      end)

    assert log =~ "[warning]"
    assert log =~ "remote_ip=192.0.2.7"
    assert log =~ "auth.failure: mechanism=PLAIN, reason=invalid_credentials, username=alice"
  end

  test "formats certificates, bans, and handshake failures" do
    log =
      capture_log([level: :info], fn ->
        :telemetry.execute([:sovite, :tls, :certificate, :loaded], %{}, %{
          cert_file: "/etc/mx.pem",
          names: ["mx.example.com", "mail.example.com"],
          not_after: ~U[2027-01-01 00:00:00Z]
        })

        :telemetry.execute([:sovite, :abuse, :penalty, :banned], %{failures: 10}, %{
          penalty: Sovite.Core.AuthPenalty,
          key: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0},
          ban_time: 3_600_000
        })

        :telemetry.execute([:sovite, :smtp, :server, :tls, :stop], %{duration: 0}, %{
          session_id: "S1",
          remote_ip: {192, 0, 2, 7},
          error: {:tls_alert, {:handshake_failure, ~c"no shared cipher"}}
        })
      end)

    assert log =~ "names=mx.example.com mail.example.com, not_after=2027-01-01T00:00:00Z"
    assert log =~ "key=2001:db8::"
    assert log =~ "smtp.server.tls.stop:"
  end
end
