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
    assert log |> String.split("\n", trim: true) |> length() == 1
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

    assert log |> String.split("\n", trim: true) |> length() == 1
  end
end
