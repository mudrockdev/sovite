defmodule Sovite.Core.MTA.LogToolsTest do
  # LogReader, Trace, and LogReport: reading Sovite's logs back.
  use ExUnit.Case, async: true

  alias Sovite.Core.LogReader
  alias Sovite.Core.MTA.{LogReport, Trace}

  @moduletag :tmp_dir

  @log """
  2026-10-04 12:00:00.100 [info] session_id=s1 remote_ip=192.0.2.7 event=smtp.server.command.stop smtp.server.command.stop: argument=<x@spam.example>, command=RCPT, duration=1, reply=554 5.7.1 <x@spam.example>: Relay access denied, reply_code=554
  2026-10-04 12:00:01.000 [info] queue_id=Q1 session_id=s1 event=queue.message.enqueued queue.message.enqueued: recipients=2, sender=alice@sender.example, size=2048
  2026-10-04 12:00:01.001 [info] queue_id=Q1 session_id=s1 remote_ip=192.0.2.7 event=smtp.message.accepted smtp.message.accepted: helo=client.example, message_id=<m1@Sender.Example>, recipients=2, sender=alice@sender.example
  2026-10-04 12:00:02.000 [info] queue_id=Q1 event=smtp.client.delivery.stop smtp.client.delivery.stop: duration=10, recipient=bob@example.net, relay=mx.example.net[192.0.2.25], reply=250 2.0.0 Ok: queued as ABC, status=delivered
  2026-10-04 12:00:02.000 [info] queue_id=Q1 event=smtp.client.delivery.stop smtp.client.delivery.stop: duration=10, recipient=carol@example.org, relay=mx.example.org[192.0.2.26], reply=550 5.1.1 <carol@example.org>: User unknown, sorry, status=failed
  2026-10-04 12:00:02.100 [info] queue_id=Q1 event=queue.notification.sent queue.notification.sent: kind=failure, notification_id=N1, recipients=1, to=alice@sender.example
  2026-10-04 12:00:02.200 [info] queue_id=Q1 event=queue.message.removed queue.message.removed: reason=bounced
  2026-10-04 12:00:03.000 [info] queue_id=N1 event=queue.message.enqueued queue.message.enqueued: recipients=1, sender=, size=900
  2026-10-04 13:10:00.000 [info] queue_id=N1 event=smtp.client.delivery.stop smtp.client.delivery.stop: duration=5, recipient=alice@sender.example, relay=mx.sender.example[192.0.2.30], reply=451 4.7.1 try later, status=deferred
  2026-10-04 13:20:00.000 [warning] session_id=s2 remote_ip=192.0.2.9 event=auth.failure auth.failure: mechanism=PLAIN, reason=invalid_credentials, username=mallory
  2026-10-04 13:30:00.000 [info] queue_id=Q2 session_id=s3 event=queue.message.enqueued queue.message.enqueued: recipients=1, sender=bob@example.net, size=100
  not a sovite line
  """

  defp write_log(dir, name \\ "sovite.2026-10-04.1.log", contents \\ @log) do
    path = Path.join(dir, name)
    File.write!(path, contents)
    path
  end

  describe "LogReader" do
    test "parses text lines" do
      [line | _] = String.split(@log, "\n")

      assert %{
               time: ~N[2026-10-04 12:00:00.100],
               level: "info",
               session_id: "s1",
               queue_id: nil,
               remote_ip: "192.0.2.7",
               event: "smtp.server.command.stop",
               fields: %{
                 "command" => "RCPT",
                 "reply" => "554 5.7.1 <x@spam.example>: Relay access denied",
                 "reply_code" => "554"
               }
             } = LogReader.parse(line)
    end

    test "parses JSON lines" do
      line =
        ~s({"time":"2026-10-04T12:00:00.123456Z","level":"info","msg":"queue.message.removed: reason=delivered","queue_id":"Q9","event":"queue.message.removed"})

      assert %{
               time: ~N[2026-10-04 12:00:00.123456],
               queue_id: "Q9",
               fields: %{"reason" => "delivered"}
             } = LogReader.parse(line)
    end

    test "parses syslog and journald lines" do
      year = Date.utc_today().year

      for line <- [
            "Oct  4 12:00:00 mx1 sovite[812]: queue_id=Q9 event=queue.message.removed queue.message.removed: reason=expired",
            "Oct 04 12:00:00 mx1 sovite[812]: 2026-10-04 12:00:00.000 [info] queue_id=Q9 event=queue.message.removed queue.message.removed: reason=expired",
            "<22>1 2026-10-04T12:00:00Z mx1 sovite 812 - - queue_id=Q9 event=queue.message.removed queue.message.removed: reason=expired"
          ] do
        assert %{queue_id: "Q9", fields: %{"reason" => "expired"}, time: time} =
                 LogReader.parse(line)

        assert time.month == 10 and time.day == 4 and time.hour == 12
        assert time.year in [year, 2026]
      end

      assert LogReader.parse("Oct  4 12:00:00 mx1 postfix/smtpd[1]: connect") == nil
      assert LogReader.parse(<<0xFF, "x">>) == nil
    end

    test "finds the log files of a pattern, compressed ones too", %{tmp_dir: dir} do
      first = write_log(dir, "sovite.2026-10-03.1.log.gz", :zlib.gzip(@log))
      File.touch!(first, {{2026, 10, 3}, {0, 0, 0}})
      second = write_log(dir)
      write_log(dir, "other.log")

      assert LogReader.files(dir, "sovite.{date}.{n}.log") == [first, second]
      assert LogReader.files(Path.join(dir, "missing"), "sovite.{n}.log") == []
      assert [first] |> LogReader.stream() |> Enum.count() == 11
    end
  end

  describe "Trace" do
    test "follows a message by Message-ID, with its session and notifications", %{tmp_dir: dir} do
      path = write_log(dir)
      trace = Trace.run("m1@sender.example", [path])

      assert trace.queue_ids == ["N1", "Q1"]
      lines = Enum.map(trace.entries, & &1.line)
      assert length(lines) == 9
      # The rejected command of the same session comes first.
      assert hd(lines) =~ "Relay access denied"
      refute Enum.any?(lines, &(&1 =~ "Q2"))
      refute Enum.any?(lines, &(&1 =~ "mallory"))
    end

    test "follows a message by queue ID", %{tmp_dir: dir} do
      path = write_log(dir)
      assert %{queue_ids: ["Q2"], entries: [entry]} = Trace.run("Q2", [path])
      assert entry.queue_id == "Q2"
      assert %{queue_ids: [], entries: []} = Trace.run("<nobody@example.com>", [path])
    end
  end

  describe "LogReport" do
    test "counts traffic, delays, and reasons", %{tmp_dir: dir} do
      report = [write_log(dir)] |> LogReader.stream() |> LogReport.build()

      assert %{
               received: 3,
               delivered: 1,
               bounced: 1,
               deferred: 1,
               rejected: 1,
               notifications: 1,
               warnings: 1,
               failed_logins: 1,
               bytes_received: 3048,
               bytes_delivered: 2048
             } = report.totals

      assert report.domains == %{"example.net" => {1, 2048, 1, 1}}
      assert report.senders["alice@sender.example"] == {1, 2048}
      assert report.senders["<>"] == {1, 900}

      text = LogReport.format(report)
      assert text =~ "Sovite log summary for 2026-10-04 12:00:00 to 2026-10-04 13:30:00"
      assert text =~ ~r/\s+3   received/
      assert text =~ "Per-Hour Traffic"
      assert text =~ "12:00-12:59"
      assert text =~ "example.net"
      assert text =~ "550 5.1.1 <...>: User unknown, sorry"
      assert text =~ "mallory from 192.0.2.9"
    end

    test "filters by date, and spans several days", %{tmp_dir: dir} do
      next_day = String.replace(@log, "2026-10-04 13:", "2026-10-05 13:")
      stream = [write_log(dir, "x.log", next_day)] |> LogReader.stream()

      assert LogReport.build(stream, date: ~D[2026-10-05]).totals.received == 1
      assert LogReport.format(LogReport.build(stream)) =~ "Per-Day Traffic"
      assert LogReport.format(LogReport.build([])) =~ "no log lines"
    end
  end
end
