defmodule Sovite.Core.SendmailTest do
  # Not async: standard error is captured, and it is global.
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Sovite.Core.Sendmail
  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.Test.FakeMTA

  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    mta = start_supervised!({FakeMTA, owner: self()})
    queue = Path.join(dir, "queue")
    :ok = Spool.init(queue)
    config = Path.join(dir, "sovite.toml")

    File.write!(config, """
    [server]
    hostname = "mx.example.com"
    [queue]
    directory = "#{queue}"
    [sendmail]
    server = "[127.0.0.1]:#{FakeMTA.port(mta)}"
    origin = "example.com"
    """)

    %{mta: mta, config: config, queue: queue}
  end

  defp sendmail(context, argv, input, env \\ %{"USER" => "cron"}) do
    {:ok, device} = StringIO.open(input)
    parent = self()

    stderr =
      capture_io(:stderr, fn ->
        send(
          parent,
          {:status, Sendmail.run(["-C", context.config | argv], input: device, env: env)}
        )
      end)

    assert_received {:status, status}
    {status, stderr}
  end

  defp message(mta) do
    assert_receive {:fake_mta, ^mta, {:message, message}}, 5_000
    message
  end

  test "sends to the given recipients, from the user, adding missing fields", context do
    input = "Subject: report\nTo: someone@example.net\n\nAll good.\n.\nnot sent\n"
    assert {0, ""} = sendmail(context, ["root", "admin@example.org"], input)

    message = message(context.mta)
    assert message.mail_from == "cron@example.com"
    assert message.rcpt_to == ["root@example.com", "admin@example.org"]
    assert message.helo == "mx.example.com"

    assert message.data =~
             ~r/\ASubject: report\r\nTo: someone@example.net\r\nFrom: <cron@example.com>\r\nDate: .+\r\nMessage-ID: <.+@example.com>\r\n\r\nAll good.\r\n\z/
  end

  test "-t reads the recipients, -f sets the sender, -F the name, -i keeps dot lines", context do
    input =
      "From: me@example.org\r\nTo: Ann <ann@example.net>, bob\r\nCc: carol@example.net\r\n" <>
        "Bcc: secret@example.net\r\n\r\n.\r\nend\r\n"

    assert {0, ""} =
             sendmail(context, ["-t", "-oi", "-fbounce@example.org", "-F", "Ignored"], input)

    message = message(context.mta)
    assert message.mail_from == "bounce@example.org"

    assert message.rcpt_to == [
             "ann@example.net",
             "carol@example.net",
             "secret@example.net"
           ]

    refute message.data =~ "Bcc"
    assert message.data =~ "From: me@example.org\r\n"
    assert String.ends_with?(message.data, "\r\n\r\n.\r\nend\r\n")

    assert {0, ""} = sendmail(context, ["-F", "Cron \"Daemon\"", "-f", "<>", "x"], "hi\n")
    message = message(context.mta)
    assert message.mail_from == ""
    assert message.data =~ ~s(From: "Cron Daemon" <cron@example.com>\r\n)
    assert message.data =~ "\r\n\r\nhi\r\n"
  end

  test "exit status for refusals, no recipients, bad options, and a missing server", context do
    mta =
      start_supervised!(
        {FakeMTA,
         owner: self(),
         responses: %{
           rcpt: fn arg -> if arg =~ "temp", do: "451 4.3.0 later", else: "550 5.1.1 no" end
         }},
        id: :refusing
      )

    config = Path.join(context.tmp_dir, "refusing.toml")
    File.write!(config, ~s([sendmail]\nserver = "[127.0.0.1]:#{FakeMTA.port(mta)}"\n))
    refusing = %{context | config: config}

    assert {69, "sendmail: gone@" <> _} = sendmail(refusing, ["gone@example.net"], "x\n")
    assert {75, _} = sendmail(refusing, ["temp@example.net"], "x\n")
    assert {65, "sendmail: no recipients\n"} = sendmail(context, [], "x\n")
    assert {64, "sendmail: unknown option -Z\n"} = sendmail(context, ["-Z"], "")
    assert {64, "sendmail: -bs is not supported\n"} = sendmail(context, ["-bs"], "")
    assert {64, "sendmail: option -f needs a value\n"} = sendmail(context, ["-f"], "")

    port =
      (
        {:ok, listen} = :gen_tcp.listen(0, [])
        {:ok, port} = :inet.port(listen)
        :gen_tcp.close(listen)
        port
      )

    File.write!(config, ~s([sendmail]\nserver = "[127.0.0.1]:#{port}"\n))

    assert {75, "sendmail: cannot send to [127.0.0.1]:" <> _} =
             sendmail(refusing, ["a@b.example"], "x\n")
  end

  test "defaults when the config cannot be read", context do
    missing = %{context | config: Path.join(context.tmp_dir, "missing.toml")}

    assert {75, "sendmail: cannot send to [127.0.0.1]:25" <> _} =
             sendmail(missing, ["a@b.example"], "x\n")
  end

  test "newaliases and -q succeed with a note", context do
    assert {0, "newaliases: " <> _} = sendmail(context, ["-bi"], "")
    assert {0, "sendmail: Sovite runs its queue on its own" <> _} = sendmail(context, ["-q"], "")
  end

  test "mailq lists the queue", context do
    assert capture_io(fn -> assert Sendmail.run(["-C", context.config, "-bp"]) == 0 end) ==
             "Mail queue is empty\n"

    envelope = %Envelope{
      queue_id: ID.generate(),
      sender: "",
      recipients: ["a@example.net", "b@example.net", "c@example.net"],
      received_at: ~U[2026-10-10 12:30:00Z]
    }

    {:ok, writer} = Spool.open(context.queue, envelope)
    {:ok, writer} = Spool.write(writer, String.duplicate("x", 2048))
    {:ok, path, _size} = Spool.commit(writer)

    details = %{
      status: "4.4.1",
      reply: "connect to mx.example.net: Connection refused",
      remote: nil,
      smtp: false,
      at: DateTime.utc_now()
    }

    {:ok, loaded} = Spool.load(path)

    {:ok, _} =
      Spool.append(path, loaded.end_offset, [
        {:recipient, "a@example.net", :deferred, details},
        {:recipient, "c@example.net", :delivered, details}
      ])

    :ok = Spool.move(context.queue, envelope.queue_id, :incoming, :hold)

    output = capture_io(fn -> assert Sendmail.run(["-C", context.config, "-bp"]) == 0 end)

    assert output == """
           -Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
           #{envelope.queue_id}!    2048 Sat Oct 10 12:30:00  MAILER-DAEMON
                                                    (connect to mx.example.net: Connection refused)
                                                    a@example.net
                                                    b@example.net

           -- 2 Kbytes in 1 Request.
           """

    assert {69, "mailq: cannot read " <> _} =
             (
               parent = self()

               err =
                 capture_io(:stderr, fn ->
                   send(parent, Sendmail.run(["-C", "/nonexistent.toml", "-bp"]))
                 end)

               assert_received status
               {status, err}
             )
  end
end
