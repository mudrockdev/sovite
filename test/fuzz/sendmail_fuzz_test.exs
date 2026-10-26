defmodule Sovite.SendmailFuzzTest do
  # Fuzzing of sendmail(1), which any local user can run: options,
  # environment ($USER, $LOGNAME), and the message on standard input are
  # theirs. Whatever they give, it ends with an exit status, sends only
  # valid addresses, and cannot add header fields through its name.
  # Not async: standard error is captured, and it is global.
  use ExUnit.Case, async: false
  use ExUnitProperties

  import ExUnit.CaptureIO

  alias Sovite.Core.Sendmail
  alias Sovite.Message.Headers
  alias Sovite.Queue.Spool
  alias Sovite.Test.{FakeMTA, Fuzz}
  alias Sovite.Validators

  @moduletag :fuzz
  # `mix fuzz` runs each property many times.
  @moduletag timeout: :infinity
  @moduletag :tmp_dir

  @injected "X-Injected: yes"

  @options [
    "-t",
    "-i",
    "-oi",
    "-f",
    "-r",
    "-F",
    "-bm",
    "-bp",
    "-bi",
    "-q",
    "-v",
    "-oem",
    "-B8BITMIME"
  ]
  @words [
    "root",
    "ann@example.net",
    "<>",
    "Ann Example",
    "bücher.example",
    "a\r\n#{@injected}",
    "--"
  ]

  @messages [
    "Subject: report\nTo: someone@example.net\n\nAll good.\n.\nnot sent\n",
    "From: me@example.org\r\nTo: Ann <ann@example.net>, bob\r\nBcc: s@example.net\r\n\r\n.\r\nend\r\n",
    "Subject: Grüße\n\nHallo\n",
    "no header line\n\nbody",
    ""
  ]

  setup %{tmp_dir: dir} do
    mta = start_supervised!({FakeMTA, owner: self(), extensions: ["8BITMIME", "SMTPUTF8"]})
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

    %{mta: mta, config: config}
  end

  property "ends with a status, sends valid addresses, and adds no field through names", %{
    mta: mta,
    config: config
  } do
    word = Fuzz.input(@options ++ @words, ["-", "@", "<", ">", "\r\n", " "])
    user = Fuzz.input(["cron", "a b", "ünïcode", "\"q\"", "x\r\n#{@injected}", ""], ["\r\n", "@"])

    check all(
            argv <- list_of(word, max_length: 6),
            input <- Fuzz.input(@messages, ["\n", "\r\n", ".\n", ":", "Bcc:", "To:"]),
            env <- fixed_map(%{"USER" => user, "LOGNAME" => user}),
            max_runs: Fuzz.runs()
          ) do
      # Never another config: that could send to a real server.
      argv = Enum.reject(argv, &String.starts_with?(&1, "-C"))
      {:ok, device} = StringIO.open(input)

      capture_io(:stderr, fn ->
        status = Sendmail.run(["-C", config | argv], input: device, env: env)
        send(self(), {:status, status})
      end)

      assert_received {:status, status}
      assert status in [0, 64, 65, 69, 75], inspect(status)

      # The fake MTA reports a message before it accepts it.
      receive do
        {:fake_mta, ^mta, {:message, message}} -> assert_message(message, input)
      after
        0 -> :ok
      end

      flush(mta)
    end
  end

  defp assert_message(message, input) do
    assert message.mail_from == "" or Validators.mailbox?(message.mail_from, utf8: true)

    assert Enum.all?(message.rcpt_to, &Validators.mailbox?(&1, utf8: true)),
           inspect(message.rcpt_to)

    # Only CRLF line endings, and an injected field only if the message
    # itself had one.
    refute message.data =~ ~r/\r(?!\n)|(?<!\r)\n/, inspect(message.data)

    header =
      case Headers.split(message.data) do
        {:ok, header, _body} -> header
        :more -> message.data
      end

    injected = Enum.count(Headers.parse(header), &(elem(&1, 0) == "x-injected"))
    assert injected <= count(input, @injected), inspect(header)
  end

  defp count(text, part), do: length(:binary.matches(text, part))

  defp flush(mta) do
    receive do
      {:fake_mta, ^mta, _event} -> flush(mta)
    after
      0 -> :ok
    end
  end
end
