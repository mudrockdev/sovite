defmodule Sovite.SMTP.Server.SessionTest do
  use ExUnit.Case, async: true

  alias Sovite.SMTP.Reply
  alias Sovite.SMTP.Server.Session

  defmodule Handler do
    @moduledoc false
    # Reports every call to the test process. A stage in opts overrides the
    # result: fn argument, state -> result end.
    @behaviour Sovite.SMTP.Server.Handler

    @impl true
    def init(connection, opts) do
      state = Map.new(opts)
      send(state.test, {:init, connection})
      if state[:init], do: state.init.(connection, state), else: {:ok, state}
    end

    @impl true
    def handle_helo(kind, name, state), do: respond(:helo, {kind, name}, state)
    @impl true
    def handle_mail(sender, params, state), do: respond(:mail, {sender, params}, state)
    @impl true
    def handle_rcpt(recipient, state), do: respond(:rcpt, recipient, state)
    @impl true
    def handle_data(transaction, state), do: respond(:data, transaction, state)
    @impl true
    def handle_data_chunk(chunk, state), do: respond(:chunk, IO.iodata_to_binary(chunk), state)
    @impl true
    def handle_data_end(transaction, state), do: respond(:data_end, transaction, state)

    @impl true
    def handle_data_abort(reason, state) do
      send(state.test, {:abort, reason})
      state
    end

    @impl true
    def handle_rset(state) do
      send(state.test, :rset)
      state
    end

    @impl true
    def handle_vrfy(argument, state), do: respond(:vrfy, argument, state)

    @impl true
    def terminate(reason, state), do: send(state.test, {:terminate, reason})

    defp respond(stage, argument, state) do
      send(state.test, {stage, argument})
      if state[stage], do: state[stage].(argument, state), else: {:ok, state}
    end
  end

  def forward_event(_event, measurements, metadata, {pid, ref}),
    do: send(pid, {ref, measurements, metadata})

  defp start(handler_opts \\ [], opts \\ []) do
    handler_opts = Keyword.put(handler_opts, :test, self())
    connection = %{remote_ip: {192, 0, 2, 7}, session_id: "S1"}
    opts = Keyword.merge([hostname: "mx.test", handler: {Handler, handler_opts}], opts)
    {result, out, session} = Session.new(connection, opts)
    {result, IO.iodata_to_binary(out), session}
  end

  defp started(handler_opts \\ [], opts \\ []) do
    {:continue, "220 mx.test ESMTP\r\n", session} = start(handler_opts, opts)
    session
  end

  defp input(session, bytes) do
    {result, out, session} = Session.handle_input(session, bytes)
    {result, IO.iodata_to_binary(out), session}
  end

  # The final line of each reply: "250 2.1.0 Ok".
  defp replies(out) do
    out
    |> String.split("\r\n", trim: true)
    |> Enum.filter(&match?(<<_::binary-3, " ", _::binary>>, &1))
  end

  defp codes(out),
    do: out |> replies() |> Enum.map(&(&1 |> binary_part(0, 3) |> String.to_integer()))

  # A session with EHLO, MAIL, and one RCPT done.
  defp in_transaction(handler_opts \\ [], opts \\ []) do
    session = started(handler_opts, opts)

    {:continue, out, session} =
      input(session, "EHLO c.test\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@y.test>\r\n")

    assert codes(out) == [250, 250, 250]
    session
  end

  test "greets, and passes the connection to the handler" do
    assert {:continue, "220 mx.test ESMTP\r\n", session} = start()
    assert_received {:init, %{remote_ip: {192, 0, 2, 7}, session_id: "S1"}}
    assert Session.session_id(session) == "S1"
  end

  test "generates a session ID when none is given" do
    {:continue, _, session} =
      Session.new(%{remote_ip: {192, 0, 2, 7}},
        hostname: "mx.test",
        handler: {Handler, test: self()}
      )

    assert Session.session_id(session) =~ ~r/\A[a-z2-7]{13}\z/
  end

  test "the handler can refuse the connection" do
    refuse = fn _connection, state -> {:close, Reply.new(554, "5.7.1", "Go away"), state} end
    assert {:close, "554 5.7.1 Go away\r\n", _} = start(init: refuse)
  end

  test "EHLO advertises the extensions without enhanced codes" do
    {:continue, out, _} = input(started(), "EHLO client.test\r\n")

    assert out ==
             "250-mx.test\r\n250-PIPELINING\r\n250-SIZE 10485760\r\n250-8BITMIME\r\n250 ENHANCEDSTATUSCODES\r\n"

    assert_received {:helo, {:ehlo, "client.test"}}
  end

  test "HELO gets a one-line reply" do
    assert {:continue, "250 mx.test\r\n", _} = input(started(), "HELO client.test\r\n")
  end

  test "rejects invalid EHLO names" do
    for name <- ["bad_name", "a..b", "-x.test"] do
      {:continue, out, _} = input(started(), "EHLO #{name}\r\n")
      assert replies(out) == ["501 5.5.2 Invalid hostname"]
    end
  end

  test "runs a pipelined transaction and streams the message" do
    session = started()

    {:continue, out, session} =
      input(
        session,
        "EHLO c.test\r\nMAIL FROM:<a@x.test> BODY=8BITMIME SIZE=100\r\nRCPT TO:<b@y.test>\r\nRCPT TO:<Postmaster>\r\nDATA\r\n"
      )

    assert replies(out) == [
             "250 ENHANCEDSTATUSCODES",
             "250 2.1.0 Ok",
             "250 2.1.5 Ok",
             "250 2.1.5 Ok",
             "354 End data with <CR><LF>.<CR><LF>"
           ]

    assert_received {:mail, {"a@x.test", %{body: :"8bitmime", size: 100}}}
    assert_received {:rcpt, "Postmaster"}
    assert Session.timeout(session) == 300_000

    {:continue, "", session} = input(session, "Subject: hi\r\n\r\n..dot\r\n")
    {:continue, out, _session} = input(session, ".\r\n")

    assert replies(out) == ["250 2.0.0 Ok"]
    assert_received {:chunk, "Subject: hi\r\n\r\n.dot\r\n"}

    assert_received {:data_end,
                     %{
                       sender: "a@x.test",
                       recipients: ["b@y.test", "Postmaster"],
                       params: %{body: :"8bitmime"}
                     }}
  end

  test "processes commands pipelined after the final dot" do
    session = in_transaction()
    {:continue, _, session} = input(session, "DATA\r\n")
    assert {:close, out, _} = input(session, "x\r\n.\r\nMAIL FROM:<a@x.test>\r\nQUIT\r\n")
    assert codes(out) == [250, 250, 221]
  end

  test "enforces command order" do
    {:continue, out, session} =
      input(started(), "MAIL FROM:<a@x.test>\r\nRCPT TO:<b@y.test>\r\nDATA\r\n")

    assert replies(out) == [
             "503 5.5.1 Send HELO/EHLO first",
             "503 5.5.1 Need MAIL command",
             "503 5.5.1 Need MAIL command"
           ]

    {:continue, out, _} =
      input(session, "EHLO c.test\r\nMAIL FROM:<a@x.test>\r\nMAIL FROM:<a@x.test>\r\nDATA\r\n")

    assert replies(out) |> tl() == [
             "250 2.1.0 Ok",
             "503 5.5.1 Nested MAIL command",
             "554 5.5.1 No valid recipients"
           ]
  end

  test "a rejected recipient is not added to the transaction" do
    reject = fn _recipient, state -> {:reply, Reply.new(550, "5.1.1", "No such user"), state} end
    session = started(rcpt: reject)

    {:continue, out, _} =
      input(session, "EHLO c.test\r\nMAIL FROM:<>\r\nRCPT TO:<b@y.test>\r\nDATA\r\n")

    assert codes(out) == [250, 250, 550, 554]
  end

  test "RSET and EHLO reset the transaction" do
    session = in_transaction()
    {:continue, out, session} = input(session, "RSET\r\nDATA\r\n")
    assert replies(out) == ["250 2.0.0 Ok", "503 5.5.1 Need MAIL command"]
    assert_received :rset

    {:continue, _, session} = input(session, "MAIL FROM:<a@x.test>\r\n")
    {:continue, out, _} = input(session, "EHLO c.test\r\nRCPT TO:<b@y.test>\r\n")
    assert codes(out) == [250, 503]
    assert_received :rset
  end

  test "validates MAIL parameters" do
    session = started()
    {:continue, _, session} = input(session, "EHLO c.test\r\n")

    for {params, reply} <- [
          {"SIZE=99999999999", "552 5.3.4 Message size exceeds fixed maximum message size"},
          {"SIZE=abc", "501 5.5.4 Invalid SIZE parameter"},
          {"SIZE", "501 5.5.4 Invalid SIZE parameter"},
          {"BODY=BINARYMIME", "501 5.5.4 Invalid BODY parameter"},
          {"SIZE=1 SIZE=2", "501 5.5.4 Duplicate parameter"},
          {"SMTPUTF8", "555 5.5.4 Unsupported parameter"}
        ] do
      {:continue, out, _} = input(session, "MAIL FROM:<a@x.test> #{params}\r\n")
      assert replies(out) == [reply], "for #{params}"
    end
  end

  test "parameters need EHLO, and RCPT takes none" do
    {:continue, out, session} =
      input(started(), "HELO c.test\r\nMAIL FROM:<a@x.test> SIZE=10\r\n")

    assert replies(out) |> List.last() == "555 5.5.4 Unsupported parameter"

    {:continue, out, _} =
      input(session, "MAIL FROM:<a@x.test>\r\nRCPT TO:<b@y.test> NOTIFY=NEVER\r\n")

    assert codes(out) == [250, 555]
  end

  test "limits recipients per transaction" do
    session = in_transaction([], max_recipients: 2)
    {:continue, out, _} = input(session, "RCPT TO:<c@y.test>\r\nRCPT TO:<d@y.test>\r\n")
    assert replies(out) == ["250 2.1.5 Ok", "452 4.5.3 Too many recipients"]
  end

  test "stops passing data once the message is too large, and replies at the end" do
    session = in_transaction([], max_message_size: 10)
    {:continue, _, session} = input(session, "DATA\r\n")
    {:continue, "", session} = input(session, "12345\r\n")
    {:continue, "", session} = input(session, "67890\r\nmore\r\n")
    {:continue, out, session} = input(session, ".\r\n")

    assert replies(out) == ["552 5.3.4 Message size exceeds fixed maximum message size"]
    assert_received {:chunk, "12345\r\n"}
    assert_received {:abort, :too_large}
    refute_received {:chunk, _}
    refute_received {:data_end, _}

    # The session goes on.
    assert {:continue, "250 2.0.0 Ok\r\n", _} = input(session, "NOOP\r\n")
  end

  test "a handler error during data is replied after the final dot" do
    fail = fn _chunk, state -> {:reply, Reply.new(451, "4.3.0", "Disk full"), state} end
    session = in_transaction(chunk: fail)
    {:continue, _, session} = input(session, "DATA\r\n")
    {:continue, "", session} = input(session, "a\r\n")
    {:continue, out, _} = input(session, "b\r\n.\r\n")

    assert replies(out) == ["451 4.3.0 Disk full"]
    refute_received {:data_end, _}
  end

  describe "bare line endings" do
    test "close the session in commands under :reject" do
      assert {:close, out, _} = input(started(), "EHLO c.test\n")
      assert replies(out) == ["521 5.5.2 mx.test Error: bare <LF> received"]

      assert {:close, out, _} = input(started(), "EHLO c\r.test\r\n")
      assert replies(out) == ["521 5.5.2 mx.test Error: bare <CR> received"]
    end

    test "close the session in data under :reject, aborting the message" do
      session = in_transaction()
      {:continue, _, session} = input(session, "DATA\r\n")
      assert {:close, out, _} = input(session, "a\n.\nRCPT TO:<x@evil.test>\r\n")
      assert replies(out) == ["521 5.5.2 mx.test Error: bare <LF> received"]
      assert_received {:abort, :bare_lf}
    end

    test "are converted under :normalize" do
      session = in_transaction([], bare_line_endings: :normalize)
      {:continue, out, session} = input(session, "NOOP\n")
      assert codes(out) == [250]

      {:continue, _, session} = input(session, "DATA\r\n")
      {:continue, out, _} = input(session, "a\n.\nb\r\n.\r\n")
      assert codes(out) == [250]
      assert_received {:chunk, "a\r\n\r\nb\r\n"}
    end
  end

  test "rejects long lines and discards the rest of them" do
    session = started([], max_line_length: 20)
    {:continue, out, session} = input(session, "NOOP " <> String.duplicate("x", 30))
    assert replies(out) == ["500 5.5.2 Line too long"]

    {:continue, "", session} = input(session, String.duplicate("y", 30))
    {:continue, out, _} = input(session, "zzz\r\nNOOP\r\n")
    assert replies(out) == ["250 2.0.0 Ok"]

    {:continue, out, _} =
      input(started([], max_line_length: 20), "NOOP #{String.duplicate("x", 20)}\r\n")

    assert replies(out) == ["500 5.5.2 Line too long"]
  end

  test "closes after too many errors" do
    session = started([], max_errors: 3)
    {:continue, _, session} = input(session, "FOO\r\nBAR\r\n")
    assert {:close, out, _} = input(session, "BAZ\r\nNOOP\r\n")

    assert replies(out) == [
             "500 5.5.2 Command not recognized",
             "421 4.7.0 mx.test Error: too many errors"
           ]
  end

  test "maps parse errors to replies" do
    session = started()
    {:continue, _, session} = input(session, "EHLO c.test\r\n")

    for {line, reply} <- [
          {"STARTTLS", "502 5.5.1 Command not implemented"},
          {"DATA x", "501 5.5.4 Syntax: DATA"},
          {"MAIL FROM:<a@@x>", "501 5.1.7 Bad sender address syntax"},
          {"RCPT TO:<a@@x>", "501 5.1.3 Bad recipient address syntax"},
          {"MAIL FROM:<a@x.test> =x", "501 5.5.4 Invalid parameter syntax"},
          {"NOOP \x01", "500 5.5.2 Invalid characters"},
          {"HELP", "214 2.0.0 Commands: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT VRFY HELP"}
        ] do
      {:continue, out, _} = input(session, line <> "\r\n")
      assert replies(out) == [reply], "for #{line}"
    end
  end

  test "closes on HTTP requests" do
    assert {:close, out, _} = input(started(), "POST / HTTP/1.1\r\nHost: x\r\n")
    assert replies(out) == ["421 4.7.0 mx.test Non-SMTP command, closing connection"]
  end

  test "VRFY answers 252 unless enabled" do
    {:continue, out, _} = input(started(), "VRFY alice\r\n")

    assert replies(out) == [
             "252 2.5.0 Cannot VRFY user, but will accept message and attempt delivery"
           ]

    refute_received {:vrfy, _}

    known = fn _argument, state -> {:reply, Reply.new(250, "2.1.5", "<alice@x.test>"), state} end
    {:continue, out, _} = input(started([vrfy: known], vrfy: true), "VRFY alice\r\n")
    assert replies(out) == ["250 2.1.5 <alice@x.test>"]
  end

  test "the handler can close the session" do
    close = fn _sender, state -> {:close, Reply.new(421, "4.7.0", "Slow down"), state} end
    session = started(mail: close)
    assert {:close, out, _} = input(session, "EHLO c.test\r\nMAIL FROM:<a@x.test>\r\nNOOP\r\n")
    assert codes(out) == [250, 421]
  end

  test "QUIT closes, and later input is ignored" do
    assert {:close, out, session} = input(started(), "QUIT\r\nNOOP\r\n")
    assert replies(out) == ["221 2.0.0 Bye"]
    assert {:close, [], _} = Session.handle_input(session, "NOOP\r\n")
  end

  test "times out with 421, aborting an open message" do
    session = in_transaction([], data_timeout: 1234)
    {:continue, _, session} = input(session, "DATA\r\n")
    assert Session.timeout(session) == 1234

    assert {:close, out, _} = Session.handle_timeout(session)
    assert IO.iodata_to_binary(out) == "421 4.4.2 mx.test Error: timeout exceeded\r\n"
    assert_received {:abort, :timeout}
  end

  test "terminate/2 aborts an open message and calls the handler" do
    session = in_transaction()
    {:continue, _, session} = input(session, "DATA\r\n")
    {:continue, _, session} = input(session, "partial")

    assert :ok = Session.terminate(session, :closed)
    assert_received {:abort, :closed}
    assert_received {:terminate, :closed}
  end

  test "emits a telemetry event per reply" do
    ref = make_ref()
    id = {__MODULE__, ref}

    :telemetry.attach(
      id,
      [:sovite, :smtp, :server, :command, :stop],
      &__MODULE__.forward_event/4,
      {self(), ref}
    )

    on_exit(fn -> :telemetry.detach(id) end)

    {:continue, _, _} = input(started(), "EHLO c.test\r\nRCPT TO:<b@y.test>\r\n")

    assert_received {^ref, %{duration: _},
                     %{
                       command: "EHLO",
                       argument: "c.test",
                       reply_code: 250,
                       session_id: "S1",
                       remote_ip: {192, 0, 2, 7}
                     }}

    assert_received {^ref, _,
                     %{
                       command: "RCPT",
                       argument: "b@y.test",
                       reply_code: 503,
                       reply: "503 5.5.1 Need MAIL command"
                     }}
  end
end
