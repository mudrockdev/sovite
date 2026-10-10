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
    def handle_greet(input, state), do: respond(:greet, input, state)
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
    def handle_tls(info, state) do
      send(state.test, {:tls, info})
      state
    end

    @impl true
    def auth_mechanisms(state), do: Map.get(state, :mechanisms, ["PLAIN", "LOGIN"])

    @impl true
    def handle_auth(mechanism, initial, state) do
      send(state.test, {:auth, mechanism, initial})
      if state[:auth], do: state.auth.({mechanism, initial}, state), else: {:ok, "user", state}
    end

    @impl true
    def handle_auth_response(response, state) do
      send(state.test, {:auth_response, response})
      state.auth_response.(response, state)
    end

    @impl true
    def handle_auth_abort(state) do
      send(state.test, :auth_abort)
      state
    end

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
          {"HELP",
           "214 2.0.0 Commands: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT VRFY HELP STARTTLS AUTH"}
        ] do
      {:continue, out, _} = input(session, line <> "\r\n")
      assert replies(out) == [reply], "for #{line}"
    end
  end

  test "closes on HTTP requests" do
    assert {:close, out, _} = input(started(), "POST / HTTP/1.1\r\nHost: x\r\n")
    assert replies(out) == ["421 4.7.0 mx.test Non-SMTP command, closing connection"]
  end

  test "closes on HTTP header lines" do
    assert {:close, out, _} = input(started(), "User-Agent: curl/8.0\r\n")
    assert replies(out) == ["421 4.7.0 mx.test Non-SMTP command, closing connection"]
  end

  describe "greeting delay" do
    defp paused(handler_opts \\ [], opts \\ []) do
      pause = fn _connection, state -> {:pause, 200, state} end
      assert {:continue, "", session} = start([init: pause] ++ handler_opts, opts)
      session
    end

    test "greets once the delay is over" do
      session = paused()
      assert Session.timeout(session) in 1..200
      refute_received {:greet, _}

      assert {:continue, out, session} = Session.handle_timeout(session)
      assert IO.iodata_to_binary(out) == "220 mx.test ESMTP\r\n"
      assert_received {:greet, ""}
      assert Session.timeout(session) == 300_000
    end

    test "passes early input to the handler, then processes it" do
      assert {:continue, out, _} = input(paused(), "EHLO c.test\r\nNOOP\r\n")
      assert_received {:greet, "EHLO c.test\r\nNOOP\r\n"}
      assert ["220 mx.test ESMTP", "250 ENHANCEDSTATUSCODES", "250 2.0.0 Ok"] = replies(out)
    end

    test "the handler can refuse an early talker" do
      refuse = fn _input, state -> {:close, Reply.new(554, "5.7.1", "Talked first"), state} end

      assert {:close, "554 5.7.1 Talked first\r\n", session} =
               input(paused(greet: refuse), "EHLO x\r\n")

      assert {:close, "", _} = input(session, "MAIL FROM:<a@x.test>\r\n")
    end
  end

  test "tarpits error replies from :tarpit_after on" do
    session = started([], tarpit_after: 2, tarpit_delay: 100)
    {:continue, _, session} = input(session, "FOO\r\n")
    assert {0, session} = Session.take_delay(session)

    {:continue, _, session} = input(session, "FOO\r\nNOOP\r\nFOO\r\n")
    assert {200, session} = Session.take_delay(session)
    assert {0, _} = Session.take_delay(session)

    # Off by default.
    {:continue, _, session} = input(started(), "FOO\r\nFOO\r\nFOO\r\nFOO\r\n")
    assert {0, _} = Session.take_delay(session)
  end

  describe "forbid_unauth_pipelining" do
    defp strict, do: started([], forbid_unauth_pipelining: true)

    test "allows pipelining where RFC 2920 does" do
      {:continue, out, session} =
        input(strict(), "EHLO c.test\r\n")

      {:continue, out2, session} =
        input(session, "MAIL FROM:<a@x.test>\r\nRCPT TO:<b@y.test>\r\nDATA\r\n")

      assert codes(out <> out2) == [250, 250, 250, 354]
      {:close, out, _} = input(session, "Subject: x\r\n\r\nhi\r\n.\r\nQUIT\r\n")
      assert codes(out) == [250, 221]
    end

    test "closes on input after a command that must end a group" do
      for line <- ["EHLO c.test", "NOOP", "VRFY alice"] do
        session =
          if line == "EHLO c.test",
            do: strict(),
            else: elem(input(strict(), "EHLO c.test\r\n"), 2)

        assert {:close, out, _} = input(session, line <> "\r\nMAIL FROM:<a@x.test>\r\n")
        assert replies(out) == ["554 5.5.0 Error: improper use of SMTP command pipelining"]
      end

      {:continue, _, session} =
        input(strict(), "EHLO c.test\r\n")

      {:continue, _, session} = input(session, "MAIL FROM:<a@x.test>\r\nRCPT TO:<b@y.test>\r\n")
      assert {:close, out, _} = input(session, "DATA\r\nSubject: x\r\n")
      assert replies(out) == ["554 5.5.0 Error: improper use of SMTP command pipelining"]
      refute_received {:data, _}
    end

    test "closes on any pipelining after HELO" do
      {:continue, _, session} = input(strict(), "HELO c.test\r\n")
      assert {:close, out, _} = input(session, "MAIL FROM:<a@x.test>\r\nRCPT TO:<b@y.test>\r\n")
      assert replies(out) == ["554 5.5.0 Error: improper use of SMTP command pipelining"]
    end

    test "is off by default" do
      {:continue, out, _} = input(started(), "EHLO c.test\r\nNOOP\r\n")
      assert codes(out) == [250, 250]
    end
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

  describe "STARTTLS" do
    @tls %{protocol: "TLSv1.3", cipher: "TLS_AES_128_GCM_SHA256", bits: 128, sni: nil}

    test "is only offered when enabled" do
      {:continue, out, _} = input(started(), "EHLO c.test\r\nSTARTTLS\r\n")
      refute out =~ "STARTTLS"
      assert replies(out) |> List.last() == "502 5.5.1 Command not implemented"
    end

    test "replies 220, drops pipelined input, and resets the session after the handshake" do
      session = in_transaction([], starttls: true)

      assert {:starttls, out, session} = input(session, "STARTTLS\r\nRCPT TO:<c@y.test>\r\n")
      assert replies(out) == ["220 2.0.0 Ready to start TLS"]
      assert_received :rset
      refute_received {:rcpt, "c@y.test"}

      assert {:continue, [], session} = Session.handle_tls(session, @tls)
      assert_received {:tls, @tls}
      assert Session.tls(session) == @tls

      {:continue, out, session} = input(session, "MAIL FROM:<a@x.test>\r\n")
      assert replies(out) == ["503 5.5.1 Send HELO/EHLO first"]

      {:continue, out, _} = input(session, "EHLO c.test\r\nSTARTTLS\r\n")
      refute out =~ "STARTTLS\r\n"
      assert replies(out) |> List.last() == "503 5.5.1 TLS already active"
    end

    test "takes no argument" do
      {:continue, out, _} = input(started([], starttls: true), "STARTTLS now\r\n")
      assert replies(out) == ["501 5.5.4 Syntax: STARTTLS"]
    end

    test "require_tls refuses mail commands until then" do
      session = started([], starttls: true, require_tls: true)

      {:continue, out, _} =
        input(session, "EHLO c.test\r\nMAIL FROM:<a@x.test>\r\nVRFY a\r\nNOOP\r\n")

      assert replies(out) |> tl() == [
               "530 5.7.0 Must issue a STARTTLS command first",
               "530 5.7.0 Must issue a STARTTLS command first",
               "250 2.0.0 Ok"
             ]
    end
  end

  describe "REQUIRETLS" do
    test "is offered and accepted only over TLS" do
      {:continue, out, _} =
        input(started([], requiretls: true), "EHLO c.test\r\nMAIL FROM:<a@x.test> REQUIRETLS\r\n")

      refute out =~ "REQUIRETLS"
      assert replies(out) |> List.last() == "555 5.5.4 Unsupported parameter"

      connection = %{remote_ip: {192, 0, 2, 7}, session_id: "S1", tls: %{protocol: "TLSv1.3"}}
      opts = [hostname: "mx.test", handler: {Handler, test: self()}, requiretls: true]
      {:continue, _, session} = Session.new(connection, opts)

      {:continue, out, session} =
        input(session, "EHLO c.test\r\nMAIL FROM:<a@x.test> requiretls\r\n")

      assert out =~ "250 REQUIRETLS\r\n"
      assert replies(out) |> List.last() =~ "250 "
      assert_received {:mail, {"a@x.test", %{requiretls: true}}}

      {:continue, out, _} = input(session, "RSET\r\nMAIL FROM:<a@x.test> REQUIRETLS=yes\r\n")
      assert replies(out) |> List.last() == "501 5.5.4 Invalid REQUIRETLS parameter"

      {:continue, _, _} = input(session, "RSET\r\nMAIL FROM:<a@x.test>\r\n")
      assert_received {:mail, {"a@x.test", %{requiretls: false}}}
    end
  end

  describe "AUTH" do
    defp auth_session(handler_opts \\ [], opts \\ []) do
      opts = Keyword.merge([auth: true, plaintext_auth: true], opts)
      {:continue, _, session} = input(started(handler_opts, opts), "EHLO c.test\r\n")
      session
    end

    test "is refused when not enabled, before EHLO, and without TLS" do
      {:continue, out, _} = input(started(), "EHLO c.test\r\nAUTH PLAIN\r\n")
      refute out =~ "AUTH"
      assert replies(out) |> List.last() == "503 5.5.1 Authentication not enabled"

      {:continue, out, _} = input(started([], auth: true), "HELO c.test\r\nAUTH PLAIN\r\n")
      assert replies(out) |> List.last() == "503 5.5.1 Send EHLO first"

      {:continue, out, _} = input(started([], auth: true), "EHLO c.test\r\nAUTH PLAIN\r\n")
      refute out =~ "250-AUTH"
      refute out =~ "250 AUTH"

      assert replies(out) |> List.last() ==
               "538 5.7.11 Encryption required for requested authentication mechanism"
    end

    test "is offered over TLS" do
      connection = %{remote_ip: {192, 0, 2, 7}, session_id: "S1", tls: %{protocol: "TLSv1.3"}}
      opts = [hostname: "mx.test", handler: {Handler, test: self()}, auth: true]
      {:continue, _, session} = Session.new(connection, opts)
      {:continue, out, _} = input(session, "EHLO c.test\r\nAUTH PLAIN AHUAcA==\r\n")
      assert out =~ "250 AUTH PLAIN LOGIN\r\n"
      assert replies(out) |> List.last() == "235 2.7.0 Authentication successful"
    end

    test "accepts an initial response" do
      session = auth_session()
      {:continue, out, session} = input(session, "AUTH plain AHUAcA==\r\n")
      assert replies(out) == ["235 2.7.0 Authentication successful"]
      assert_received {:auth, "PLAIN", <<0, "u", 0, "p">>}
      assert Session.identity(session) == "user"

      {:continue, out, _} = input(session, "EHLO c.test\r\nAUTH PLAIN\r\n")
      refute out =~ "AUTH PLAIN LOGIN"
      assert replies(out) |> List.last() == "503 5.5.1 Already authenticated"
    end

    test "passes = as an empty initial response" do
      {:continue, _, _} = input(auth_session(), "AUTH PLAIN =\r\n")
      assert_received {:auth, "PLAIN", ""}
    end

    test "runs a challenge-response exchange" do
      session =
        auth_session(
          auth: fn {"LOGIN", nil}, s -> {:challenge, "Username:", s} end,
          auth_response: fn
            "alice", s -> {:challenge, "Password:", s}
            "secret", s -> {:ok, "alice", s}
          end
        )

      {:continue, out, session} = input(session, "AUTH LOGIN\r\n")
      assert out == "334 VXNlcm5hbWU6\r\n"
      {:continue, out, session} = input(session, "YWxpY2U=\r\n")
      assert out == "334 UGFzc3dvcmQ6\r\n"
      {:continue, out, session} = input(session, "c2VjcmV0\r\n")
      assert replies(out) == ["235 2.7.0 Authentication successful"]
      assert Session.identity(session) == "alice"
    end

    test "sends an empty challenge as a bare 334" do
      session = auth_session(auth: fn _, s -> {:challenge, "", s} end)
      {:continue, out, _} = input(session, "AUTH PLAIN\r\n")
      assert out == "334 \r\n"
    end

    test "can be cancelled, and rejects undecodable responses" do
      session = auth_session(auth: fn _, s -> {:challenge, "", s} end)

      {:continue, _, session} = input(session, "AUTH PLAIN\r\n")
      {:continue, out, session} = input(session, "*\r\n")
      assert replies(out) == ["501 5.0.0 Authentication cancelled"]
      assert_received :auth_abort

      {:continue, _, session} = input(session, "AUTH PLAIN\r\n")
      {:continue, out, session} = input(session, "not base64!\r\n")
      assert replies(out) == ["501 5.5.2 Cannot decode response"]
      assert_received :auth_abort

      {:continue, out, _} = input(session, "AUTH PLAIN %%%\r\n")
      assert replies(out) == ["501 5.5.2 Cannot decode response"]
    end

    test "refuses unknown mechanisms and AUTH during a transaction" do
      {:continue, out, _} = input(auth_session(), "AUTH CRAM-MD5\r\n")
      assert replies(out) == ["504 5.5.4 Unrecognized authentication type"]

      session = in_transaction([], auth: true, plaintext_auth: true)
      {:continue, out, _} = input(session, "AUTH PLAIN AHUAcA==\r\n")
      assert replies(out) == ["503 5.5.1 MAIL transaction in progress"]
    end

    test "closes after too many failures" do
      failure = Reply.new(535, "5.7.8", "Authentication credentials invalid")
      session = auth_session(auth: fn _, s -> {:error, failure, s} end)

      {:continue, out, session} = input(session, "AUTH PLAIN AHUAcA==\r\nAUTH PLAIN AHUAcA==\r\n")
      assert codes(out) == [535, 535]

      {:close, out, _} = input(session, "AUTH PLAIN AHUAcA==\r\n")

      assert replies(out) == [
               "535 5.7.8 Authentication credentials invalid",
               "421 4.7.0 mx.test Error: too many failed authentications"
             ]
    end

    test "temporary failures do not count" do
      failure = Reply.new(454, "4.7.0", "Temporary authentication failure")
      session = auth_session([auth: fn _, s -> {:error, failure, s} end], max_errors: 100)
      {:continue, out, _} = input(session, String.duplicate("AUTH PLAIN =\r\n", 5))
      assert codes(out) == [454, 454, 454, 454, 454]
    end

    test "accepts long lines while AUTH is offered" do
      token = Base.encode64(String.duplicate("t", 9000))

      session =
        auth_session(
          auth: fn _, s -> {:challenge, "", s} end,
          auth_response: fn _, s -> {:ok, "u", s} end
        )

      {:continue, out, session} = input(session, "AUTH PLAIN " <> token <> "\r\n")
      assert out == "334 \r\n"
      {:continue, out, _} = input(session, token <> "\r\n")
      assert codes(out) == [235]
    end

    test "requires authentication before MAIL when configured" do
      session = auth_session([], auth_required: true)
      {:continue, out, session} = input(session, "MAIL FROM:<a@x.test>\r\n")
      assert replies(out) == ["530 5.7.0 Authentication required"]

      {:continue, out, _} =
        input(session, "AUTH PLAIN AHUAcA==\r\nMAIL FROM:<a@x.test> AUTH=<>\r\n")

      assert codes(out) == [235, 250]
    end

    test "the AUTH= MAIL parameter needs AUTH" do
      {:continue, out, _} = input(started(), "EHLO c.test\r\nMAIL FROM:<a@x.test> AUTH=<>\r\n")
      assert replies(out) |> List.last() == "555 5.5.4 Unsupported parameter"
    end

    test "telemetry shows the mechanism, never the response" do
      ref = make_ref()
      id = {__MODULE__, ref}

      :telemetry.attach(
        id,
        [:sovite, :smtp, :server, :command, :stop],
        &__MODULE__.forward_event/4,
        {self(), ref}
      )

      on_exit(fn -> :telemetry.detach(id) end)

      {:continue, _, _} = input(auth_session(), "AUTH PLAIN AHUAcA==\r\n")

      assert_received {^ref, _,
                       %{session_id: "S1", command: "AUTH", argument: "PLAIN", reply_code: 235}}
    end
  end

  describe "LMTP" do
    defp lmtp(handler_opts \\ [], opts \\ []) do
      {:continue, "220 mx.test LMTP\r\n", session} = start(handler_opts, [lmtp: true] ++ opts)
      session
    end

    test "greets with LHLO and refuses EHLO and HELO" do
      session = lmtp()
      {:continue, out, session} = input(session, "EHLO c.test\r\nHELO c.test\r\n")
      assert codes(out) == [500, 500]

      {:continue, out, session} = input(session, "MAIL FROM:<a@x.test>\r\n")
      assert out == "503 5.5.1 Send LHLO first\r\n"

      {:continue, out, _} = input(session, "LHLO c.test\r\n")
      assert out =~ "250-mx.test\r\n250-PIPELINING"
      assert_received {:helo, {:lhlo, "c.test"}}
    end

    test "SMTP does not know LHLO" do
      {:continue, out, _} = input(started(), "LHLO c.test\r\n")
      assert out == "500 5.5.1 Command not recognized\r\n"
    end

    test "answers the data once per accepted recipient" do
      rcpt = fn
        "bad@y.test", state -> {:reply, Reply.new(550, "5.1.1", "No such user"), state}
        _, state -> {:ok, state}
      end

      session = lmtp(rcpt: rcpt)

      {:continue, out, session} =
        input(
          session,
          "LHLO c.test\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@y.test>\r\n" <>
            "RCPT TO:<bad@y.test>\r\nRCPT TO:<c@y.test>\r\nDATA\r\n"
        )

      assert codes(out) == [250, 250, 250, 550, 250, 354]

      {:continue, out, _} = input(session, "Subject: x\r\n\r\nbody\r\n.\r\n")
      assert out == "250 2.0.0 Ok\r\n250 2.0.0 Ok\r\n"
      assert_received {:data_end, %{recipients: ["b@y.test", "c@y.test"]}}
    end

    test "repeats a rejection for every recipient" do
      reject = fn _transaction, state -> {:reply, Reply.new(451, "4.3.0", "Try later"), state} end
      session = lmtp(data_end: reject)

      {:continue, _out, session} =
        input(
          session,
          "LHLO c.test\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@y.test>\r\n" <>
            "RCPT TO:<c@y.test>\r\nDATA\r\n"
        )

      {:continue, out, _} = input(session, "body\r\n.\r\n")
      assert out == "451 4.3.0 Try later\r\n451 4.3.0 Try later\r\n"
    end

    test "a message that is too large fails for every recipient" do
      session = lmtp([], max_message_size: 10)

      {:continue, _out, session} =
        input(
          session,
          "LHLO c.test\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@y.test>\r\n" <>
            "RCPT TO:<c@y.test>\r\nDATA\r\n"
        )

      {:continue, out, _} = input(session, String.duplicate("x", 100) <> "\r\n.\r\n")
      assert codes(out) == [552, 552]
    end
  end

  describe "XCLIENT and XFORWARD" do
    defp proxied(handler_opts \\ [], opts \\ []) do
      opts = Keyword.merge([xclient_networks: [{{192, 0, 2, 0}, 24}]], opts)
      session = started(handler_opts, opts)
      {:continue, out, session} = input(session, "EHLO proxy.test\r\n")

      assert out =~
               "250 XCLIENT NAME REVERSE_NAME ADDR PORT PROTO HELO LOGIN DESTADDR DESTPORT\r\n"

      assert_received {:init, _}
      session
    end

    test "are only offered to and accepted from the configured networks" do
      session = started()
      {:continue, out, session} = input(session, "EHLO c.test\r\n")
      refute out =~ "XCLIENT"
      refute out =~ "XFORWARD"

      {:continue, out, _} =
        input(session, "XCLIENT ADDR=198.51.100.1\r\nXFORWARD NAME=a.test\r\n")

      assert replies(out) ==
               ["550 5.7.0 Error: insufficient authorization"]
               |> List.duplicate(2)
               |> List.flatten()
    end

    test "XCLIENT starts over with the client the proxy names" do
      session = proxied()

      {:continue, out, session} =
        input(
          session,
          "XCLIENT ADDR=IPV6:2001:db8::1 PORT=4711 NAME=client.example DESTADDR=203.0.113.5 " <>
            "DESTPORT=25 LOGIN=alice HELO=client.example PROTO=ESMTP\r\n"
        )

      assert out == "220 mx.test ESMTP\r\n"
      assert_received {:terminate, :xclient}

      assert_received {:init,
                       %{
                         remote_ip: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1},
                         remote_port: 4711,
                         client_name: "client.example",
                         local_ip: {203, 0, 113, 5},
                         local_port: 25,
                         login: "alice",
                         session_id: "S1"
                       }}

      assert_received {:helo, {:ehlo, "client.example"}}
      assert Session.identity(session) == "alice"

      # HELO was given: MAIL may follow at once, and the proxy may send
      # XCLIENT again.
      {:continue, out, session} = input(session, "MAIL FROM:<a@x.test>\r\n")
      assert codes(out) == [250]
      {:continue, out, session} = input(session, "XCLIENT ADDR=192.0.2.9\r\n")
      assert replies(out) == ["503 5.5.1 Error: MAIL transaction in progress"]
      {:continue, _out, session} = input(session, "RSET\r\n")
      {:continue, out, _} = input(session, "XCLIENT ADDR=192.0.2.9 LOGIN=[UNAVAILABLE]\r\n")
      assert out == "220 mx.test ESMTP\r\n"
      assert_received {:init, %{remote_ip: {192, 0, 2, 9}, login: nil}}
    end

    test "XCLIENT without HELO needs a new EHLO, and a refused HELO is forgotten" do
      session =
        proxied(
          helo: fn {_kind, name}, state ->
            if name == "bad.example",
              do: {:reply, Reply.new(550, "5.7.1", "No"), state},
              else: {:ok, state}
          end
        )

      {:continue, "220 mx.test ESMTP\r\n", session} = input(session, "XCLIENT ADDR=192.0.2.8\r\n")
      {:continue, out, session} = input(session, "MAIL FROM:<a@x.test>\r\n")
      assert replies(out) == ["503 5.5.1 Send HELO/EHLO first"]

      {:continue, _out, session} = input(session, "XCLIENT HELO=bad.example PROTO=SMTP\r\n")
      assert_received {:helo, {:helo, "bad.example"}}
      {:continue, out, _} = input(session, "MAIL FROM:<a@x.test>\r\n")
      assert replies(out) == ["503 5.5.1 Send HELO/EHLO first"]
    end

    test "XCLIENT refuses bad attributes" do
      session = proxied()

      for {line, name} <- [
            {"XCLIENT FOO=1", "FOO"},
            {"XCLIENT ADDR=999.1.1.1", "ADDR"},
            {"XCLIENT PORT=70000", "PORT"},
            {"XCLIENT NAME=-bad-", "NAME"},
            {"XCLIENT HELO=a..b", "HELO"},
            {"XCLIENT PROTO=UUCP", "PROTO"}
          ] do
        {:continue, out, _} = input(session, line <> "\r\n")
        assert replies(out) == ["501 5.5.4 Bad XCLIENT attribute: #{name}"]
      end

      {:continue, out, _} = input(session, "XCLIENT ADDR=[TEMPUNAVAIL] PORT=[UNAVAILABLE]\r\n")
      assert out == "220 mx.test ESMTP\r\n"
      assert_received {:init, %{remote_ip: {192, 0, 2, 7}} = connection}
      refute Map.has_key?(connection, :remote_port)
    end

    test "a handler that refuses the new client closes the session" do
      init = fn connection, state ->
        if connection.remote_ip == {198, 51, 100, 1},
          do: {:close, Reply.new(554, "5.7.1", "Go away"), state},
          else: {:ok, state}
      end

      session = proxied(init: init)
      assert {:close, out, _} = input(session, "XCLIENT ADDR=198.51.100.1\r\n")
      assert out == "554 5.7.1 Go away\r\n"
    end

    test "a greeting delay is skipped after XCLIENT" do
      init = fn connection, state ->
        if connection.remote_ip == {198, 51, 100, 1},
          do: {:pause, 60_000, state},
          else: {:ok, state}
      end

      session = proxied(init: init)

      assert {:continue, "220 mx.test ESMTP\r\n", _} =
               input(session, "XCLIENT ADDR=198.51.100.1\r\n")
    end

    test "XFORWARD attributes go with the next transaction only" do
      session = started([], xforward_networks: [{{192, 0, 2, 0}, 24}])
      {:continue, out, session} = input(session, "EHLO filter.test\r\n")
      assert out =~ "250 XFORWARD NAME ADDR PORT PROTO HELO IDENT SOURCE\r\n"

      {:continue, out, session} =
        input(
          session,
          "XFORWARD NAME=client.example ADDR=IPV6:2001:db8::2 PORT=1234\r\n" <>
            "XFORWARD PROTO=ESMTP HELO=client.example IDENT=abc SOURCE=remote\r\n" <>
            "MAIL FROM:<a@x.test>\r\nRCPT TO:<b@y.test>\r\nDATA\r\n"
        )

      assert codes(out) == [250, 250, 250, 250, 354]
      {:continue, _out, session} = input(session, "x\r\n.\r\n")

      assert_received {:data_end,
                       %{
                         xforward: %{
                           name: "client.example",
                           addr: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 2},
                           port: 1234,
                           proto: "ESMTP",
                           helo: "client.example",
                           ident: "abc",
                           source: "REMOTE"
                         }
                       }}

      {:continue, _out, session} =
        input(session, "MAIL FROM:<a@x.test>\r\nRCPT TO:<b@y.test>\r\nDATA\r\n")

      {:continue, _out, session} = input(session, "x\r\n.\r\n")
      assert_received {:data_end, %{xforward: xforward}} when xforward == %{}

      {:continue, out, session} =
        input(session, "MAIL FROM:<a@x.test>\r\nXFORWARD NAME=a.test\r\n")

      assert replies(out) == ["250 2.1.0 Ok", "503 5.5.1 Error: MAIL transaction in progress"]
      {:continue, _out, session} = input(session, "RSET\r\n")

      for {line, name} <- [
            {"XFORWARD ADDR=x", "ADDR"},
            {"XFORWARD PORT=-1", "PORT"},
            {"XFORWARD SOURCE=MARS", "SOURCE"},
            {"XFORWARD LOGIN=alice", "LOGIN"}
          ] do
        {:continue, out, _} = input(session, line <> "\r\n")
        assert replies(out) == ["501 5.5.4 Bad XFORWARD attribute: #{name}"]
      end

      {:continue, out, _} = input(session, "XFORWARD ADDR=[UNAVAILABLE]\r\n")
      assert codes(out) == [250]
    end
  end
end
