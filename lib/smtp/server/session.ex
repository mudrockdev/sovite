defmodule Sovite.SMTP.Server.Session do
  @moduledoc """
  The SMTP server protocol as a state machine, without I/O.

  Feed it the bytes read from the client; it returns the bytes to send
  back and whether to close the connection. Policy and storage are left to
  a `Sovite.SMTP.Server.Handler`. `Sovite.SMTP.Server.Connection` runs a
  session on a socket.

      {:continue, greeting, session} = Session.new(connection, hostname: "mx.example.com", handler: {MyHandler, []})
      {:continue, replies, session} = Session.handle_input(session, "EHLO client.example\\r\\n")

  Pipelined commands (RFC 2920) need no special handling: all complete
  lines in the input are processed, and their replies returned together.

  ## STARTTLS

  With `starttls: true`, `STARTTLS` (RFC 3207) is offered until the
  connection is encrypted. On `STARTTLS` the session replies `220` and
  returns `{:starttls, replies, session}`: send the replies, run the TLS
  handshake, then call `handle_tls/2`. Input received after the
  `STARTTLS` command and before the handshake is discarded, so a
  man-in-the-middle cannot inject commands into the encrypted session.
  After the handshake the session starts over, as the RFC requires: the
  client must send `EHLO` again.

  ## LMTP

  With `lmtp: true` the session speaks LMTP (RFC 2033): the client
  greets with `LHLO` (`EHLO` and `HELO` are refused), and the end of the
  data gets one reply per accepted recipient, all with the handler's
  reply. The handler sees `LHLO` as `handle_helo(:lhlo, name, state)`.
  Without it, `LHLO` is an unknown command.

  ## AUTH

  With `auth: true`, `AUTH` (RFC 4954) is offered with the mechanisms the
  handler's `auth_mechanisms/1` returns, but only over TLS unless
  `plaintext_auth: true`. The handler runs the SASL exchange, see
  `Sovite.SMTP.Server.Handler`. Lines of up to 12288 bytes are accepted
  while `AUTH` is offered, for large initial responses and tokens.

  ## Greeting delay

  A handler's `init/2` may return `{:pause, milliseconds, state}` to hold
  the greeting back, as postscreen does: clients must wait for it (RFC
  5321 §3.1), so one that talks first is most likely a spam bot. The
  session then returns no output, and `timeout/1` is the time left. When
  it runs out, or as soon as the client sends anything, the handler's
  `handle_greet/2` gets the early input (`""` if none) and decides
  whether to greet the client. Early input of a client let in is then
  processed as commands.

  ## Tarpit

  With `:tarpit_delay`, every error reply from the `:tarpit_after`th on
  adds that many milliseconds to the session's delay: the caller waits
  that long before sending the output (see `take_delay/1`). This slows
  down dictionary attacks and other clients that keep getting errors.

  ## Pipelining

  With `forbid_unauth_pipelining: true`, a client that sends more input
  after a command that must end a group (RFC 2920 §3.1: `EHLO`, `DATA`,
  `NOOP`, ...), or after any command before `PIPELINING` was offered,
  gets `554 5.5.0` and is disconnected: it did not wait for the reply.

  ## XCLIENT and XFORWARD

  Clients in `:xclient_networks` may use Postfix's `XCLIENT` command, and
  clients in `:xforward_networks` its `XFORWARD` command (see
  https://www.postfix.org/XCLIENT_README.html and XFORWARD_README.html).
  Both are offered in the `EHLO` reply only to those clients.

  `XCLIENT` is for proxies such as nginx: it replaces what the session
  knows about the client (`ADDR`, `PORT`, `NAME`, `REVERSE_NAME`,
  `DESTADDR`, `DESTPORT`, `HELO`, `PROTO`, `LOGIN`), as if the client
  had connected itself. The handler's state is ended with `terminate/2`
  and started again with `init/2` and the new connection map, which has
  `:client_name`, `:reverse_name`, and `:login` when given; `HELO` is
  passed to `handle_helo/3`, and `LOGIN` counts as authenticated. The
  reply is a new greeting. The client that may use `XCLIENT` is decided
  at connect, so it may send it again.

  `XFORWARD` is for content filters that send mail back: the attributes
  (`NAME`, `ADDR`, `PORT`, `PROTO`, `HELO`, `IDENT`, `SOURCE`) describe
  the original client of the next transaction only, and reach the
  handler in the transaction's `:xforward` map. They change nothing
  else.

  ## SMTPUTF8

  With `smtputf8: true`, `SMTPUTF8` (RFC 6531) is offered in the `EHLO`
  and `LHLO` replies. A `MAIL FROM` with the `SMTPUTF8` parameter sets
  `smtputf8: true` in the mail parameters, and lets the sender and the
  recipients of that transaction be internationalized addresses, with
  UTF-8 local parts and U-label domains (`Sovite.Validators`). Without
  it, such an address gets `553 5.6.7`. Domains in U-labels reach the
  handler, and the transaction, converted to A-labels
  (`Sovite.Validators.ascii_domain/1`), so every domain has one form.
  The message may then have UTF-8 header fields (RFC 6532).

  ## CHUNKING and BINARYMIME

  With `chunking: true`, `CHUNKING` (RFC 3030) is offered: the client
  may send the message in `BDAT` chunks instead of with `DATA`. Each
  chunk is passed to the handler as it arrives, as `DATA` content is,
  but there is no dot-stuffing; bare line endings get the
  `:bare_line_endings` policy all the same. The first chunk calls
  `handle_data/2`, every chunk but the last is answered with `250`, and
  `BDAT ... LAST` ends the message like the final dot. A chunk is always
  read to its end, also when it is refused, so its content can never be
  taken for commands.

  With `binarymime: true` as well, `BINARYMIME` is offered: `MAIL FROM`
  with `BODY=BINARYMIME` sets `body: :binarymime`, and the message must
  be sent with `BDAT`. Its content is binary: it is passed on unchecked.

  ## DSN

  With `dsn: true`, `DSN` (RFC 3461) is offered. `MAIL FROM` may then
  have `RET` and `ENVID` (in the mail parameters), and `RCPT TO` may
  have `NOTIFY` and `ORCPT` (in the recipient parameters passed to
  `handle_rcpt/3`), see `Sovite.SMTP.DSNParams`. Acting on them is up to
  the handler.

  ## ETRN

  With `etrn: true` and a handler with `handle_etrn/2`, `ETRN` (RFC
  1985) is offered: the client asks for the mail queued for its domain
  to be sent now. Not allowed in a mail transaction.

  ## MT-PRIORITY, FUTURERELEASE, DELIVERBY, and RRVS

  These are offered on request, and their parameters (see
  `Sovite.SMTP.Params`) reach the handler checked but not acted on:

    * `mt_priority: true` - `MT-PRIORITY` (RFC 6710): `MAIL FROM` may
      have `MT-PRIORITY=-9..9` (`priority` in the mail parameters). The
      handler must not let untrusted clients raise it.
    * `future_release: seconds` - `FUTURERELEASE` (RFC 4865), with
      `HOLDFOR` and `HOLDUNTIL` up to that many seconds ahead (`hold`).
    * `deliverby: true` - `DELIVERBY` (RFC 2852): `BY=seconds;R|N[T]`
      (`by`). With a hold as well, the message must be due after its
      release.
    * `rrvs: true` - `RRVS` (RFC 7293): `RCPT TO` may have
      `RRVS=time[;R|;C]` (`rrvs` in the recipient parameters).

  ## Options

    * `:hostname` - name in the greeting and `EHLO` reply. Required.
    * `:handler` - `{module, opts}`. Required.
    * `:max_message_size` - bytes, advertised with `SIZE` and enforced
      while streaming. Defaults to 10 MiB.
    * `:max_recipients` - per transaction. Defaults to 100.
    * `:max_errors` - error replies before the session is closed.
      Defaults to 10.
    * `:max_line_length` - command line length, including CRLF. Defaults
      to 2048.
    * `:command_timeout` / `:data_timeout` - milliseconds to wait for
      input. Default to 5 minutes (RFC 5321 §4.5.3.2.7).
    * `:vrfy` - answer `VRFY` with the handler. Defaults to `false`.
    * `:bare_line_endings` - `:reject` (default) or `:normalize`, see
      `Sovite.SMTP.DataDecoder`. Under `:reject`, a bare LF or CR in a
      command or in the data closes the session with `521`.
    * `:starttls` - offer `STARTTLS`. Defaults to `false`.
    * `:require_tls` - refuse `MAIL`, `RCPT`, `DATA`, `VRFY`, and `AUTH`
      with `530 5.7.0` until the connection is encrypted. Defaults to
      `false`.
    * `:auth` - offer `AUTH`. Defaults to `false`.
    * `:auth_required` - refuse `MAIL` with `530 5.7.0` until the client
      has authenticated. Defaults to `false`.
    * `:plaintext_auth` - offer `AUTH` on unencrypted connections too.
      Defaults to `false`: passwords are never sent in the clear.
    * `:max_auth_failures` - failed `AUTH` attempts before the session is
      closed. Defaults to 3.
    * `:lmtp` - speak LMTP instead of SMTP. Defaults to `false`.
    * `:requiretls` - offer `REQUIRETLS` (RFC 8689) on encrypted
      connections. A `MAIL FROM` with the `REQUIRETLS` parameter sets
      `requiretls: true` in the mail parameters: the handler must then
      only relay the message over TLS that is verified with DANE or
      MTA-STS. Defaults to `false`.
    * `:smtputf8` - offer `SMTPUTF8`, see "SMTPUTF8". Defaults to
      `false`.
    * `:chunking` / `:binarymime` - offer `CHUNKING` and `BINARYMIME`,
      see "CHUNKING and BINARYMIME". Default to `false`.
    * `:dsn` - offer `DSN`, see "DSN". Defaults to `false`.
    * `:etrn` - offer `ETRN`, see "ETRN". Defaults to `false`.
    * `:mt_priority`, `:future_release`, `:deliverby`, `:rrvs` - see
      "MT-PRIORITY, FUTURERELEASE, DELIVERBY, and RRVS". Default to
      `false` (`nil` for `:future_release`).
    * `:tarpit_after` - errors before the tarpit starts. Defaults to 3.
    * `:tarpit_delay` - milliseconds per error reply after that. Defaults
      to 0: no tarpit.
    * `:forbid_unauth_pipelining` - see "Pipelining". Defaults to `false`.
    * `:xclient_networks` / `:xforward_networks` - `Sovite.Net` networks
      whose clients may use `XCLIENT` / `XFORWARD`. Default to `[]`.

  The connection map may carry `:tls` (a `Sovite.TLS.info()`) when it is
  encrypted from the start (implicit TLS, RFC 8314).

  ## Telemetry

  `[:sovite, :smtp, :server, :command, :stop]` for every reply, with
  `%{duration}` and `%{session_id, remote_ip, command, argument,
  reply_code, reply}`. `command` is the verb (`"MAIL"`), `"UNKNOWN"`, or
  `"END-OF-MESSAGE"` for the final dot or `BDAT ... LAST`. `argument` is
  only set for `EHLO`, `HELO`, `LHLO`, `MAIL`, `RCPT`, `VRFY`, and
  `ETRN`, and is network input. For `AUTH` it
  is the mechanism; SASL responses are never included.
  """

  alias Sovite.Net
  alias Sovite.SMTP.{Command, DataDecoder, DSNParams, Params, Reply}
  alias Sovite.Validators

  @typedoc "Who is connected. Passed to the handler's `init/2`."
  @type connection :: %{
          required(:session_id) => String.t(),
          required(:remote_ip) => :inet.ip_address(),
          optional(:remote_port) => :inet.port_number(),
          optional(:local_ip) => :inet.ip_address(),
          optional(:local_port) => :inet.port_number(),
          optional(:listener) => String.t(),
          optional(:tls) => Sovite.TLS.info() | nil,
          optional(:client_name) => String.t() | nil,
          optional(:reverse_name) => String.t() | nil,
          optional(:login) => String.t() | nil
        }

  @typedoc """
  `MAIL FROM` parameters. Those not given are `nil` (`false` for
  `requiretls` and `smtputf8`).
  """
  @type mail_params :: %{
          size: non_neg_integer() | nil,
          body: :"7bit" | :"8bitmime" | :binarymime | nil,
          requiretls: boolean(),
          smtputf8: boolean(),
          ret: DSNParams.ret() | nil,
          envid: String.t() | nil,
          priority: -9..9 | nil,
          hold: Params.hold() | nil,
          by: Params.by() | nil
        }

  @typedoc "`RCPT TO` parameters (DSN and RRVS), `nil` when not given."
  @type rcpt_params :: %{
          notify: DSNParams.notify() | nil,
          orcpt: DSNParams.orcpt() | nil,
          rrvs: Params.rrvs() | nil
        }

  @typedoc """
  What `XFORWARD` said about the original client, see "XCLIENT and
  XFORWARD". `:addr` is an IP address, `:port` an integer, `:source`
  `"LOCAL"` or `"REMOTE"`; the others are strings.
  """
  @type xforward :: %{
          optional(:name) => String.t() | nil,
          optional(:addr) => :inet.ip_address() | nil,
          optional(:port) => :inet.port_number() | nil,
          optional(:proto) => String.t() | nil,
          optional(:helo) => String.t() | nil,
          optional(:ident) => String.t() | nil,
          optional(:source) => String.t() | nil
        }

  @typedoc "The current mail transaction. Recipients are in the order given."
  @type transaction :: %{
          sender: String.t(),
          params: mail_params(),
          recipients: [String.t()],
          xforward: xforward()
        }

  @type result :: {:continue | :close | :starttls, iodata(), t()}

  # RFC 4954 §4: AUTH lines of at least 12288 octets must be accepted.
  @auth_line_length 12_288 + 2

  @defaults [
    max_message_size: 10 * 1024 * 1024,
    max_recipients: 100,
    max_errors: 10,
    max_line_length: 2048,
    command_timeout: 300_000,
    data_timeout: 300_000,
    vrfy: false,
    bare_line_endings: :reject,
    starttls: false,
    require_tls: false,
    auth: false,
    auth_required: false,
    plaintext_auth: false,
    max_auth_failures: 3,
    lmtp: false,
    requiretls: false,
    smtputf8: false,
    chunking: false,
    binarymime: false,
    dsn: false,
    etrn: false,
    mt_priority: false,
    future_release: nil,
    deliverby: false,
    rrvs: false,
    tarpit_after: 3,
    tarpit_delay: 0,
    forbid_unauth_pipelining: false,
    xclient_networks: [],
    xforward_networks: []
  ]

  # RFC 2920 §3.1: these may only be the last command of a group. QUIT
  # closes anyway, and input after STARTTLS is dropped.
  @group_end ~w(EHLO HELO LHLO DATA VRFY NOOP AUTH XCLIENT)

  @no_mail_params %{
    size: nil,
    body: nil,
    requiretls: false,
    smtputf8: false,
    ret: nil,
    envid: nil,
    priority: nil,
    hold: nil,
    by: nil
  }

  @no_rcpt_params %{notify: nil, orcpt: nil, rrvs: nil}

  @xclient_attributes ~w(NAME REVERSE_NAME ADDR PORT PROTO HELO LOGIN DESTADDR DESTPORT)
  @xforward_attributes ~w(NAME ADDR PORT PROTO HELO IDENT SOURCE)

  defstruct [
    :connection,
    :hostname,
    :handler,
    :handler_state,
    :handler_opts,
    :opts,
    :helo,
    :transaction,
    :data,
    :identity,
    phase: :command,
    esmtp: false,
    buffer: <<>>,
    discarding: false,
    errors: 0,
    auth_failures: 0,
    delay: 0,
    xclient: false,
    xforward: false,
    xforward_attributes: %{}
  ]

  @opaque t :: %__MODULE__{}

  @doc """
  Starts a session for `connection` and returns the greeting. A
  `:session_id` is generated if missing.
  """
  @spec new(map(), keyword()) :: result()
  def new(connection, opts) do
    opts = Keyword.validate!(opts, [:hostname, :handler] ++ @defaults)
    {module, handler_opts} = Keyword.fetch!(opts, :handler)

    connection =
      Map.put_new_lazy(connection, :session_id, fn ->
        8 |> :crypto.strong_rand_bytes() |> Base.encode32(padding: false, case: :lower)
      end)

    session = %__MODULE__{
      connection: connection,
      hostname: Keyword.fetch!(opts, :hostname),
      handler: module,
      handler_opts: handler_opts,
      opts: Map.new(opts),
      xclient: Net.in_networks?(connection.remote_ip, opts[:xclient_networks]),
      xforward: Net.in_networks?(connection.remote_ip, opts[:xforward_networks])
    }

    case module.init(connection, handler_opts) do
      {:ok, state} ->
        greet(%{session | handler_state: state})

      {:pause, delay, state} ->
        deadline = System.monotonic_time(:millisecond) + delay
        {:continue, [], %{session | handler_state: state, phase: {:greeting, deadline}}}

      {:close, reply, state} ->
        {:close, Reply.encode(reply), %{session | handler_state: state, phase: :closed}}
    end
  end

  # Input that arrived before the greeting is passed to the handler, then
  # processed as commands if the handler lets the client in.
  defp greet(session) do
    result =
      if function_exported?(session.handler, :handle_greet, 2),
        do: session.handler.handle_greet(session.buffer, session.handler_state),
        else: {:ok, session.handler_state}

    case result do
      {:ok, state} ->
        greeting = greeting(session)
        session = %{session | handler_state: state, phase: :command}

        if session.buffer == "",
          do: {:continue, Reply.encode(greeting), session},
          else: process(session, [Reply.encode(greeting)])

      {:close, reply, state} ->
        {:close, Reply.encode(reply), %{session | handler_state: state, phase: :closed}}
    end
  end

  defp greeting(session) do
    protocol = if session.opts.lmtp, do: "LMTP", else: "ESMTP"
    Reply.new(220, "#{session.hostname} #{protocol}")
  end

  @doc "Returns the session ID."
  @spec session_id(t()) :: String.t()
  def session_id(%__MODULE__{connection: connection}), do: connection.session_id

  @doc "Returns the TLS details if the connection is encrypted, else `nil`."
  @spec tls(t()) :: Sovite.TLS.info() | nil
  def tls(%__MODULE__{connection: connection}), do: Map.get(connection, :tls)

  @doc "Returns the authenticated identity, or `nil`."
  @spec identity(t()) :: String.t() | nil
  def identity(%__MODULE__{identity: identity}), do: identity

  @doc """
  The TLS handshake after `STARTTLS` succeeded. Resets the session to
  its initial state, as RFC 3207 §4.2 requires, and tells the handler.
  """
  @spec handle_tls(t(), Sovite.TLS.info()) :: result()
  def handle_tls(%__MODULE__{phase: :starttls} = session, info) do
    session = reset_transaction(session)

    state =
      if function_exported?(session.handler, :handle_tls, 2),
        do: session.handler.handle_tls(info, session.handler_state),
        else: session.handler_state

    session = %{
      session
      | connection: Map.put(session.connection, :tls, info),
        handler_state: state,
        phase: :command,
        helo: nil,
        esmtp: false,
        buffer: <<>>
    }

    {:continue, [], session}
  end

  @doc "Milliseconds to wait for more input before calling `handle_timeout/1`."
  @spec timeout(t()) :: timeout()
  def timeout(%__MODULE__{phase: :data, opts: opts}), do: opts.data_timeout
  def timeout(%__MODULE__{phase: {:bdat, _chunk}, opts: opts}), do: opts.data_timeout

  def timeout(%__MODULE__{phase: {:greeting, deadline}}),
    do: max(deadline - System.monotonic_time(:millisecond), 0)

  def timeout(%__MODULE__{opts: opts}), do: opts.command_timeout

  @doc """
  Returns the milliseconds to wait before sending the output of the last
  call (see "Tarpit" above), and resets it.
  """
  @spec take_delay(t()) :: {non_neg_integer(), t()}
  def take_delay(%__MODULE__{delay: delay} = session), do: {delay, %{session | delay: 0}}

  @doc "Processes bytes received from the client."
  @spec handle_input(t(), binary()) :: result()
  def handle_input(%__MODULE__{phase: :closed} = session, _bytes), do: {:close, [], session}

  # The client did not wait for the greeting.
  def handle_input(%__MODULE__{phase: {:greeting, _}} = session, bytes),
    do: greet(%{session | buffer: session.buffer <> bytes})

  def handle_input(%__MODULE__{} = session, bytes) do
    process(%{session | buffer: session.buffer <> bytes}, [])
  end

  @doc "The client sent nothing for `timeout/1` milliseconds."
  @spec handle_timeout(t()) :: result()
  def handle_timeout(%__MODULE__{phase: {:greeting, _}} = session), do: greet(session)

  def handle_timeout(%__MODULE__{} = session) do
    session = session |> abort_data(:timeout) |> abort_auth()
    reply = Reply.new(421, "4.4.2", "#{session.hostname} Error: timeout exceeded")
    {:close, Reply.encode(reply), %{session | phase: :closed}}
  end

  @doc """
  Ends the session, for example when the connection closed or the server
  shuts down. Calls the handler's `terminate/2`.
  """
  @spec terminate(t(), term()) :: :ok
  def terminate(%__MODULE__{} = session, reason) do
    session = abort_data(session, :closed)

    if function_exported?(session.handler, :terminate, 2),
      do: session.handler.terminate(reason, session.handler_state)

    :ok
  end

  ## Input processing

  defp process(%{phase: :closed} = session, out), do: {:close, Enum.reverse(out), session}
  defp process(%{phase: :data} = session, out), do: process_data(session, out)
  defp process(%{phase: {:bdat, _chunk}} = session, out), do: process_chunk(session, out)

  # Input after STARTTLS is dropped until the handshake, see the moduledoc.
  defp process(%{phase: :starttls} = session, out),
    do: {:starttls, Enum.reverse(out), %{session | buffer: <<>>}}

  defp process(session, out) do
    max_line_length = line_limit(session)

    case :binary.match(session.buffer, "\n") do
      :nomatch when session.discarding ->
        {:continue, Enum.reverse(out), %{session | buffer: <<>>}}

      :nomatch when byte_size(session.buffer) > max_line_length ->
        # Drop the line so far and the rest of it as it arrives.
        session = %{session | buffer: <<>>, discarding: true}
        reply(session, out, "UNKNOWN", nil, line_too_long())

      :nomatch ->
        {:continue, Enum.reverse(out), session}

      {index, 1} ->
        <<line::binary-size(^index), ?\n, rest::binary>> = session.buffer
        session = %{session | buffer: rest}

        cond do
          session.discarding ->
            process(%{session | discarding: false}, out)

          index + 1 > max_line_length ->
            session = abort_auth(session)
            reply(session, out, "UNKNOWN", nil, line_too_long())

          true ->
            command_line(session, out, line)
        end
    end
  end

  defp line_limit(%{opts: %{auth: true, max_line_length: max}}), do: max(max, @auth_line_length)
  defp line_limit(%{opts: opts}), do: opts.max_line_length

  defp command_line(session, out, line) do
    cond do
      String.ends_with?(line, "\r") ->
        dispatch(session, out, binary_part(line, 0, byte_size(line) - 1))

      session.opts.bare_line_endings == :normalize ->
        dispatch(session, out, line)

      true ->
        bare_line_ending(session, out, "UNKNOWN", :bare_lf)
    end
  end

  defp dispatch(%{phase: {:auth, _}} = session, out, line), do: auth_response(session, out, line)
  defp dispatch(session, out, line), do: command(session, out, line)

  defp bare_line_ending(session, out, command, reason) do
    session = session |> abort_data(reason) |> abort_auth()
    text = if reason == :bare_lf, do: "<LF>", else: "<CR>"
    reply = Reply.new(521, "5.5.2", "#{session.hostname} Error: bare #{text} received")
    session = %{session | phase: :closed}
    reply(session, out, command, nil, reply)
  end

  ## Commands

  defp command(session, out, line) do
    started = System.monotonic_time()

    case Command.parse(line) do
      {:ok, command} ->
        case gate(command, session) do
          :ok ->
            execute(command, session, out, started)

          {:error, reply} ->
            reply(session, out, command_name(command), nil, reply, started)

          {:close, reply} ->
            session = %{abort_auth(session) | phase: :closed, buffer: <<>>}
            reply(session, out, command_name(command), nil, reply, started)
        end

      {:error, verb, reason} ->
        if reason == :invalid_characters and :binary.match(line, "\r") != :nomatch and
             session.opts.bare_line_endings == :reject do
          bare_line_ending(session, out, verb_name(verb), :bare_cr)
        else
          reply(session, out, verb_name(verb), nil, parse_error(verb, reason, session), started)
        end
    end
  end

  defp gate(command, session) do
    cond do
      unauth_pipelining?(command, session) ->
        {:close, Reply.new(554, "5.5.0", "Error: improper use of SMTP command pipelining")}

      # Commands that need TLS first, under require_tls.
      session.opts.require_tls and tls(session) == nil and
          command_name(command) in ~w(MAIL RCPT DATA VRFY AUTH) ->
        {:error, Reply.new(530, "5.7.0", "Must issue a STARTTLS command first")}

      true ->
        :ok
    end
  end

  # More input after a command that must end a group, or after any command
  # before PIPELINING was offered: the client did not wait for the reply.
  # Spam bots do this, and so do SMTP smuggling attempts.
  defp unauth_pipelining?(command, %{opts: %{forbid_unauth_pipelining: true}} = session) do
    name = command_name(command)

    session.buffer != "" and name not in ["QUIT", "STARTTLS"] and
      (name in @group_end or not session.esmtp)
  end

  defp unauth_pipelining?(_command, _session), do: false

  defp command_name(command) when is_atom(command), do: verb_name(command)
  defp command_name(command), do: command |> elem(0) |> verb_name()

  # LMTP has only LHLO, SMTP has no LHLO (RFC 2033 §4.1).
  defp execute({kind, name}, %{opts: %{lmtp: lmtp}} = session, out, started)
       when (kind == :lhlo and not lmtp) or (kind in [:ehlo, :helo] and lmtp) do
    reply(
      session,
      out,
      verb_name(kind),
      name,
      Reply.new(500, "5.5.1", "Command not recognized"),
      started
    )
  end

  defp execute({kind, name}, session, out, started) when kind in [:ehlo, :helo, :lhlo] do
    verb = verb_name(kind)
    esmtp = kind != :helo

    if Validators.helo?(name) do
      session = reset_transaction(session)

      case session.handler.handle_helo(kind, name, session.handler_state) do
        {:ok, state} ->
          session = %{session | handler_state: state, helo: name, esmtp: esmtp}
          reply(session, out, verb, name, helo_reply(session, kind), started)

        result ->
          handler_reply(
            session,
            out,
            verb,
            name,
            result,
            started,
            &%{&1 | helo: name, esmtp: esmtp}
          )
      end
    else
      reply(session, out, verb, name, Reply.new(501, "5.5.2", "Invalid hostname"), started)
    end
  end

  defp execute(:starttls, session, out, started) do
    cond do
      tls(session) != nil ->
        reply(
          session,
          out,
          "STARTTLS",
          nil,
          Reply.new(503, "5.5.1", "TLS already active"),
          started
        )

      not session.opts.starttls ->
        reply(
          session,
          out,
          "STARTTLS",
          nil,
          Reply.new(502, "5.5.1", "Command not implemented"),
          started
        )

      true ->
        session = %{reset_transaction(session) | phase: :starttls}

        reply(
          session,
          out,
          "STARTTLS",
          nil,
          Reply.new(220, "2.0.0", "Ready to start TLS"),
          started
        )
    end
  end

  defp execute({:auth, mechanism, initial}, session, out, started) do
    case check_auth(mechanism, initial, session) do
      {:ok, initial} ->
        session.handler.handle_auth(mechanism, initial, session.handler_state)
        |> auth_result(%{session | phase: {:auth, mechanism}}, out, started)

      {:error, reply} ->
        reply(session, out, "AUTH", mechanism, reply, started)
    end
  end

  defp execute({:mail, sender, params}, session, out, started) do
    with {:ok, mail_params} <- check_mail(params, session),
         {:ok, sender} <- envelope_address(sender, mail_params.smtputf8) do
      execute_mail(sender, mail_params, session, out, started)
    else
      {:error, reply} -> reply(session, out, "MAIL", sender, reply, started)
    end
  end

  defp execute({:rcpt, recipient, params}, session, out, started) do
    smtputf8 = session.transaction != nil and session.transaction.params.smtputf8

    case envelope_address(recipient, smtputf8) do
      {:ok, recipient} -> execute_rcpt(recipient, params, session, out, started)
      {:error, reply} -> reply(session, out, "RCPT", recipient, reply, started)
    end
  end

  defp execute(:data, session, out, started) do
    cond do
      session.transaction == nil ->
        reply(session, out, "DATA", nil, Reply.new(503, "5.5.1", "Need MAIL command"), started)

      session.transaction.recipients == [] ->
        reply(session, out, "DATA", nil, Reply.new(554, "5.5.1", "No valid recipients"), started)

      session.data != nil ->
        reply(session, out, "DATA", nil, bdat_in_progress(), started)

      session.transaction.params.body == :binarymime ->
        text = "BODY=BINARYMIME needs BDAT"
        reply(session, out, "DATA", nil, Reply.new(503, "5.5.1", text), started)

      true ->
        go_ahead = Reply.new(354, "End data with <CR><LF>.<CR><LF>")

        session.handler.handle_data(session.transaction, session.handler_state)
        |> accept(session, out, "DATA", nil, started, go_ahead, fn s ->
          decoder = DataDecoder.new(s.opts.bare_line_endings)
          %{s | phase: :data, data: %{decoder: decoder, size: 0, error: nil}}
        end)
    end
  end

  # The chunk is read first, whatever the reply (RFC 3030 §2).
  defp execute({:bdat, size, last}, session, out, started) do
    {session, refusal} =
      cond do
        not session.opts.chunking ->
          {session, Reply.new(502, "5.5.1", "Command not implemented")}

        session.transaction == nil ->
          {session, Reply.new(503, "5.5.1", "Need MAIL command")}

        session.transaction.recipients == [] ->
          {session, Reply.new(554, "5.5.1", "No valid recipients")}

        session.data == nil ->
          open_chunks(session, started)

        true ->
          {session, nil}
      end

    chunk = %{remaining: size, last: last, refusal: refusal, started: started}
    process(%{session | phase: {:bdat, chunk}}, out)
  end

  defp execute({:etrn, node}, session, out, started) do
    argument = etrn_argument(node)

    cond do
      not etrn_offered?(session) ->
        reply(
          session,
          out,
          "ETRN",
          argument,
          Reply.new(502, "5.5.1", "Command not implemented"),
          started
        )

      not session.esmtp ->
        reply(session, out, "ETRN", argument, Reply.new(503, "5.5.1", "Send EHLO first"), started)

      session.transaction != nil ->
        reply(
          session,
          out,
          "ETRN",
          argument,
          Reply.new(503, "5.5.1", "MAIL transaction in progress"),
          started
        )

      true ->
        session.handler.handle_etrn(node, session.handler_state)
        |> accept(
          session,
          out,
          "ETRN",
          argument,
          started,
          Reply.new(250, "2.0.0", "Queuing started"),
          & &1
        )
    end
  end

  defp execute(:rset, session, out, started) do
    session = reset_transaction(session)
    reply(session, out, "RSET", nil, Reply.new(250, "2.0.0", "Ok"), started)
  end

  defp execute({:noop, _argument}, session, out, started),
    do: reply(session, out, "NOOP", nil, Reply.new(250, "2.0.0", "Ok"), started)

  defp execute(:quit, session, out, started) do
    session = %{reset_transaction(session) | phase: :closed}
    reply(session, out, "QUIT", nil, Reply.new(221, "2.0.0", "Bye"), started)
  end

  defp execute({:vrfy, argument}, session, out, started) do
    if session.opts.vrfy and function_exported?(session.handler, :handle_vrfy, 2) do
      session.handler.handle_vrfy(argument, session.handler_state)
      |> accept(session, out, "VRFY", argument, started, Reply.new(252, "2.5.0", "Ok"), & &1)
    else
      text = "Cannot VRFY user, but will accept message and attempt delivery"
      reply(session, out, "VRFY", argument, Reply.new(252, "2.5.0", text), started)
    end
  end

  defp execute({:xclient, attributes}, session, out, started) do
    with :ok <- check_proxy_command(session, session.xclient),
         {:ok, changes} <- xclient_changes(attributes, session.connection) do
      xclient(session, out, changes, started)
    else
      {:error, reply} -> reply(session, out, "XCLIENT", nil, reply, started)
    end
  end

  defp execute({:xforward, attributes}, session, out, started) do
    with :ok <- check_proxy_command(session, session.xforward),
         {:ok, forwarded} <- xforward_attributes(attributes) do
      session = %{
        session
        | xforward_attributes: Map.merge(session.xforward_attributes, forwarded)
      }

      reply(session, out, "XFORWARD", nil, Reply.new(250, "2.0.0", "Ok"), started)
    else
      {:error, reply} -> reply(session, out, "XFORWARD", nil, reply, started)
    end
  end

  defp execute({:help, _argument}, session, out, started) do
    greeting = if session.opts.lmtp, do: "LHLO", else: "EHLO HELO"
    bdat = if session.opts.chunking, do: " BDAT", else: ""
    etrn = if etrn_offered?(session), do: " ETRN", else: ""

    text =
      "Commands: #{greeting} MAIL RCPT DATA#{bdat} RSET NOOP QUIT VRFY HELP STARTTLS AUTH#{etrn}"

    reply(session, out, "HELP", nil, Reply.new(214, "2.0.0", text), started)
  end

  ## XCLIENT and XFORWARD

  defp check_proxy_command(_session, false),
    do: {:error, Reply.new(550, "5.7.0", "Error: insufficient authorization")}

  defp check_proxy_command(%{transaction: transaction}, true) when transaction != nil,
    do: {:error, Reply.new(503, "5.5.1", "Error: MAIL transaction in progress")}

  defp check_proxy_command(_session, true), do: :ok

  # The connection map changes, and the HELO and PROTO to apply after.
  defp xclient_changes(attributes, connection) do
    Enum.reduce_while(attributes, {:ok, {connection, %{}}}, fn {name, value}, {:ok, acc} ->
      case xclient_attribute(name, value, acc) do
        {:ok, acc} -> {:cont, {:ok, acc}}
        :error -> {:halt, {:error, bad_attribute("XCLIENT", name)}}
      end
    end)
  end

  defp xclient_attribute(name, _value, _acc) when name not in @xclient_attributes, do: :error

  defp xclient_attribute(name, value, {connection, hello}) when name in ~w(ADDR DESTADDR) do
    key = if name == "ADDR", do: :remote_ip, else: :local_ip

    case value && parse_xaddr(value) do
      # An unknown address keeps the one the session knows.
      nil -> {:ok, {connection, hello}}
      {:ok, ip} -> {:ok, {Map.put(connection, key, ip), hello}}
      :error -> :error
    end
  end

  defp xclient_attribute(name, value, {connection, hello}) when name in ~w(PORT DESTPORT) do
    key = if name == "PORT", do: :remote_port, else: :local_port

    case value && parse_port(value) do
      nil -> {:ok, {Map.delete(connection, key), hello}}
      {:ok, port} -> {:ok, {Map.put(connection, key, port), hello}}
      :error -> :error
    end
  end

  defp xclient_attribute(name, value, {connection, hello}) when name in ~w(NAME REVERSE_NAME) do
    key = if name == "NAME", do: :client_name, else: :reverse_name

    if value == nil or Validators.hostname?(value),
      do: {:ok, {Map.put(connection, key, value && String.downcase(value, :ascii)), hello}},
      else: :error
  end

  defp xclient_attribute("LOGIN", value, {connection, hello}),
    do: {:ok, {Map.put(connection, :login, value), hello}}

  defp xclient_attribute("HELO", value, {connection, hello}) do
    if value == nil or Validators.helo?(value),
      do: {:ok, {connection, Map.put(hello, :helo, value)}},
      else: :error
  end

  defp xclient_attribute("PROTO", value, {connection, hello}) do
    case value && String.upcase(value, :ascii) do
      nil -> {:ok, {connection, Map.delete(hello, :proto)}}
      "SMTP" -> {:ok, {connection, Map.put(hello, :proto, :helo)}}
      "ESMTP" -> {:ok, {connection, Map.put(hello, :proto, :ehlo)}}
      _ -> :error
    end
  end

  # Starts over as if the client had connected itself.
  defp xclient(session, out, {connection, hello}, started) do
    if function_exported?(session.handler, :terminate, 2),
      do: session.handler.terminate(:xclient, session.handler_state)

    session = %{
      session
      | connection: connection,
        helo: nil,
        esmtp: false,
        identity: Map.get(connection, :login),
        xforward_attributes: %{}
    }

    case session.handler.init(connection, session.handler_opts) do
      {:ok, state} ->
        xclient_greet(session, out, state, hello, started)

      # No greeting delay: the proxy has waited already.
      {:pause, _delay, state} ->
        xclient_greet(session, out, state, hello, started)

      {:close, reply, state} ->
        session = %{session | handler_state: state, phase: :closed}
        reply(session, out, "XCLIENT", nil, reply, started)
    end
  end

  defp xclient_greet(session, out, state, hello, started) do
    session = xclient_helo(%{session | handler_state: state}, hello)
    reply(session, out, "XCLIENT", nil, greeting(session), started)
  end

  defp xclient_helo(session, %{helo: helo} = hello) when helo != nil do
    kind = Map.get(hello, :proto, :ehlo)

    case session.handler.handle_helo(kind, helo, session.handler_state) do
      {:ok, state} -> %{session | handler_state: state, helo: helo, esmtp: kind == :ehlo}
      {_reply_or_close, _reply, state} -> %{session | handler_state: state}
    end
  end

  defp xclient_helo(session, _hello), do: session

  defp xforward_attributes(attributes) do
    Enum.reduce_while(attributes, {:ok, %{}}, fn {name, value}, {:ok, acc} ->
      case xforward_attribute(name, value) do
        {:ok, key, value} -> {:cont, {:ok, Map.put(acc, key, value)}}
        :error -> {:halt, {:error, bad_attribute("XFORWARD", name)}}
      end
    end)
  end

  defp xforward_attribute(name, nil) when name in @xforward_attributes,
    do: {:ok, xforward_key(name), nil}

  defp xforward_attribute("ADDR", value) do
    with {:ok, ip} <- parse_xaddr(value), do: {:ok, :addr, ip}
  end

  defp xforward_attribute("PORT", value) do
    with {:ok, port} <- parse_port(value), do: {:ok, :port, port}
  end

  defp xforward_attribute("SOURCE", value) do
    case String.upcase(value, :ascii) do
      source when source in ["LOCAL", "REMOTE"] -> {:ok, :source, source}
      _ -> :error
    end
  end

  defp xforward_attribute(name, value) when name in ~w(NAME PROTO HELO IDENT),
    do: {:ok, xforward_key(name), value}

  defp xforward_attribute(_name, _value), do: :error

  defp xforward_key("NAME"), do: :name
  defp xforward_key("ADDR"), do: :addr
  defp xforward_key("PORT"), do: :port
  defp xforward_key("PROTO"), do: :proto
  defp xforward_key("HELO"), do: :helo
  defp xforward_key("IDENT"), do: :ident
  defp xforward_key("SOURCE"), do: :source

  # "192.0.2.1", "IPV6:2001:db8::1".
  defp parse_xaddr(value) do
    address =
      case value do
        <<prefix::binary-size(5), rest::binary>> when prefix in ["IPV6:", "ipv6:", "IPv6:"] ->
          rest

        _ ->
          value
      end

    case Net.parse_ip(address) do
      {:ok, ip} -> {:ok, Net.normalize(ip)}
      {:error, _} -> :error
    end
  end

  defp parse_port(value) do
    case Integer.parse(value) do
      {port, ""} when port in 0..65_535 -> {:ok, port}
      _ -> :error
    end
  end

  defp bad_attribute(command, name),
    do: Reply.new(501, "5.5.4", "Bad #{command} attribute: #{name}")

  ## AUTH

  defp auth_offered?(session) do
    session.opts.auth and (tls(session) != nil or session.opts.plaintext_auth)
  end

  defp mechanisms(session) do
    if function_exported?(session.handler, :auth_mechanisms, 1),
      do: session.handler.auth_mechanisms(session.handler_state),
      else: []
  end

  defp check_auth(mechanism, initial, session) do
    cond do
      not session.opts.auth ->
        {:error, Reply.new(503, "5.5.1", "Authentication not enabled")}

      not session.esmtp ->
        {:error,
         Reply.new(503, "5.5.1", "Send #{if session.opts.lmtp, do: "LHLO", else: "EHLO"} first")}

      session.identity != nil ->
        {:error, Reply.new(503, "5.5.1", "Already authenticated")}

      session.transaction != nil ->
        {:error, Reply.new(503, "5.5.1", "MAIL transaction in progress")}

      not auth_offered?(session) ->
        {:error,
         Reply.new(538, "5.7.11", "Encryption required for requested authentication mechanism")}

      mechanism not in mechanisms(session) ->
        {:error, Reply.new(504, "5.5.4", "Unrecognized authentication type")}

      true ->
        decode_response(initial)
    end
  end

  defp decode_response(nil), do: {:ok, nil}
  defp decode_response("="), do: {:ok, ""}

  defp decode_response(data) do
    case Base.decode64(data) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, Reply.new(501, "5.5.2", "Cannot decode response")}
    end
  end

  defp auth_response(session, out, line) do
    started = System.monotonic_time()
    {:auth, mechanism} = session.phase

    if line == "*" do
      session = abort_auth(session)

      reply(
        session,
        out,
        "AUTH",
        mechanism,
        Reply.new(501, "5.0.0", "Authentication cancelled"),
        started
      )
    else
      case decode_response(line) do
        {:ok, data} ->
          session.handler.handle_auth_response(data, session.handler_state)
          |> auth_result(session, out, started)

        {:error, reply} ->
          reply(abort_auth(session), out, "AUTH", mechanism, reply, started)
      end
    end
  end

  # A challenge is not a final reply: no telemetry, not counted as an error.
  defp auth_result({:challenge, data, state}, session, out, _started) do
    challenge = Reply.new(334, Base.encode64(data))
    process(%{session | handler_state: state}, [Reply.encode(challenge) | out])
  end

  defp auth_result({:ok, identity, state}, session, out, started) do
    {:auth, mechanism} = session.phase
    session = %{session | handler_state: state, identity: identity, phase: :command}

    reply(
      session,
      out,
      "AUTH",
      mechanism,
      Reply.new(235, "2.7.0", "Authentication successful"),
      started
    )
  end

  defp auth_result({:error, reply, state}, session, out, started) do
    {:auth, mechanism} = session.phase
    failures = session.auth_failures + if(reply.code == 535, do: 1, else: 0)
    session = %{session | handler_state: state, phase: :command, auth_failures: failures}

    if failures >= session.opts.max_auth_failures do
      closing =
        Reply.new(421, "4.7.0", "#{session.hostname} Error: too many failed authentications")

      session = %{session | phase: :closed}
      reply(session, [Reply.encode(reply) | out], "AUTH", mechanism, closing, started)
    else
      reply(session, out, "AUTH", mechanism, reply, started)
    end
  end

  defp auth_result({:close, reply, state}, session, out, started) do
    {:auth, mechanism} = session.phase
    session = %{session | handler_state: state, phase: :closed}
    reply(session, out, "AUTH", mechanism, reply, started)
  end

  defp abort_auth(%{phase: {:auth, _}} = session) do
    state =
      if function_exported?(session.handler, :handle_auth_abort, 1),
        do: session.handler.handle_auth_abort(session.handler_state),
        else: session.handler_state

    %{session | phase: :command, handler_state: state}
  end

  defp abort_auth(session), do: session

  # Runs `on_accept` on the session when the handler accepts.
  defp accept({:ok, state}, session, out, verb, argument, started, default, on_accept) do
    session = on_accept.(%{session | handler_state: state})
    reply(session, out, verb, argument, default, started)
  end

  defp accept(result, session, out, verb, argument, started, _default, on_accept),
    do: handler_reply(session, out, verb, argument, result, started, on_accept)

  defp handler_reply(session, out, verb, argument, {:reply, reply, state}, started, on_accept) do
    session = %{session | handler_state: state}
    session = if Reply.positive?(reply), do: on_accept.(session), else: session
    reply(session, out, verb, argument, reply, started)
  end

  defp handler_reply(session, out, verb, argument, {:close, reply, state}, started, _on_accept) do
    session = %{abort_data(%{session | handler_state: state}, :closed) | phase: :closed}
    reply(session, out, verb, argument, reply, started)
  end

  defp helo_reply(session, :helo), do: Reply.new(250, session.hostname)

  defp helo_reply(session, _ehlo_or_lhlo) do
    Reply.new(
      250,
      [
        session.hostname,
        "PIPELINING",
        "SIZE #{session.opts.max_message_size}",
        "8BITMIME",
        "ENHANCEDSTATUSCODES"
      ] ++ optional_extensions(session) ++ auth_extension(session) ++ proxy_extensions(session)
    )
  end

  defp optional_extensions(%{opts: opts} = session) do
    for {true, extension} <- [
          {opts.chunking, "CHUNKING"},
          {opts.chunking and opts.binarymime, "BINARYMIME"},
          {opts.dsn, "DSN"},
          {etrn_offered?(session), "ETRN"},
          {opts.starttls and tls(session) == nil, "STARTTLS"},
          {requiretls_offered?(session), "REQUIRETLS"},
          {opts.smtputf8, "SMTPUTF8"},
          {opts.mt_priority, "MT-PRIORITY"},
          {opts.future_release != nil, "FUTURERELEASE"},
          {opts.deliverby, "DELIVERBY"},
          {opts.rrvs, "RRVS"}
        ],
        do: extension_line(extension, session)
  end

  # RFC 4865 §3: the longest hold, and the latest release time.
  defp extension_line("FUTURERELEASE", %{opts: %{future_release: max}}) do
    latest = DateTime.add(DateTime.utc_now(), max)
    "FUTURERELEASE #{max} #{Params.format_time(latest)}"
  end

  defp extension_line(extension, _session), do: extension

  defp auth_extension(session) do
    with true <- auth_offered?(session) and session.identity == nil,
         [_ | _] = mechanisms <- mechanisms(session) do
      ["AUTH " <> Enum.join(mechanisms, " ")]
    else
      _ -> []
    end
  end

  defp proxy_extensions(session) do
    for {true, name, attributes} <- [
          {session.xclient, "XCLIENT", @xclient_attributes},
          {session.xforward, "XFORWARD", @xforward_attributes}
        ],
        do: name <> " " <> Enum.join(attributes, " ")
  end

  defp etrn_offered?(session),
    do: session.opts.etrn and function_exported?(session.handler, :handle_etrn, 2)

  defp etrn_argument({:domain, domain}), do: domain
  defp etrn_argument({:subdomains, domain}), do: "@" <> domain
  defp etrn_argument({:queue, queue}), do: "#" <> queue

  # RFC 8689 §4: only offered once the connection is encrypted.
  defp requiretls_offered?(session), do: session.opts.requiretls and tls(session) != nil

  defp execute_mail(sender, mail_params, session, out, started) do
    transaction = %{
      sender: sender,
      params: mail_params,
      recipients: [],
      xforward: session.xforward_attributes
    }

    session.handler.handle_mail(sender, mail_params, session.handler_state)
    |> accept(
      session,
      out,
      "MAIL",
      sender,
      started,
      Reply.new(250, "2.1.0", "Ok"),
      &%{&1 | transaction: transaction, xforward_attributes: %{}}
    )
  end

  defp execute_rcpt(recipient, params, session, out, started) do
    cond do
      session.transaction == nil ->
        reply(
          session,
          out,
          "RCPT",
          recipient,
          Reply.new(503, "5.5.1", "Need MAIL command"),
          started
        )

      session.data != nil ->
        reply(session, out, "RCPT", recipient, bdat_in_progress(), started)

      length(session.transaction.recipients) >= session.opts.max_recipients ->
        reply(
          session,
          out,
          "RCPT",
          recipient,
          Reply.new(452, "4.5.3", "Too many recipients"),
          started
        )

      true ->
        case check_rcpt(params, session) do
          {:ok, rcpt_params} -> rcpt(recipient, rcpt_params, session, out, started)
          {:error, reply} -> reply(session, out, "RCPT", recipient, reply, started)
        end
    end
  end

  defp rcpt(recipient, rcpt_params, session, out, started) do
    session.handler.handle_rcpt(recipient, rcpt_params, session.handler_state)
    |> accept(
      session,
      out,
      "RCPT",
      recipient,
      started,
      Reply.new(250, "2.1.5", "Ok"),
      fn s -> update_in(s.transaction.recipients, &(&1 ++ [recipient])) end
    )
  end

  defp check_rcpt([], _session), do: {:ok, @no_rcpt_params}
  defp check_rcpt(_params, %{esmtp: false}), do: {:error, unsupported_parameter()}

  defp check_rcpt(params, session) do
    with :ok <- unique_params(params),
         do: Enum.reduce_while(params, {:ok, @no_rcpt_params}, &add_rcpt_param(&1, &2, session))
  end

  defp add_rcpt_param(param, {:ok, acc}, session) do
    case rcpt_param(param, session) do
      {:ok, key, value} -> {:cont, {:ok, Map.put(acc, key, value)}}
      {:error, reply} -> {:halt, {:error, reply}}
    end
  end

  defp rcpt_param({"NOTIFY", value}, %{opts: %{dsn: true}}) when is_binary(value) do
    case DSNParams.parse_notify(value) do
      {:ok, notify} -> {:ok, :notify, notify}
      :error -> {:error, invalid_parameter("NOTIFY")}
    end
  end

  defp rcpt_param({"ORCPT", value}, %{opts: %{dsn: true}} = session) when is_binary(value) do
    case DSNParams.parse_orcpt(value, utf8: session.transaction.params.smtputf8) do
      {:ok, orcpt} -> {:ok, :orcpt, orcpt}
      :error -> {:error, invalid_parameter("ORCPT")}
    end
  end

  defp rcpt_param({key, _value}, %{opts: %{dsn: true}}) when key in ["NOTIFY", "ORCPT"],
    do: {:error, invalid_parameter(key)}

  defp rcpt_param({"RRVS", value}, %{opts: %{rrvs: true}}) do
    case value && Params.parse_rrvs(value) do
      {:ok, rrvs} -> {:ok, :rrvs, rrvs}
      _ -> {:error, invalid_parameter("RRVS")}
    end
  end

  defp rcpt_param(_param, _session), do: {:error, unsupported_parameter()}

  # RFC 6531 §3.4: internationalized addresses only in transactions
  # with SMTPUTF8. Their domains go on in A-labels.
  defp envelope_address(address, smtputf8) do
    cond do
      not Validators.international?(address) ->
        {:ok, address}

      not smtputf8 ->
        {:error, Reply.new(553, "5.6.7", "Non-ASCII addresses need the SMTPUTF8 parameter")}

      true ->
        case Validators.ascii_domain(address) do
          {:ok, address} -> {:ok, address}
          {:error, _} -> {:ok, address}
        end
    end
  end

  defp check_mail(_params, %{helo: nil, opts: %{lmtp: true}}),
    do: {:error, Reply.new(503, "5.5.1", "Send LHLO first")}

  defp check_mail(_params, %{helo: nil}),
    do: {:error, Reply.new(503, "5.5.1", "Send HELO/EHLO first")}

  defp check_mail(_params, %{identity: nil, opts: %{auth_required: true}}),
    do: {:error, Reply.new(530, "5.7.0", "Authentication required")}

  defp check_mail(_params, %{transaction: transaction}) when transaction != nil,
    do: {:error, Reply.new(503, "5.5.1", "Nested MAIL command")}

  defp check_mail([], _session), do: {:ok, @no_mail_params}

  defp check_mail(_params, %{esmtp: false}), do: {:error, unsupported_parameter()}

  defp check_mail(params, session) do
    with :ok <- unique_params(params),
         {:ok, mail_params} <-
           Enum.reduce_while(params, {:ok, @no_mail_params}, &add_mail_param(&1, &2, session)),
         do: check_release(mail_params)
  end

  # RFC 4865 §4: one hold at most, and with BY, due after the release.
  defp check_release(%{hold: {:conflict, _}}), do: {:error, invalid_parameter("HOLDFOR")}

  defp check_release(%{hold: hold, by: %{time: by}} = mail_params) when hold != nil do
    now = DateTime.utc_now()

    if DateTime.compare(Params.release_time(hold, now), DateTime.add(now, by)) == :lt,
      do: {:ok, mail_params},
      else: {:error, Reply.new(501, "5.5.4", "BY must end after the release time")}
  end

  defp check_release(mail_params), do: {:ok, mail_params}

  defp unique_params(params) do
    keys = Enum.map(params, &elem(&1, 0))

    if length(Enum.uniq(keys)) != length(keys),
      do: {:error, Reply.new(501, "5.5.4", "Duplicate parameter")},
      else: :ok
  end

  defp add_mail_param(param, {:ok, acc}, session) do
    case mail_param(param, session) do
      {:ok, :auth, _value} ->
        {:cont, {:ok, acc}}

      {:ok, :hold, value} when acc.hold != nil ->
        {:cont, {:ok, %{acc | hold: {:conflict, value}}}}

      {:ok, key, value} ->
        {:cont, {:ok, Map.put(acc, key, value)}}

      {:error, reply} ->
        {:halt, {:error, reply}}
    end
  end

  defp mail_param({"SIZE", value}, session) when is_binary(value) and byte_size(value) <= 20 do
    case Integer.parse(value) do
      {size, ""} when size > session.opts.max_message_size ->
        {:error, Reply.new(552, "5.3.4", "Message size exceeds fixed maximum message size")}

      {size, ""} when size >= 0 ->
        {:ok, :size, size}

      _ ->
        {:error, Reply.new(501, "5.5.4", "Invalid SIZE parameter")}
    end
  end

  defp mail_param({"BODY", value}, session) when is_binary(value) do
    case String.upcase(value, :ascii) do
      "7BIT" ->
        {:ok, :body, :"7bit"}

      "8BITMIME" ->
        {:ok, :body, :"8bitmime"}

      "BINARYMIME" when session.opts.chunking and session.opts.binarymime ->
        {:ok, :body, :binarymime}

      _ ->
        {:error, invalid_parameter("BODY")}
    end
  end

  defp mail_param({"RET", value}, %{opts: %{dsn: true}}) when is_binary(value) do
    case DSNParams.parse_ret(value) do
      {:ok, ret} -> {:ok, :ret, ret}
      :error -> {:error, invalid_parameter("RET")}
    end
  end

  defp mail_param({"ENVID", value}, %{opts: %{dsn: true}}) when is_binary(value) do
    case DSNParams.parse_envid(value) do
      {:ok, envid} -> {:ok, :envid, envid}
      :error -> {:error, invalid_parameter("ENVID")}
    end
  end

  defp mail_param({key, _value}, %{opts: %{dsn: true}}) when key in ["RET", "ENVID"],
    do: {:error, invalid_parameter(key)}

  defp mail_param({"MT-PRIORITY", value}, %{opts: %{mt_priority: true}}) do
    case value && Params.parse_priority(value) do
      {:ok, priority} -> {:ok, :priority, priority}
      _ -> {:error, Reply.new(501, "5.5.2", "Invalid MT-PRIORITY parameter")}
    end
  end

  defp mail_param({"HOLDFOR", value}, %{opts: %{future_release: max}}) when max != nil do
    case value && Params.parse_holdfor(value) do
      {:ok, seconds} when seconds <= max -> {:ok, :hold, {:for, seconds}}
      _ -> {:error, invalid_parameter("HOLDFOR")}
    end
  end

  defp mail_param({"HOLDUNTIL", value}, %{opts: %{future_release: max}}) when max != nil do
    latest = DateTime.add(DateTime.utc_now(), max)

    with {:ok, time} <- (value && Params.parse_holduntil(value)) || :error,
         true <- DateTime.compare(time, latest) != :gt do
      {:ok, :hold, {:until, time}}
    else
      _ -> {:error, invalid_parameter("HOLDUNTIL")}
    end
  end

  defp mail_param({"BY", value}, %{opts: %{deliverby: true}}) do
    case value && Params.parse_by(value) do
      {:ok, by} -> {:ok, :by, by}
      _ -> {:error, invalid_parameter("BY")}
    end
  end

  # RFC 4954 §5. Accepted and not used: Sovite does not relay
  # authenticated identities between trusted servers.
  defp mail_param({"AUTH", value}, %{opts: %{auth: true}}) when is_binary(value),
    do: {:ok, :auth, nil}

  defp mail_param({"REQUIRETLS", nil}, session) do
    if requiretls_offered?(session),
      do: {:ok, :requiretls, true},
      else: {:error, unsupported_parameter()}
  end

  defp mail_param({"SMTPUTF8", nil}, %{opts: %{smtputf8: true}}), do: {:ok, :smtputf8, true}

  defp mail_param({key, _value}, _session) when key in ["SIZE", "BODY", "REQUIRETLS"],
    do: {:error, invalid_parameter(key)}

  defp mail_param(_param, _session), do: {:error, unsupported_parameter()}

  defp unsupported_parameter, do: Reply.new(555, "5.5.4", "Unsupported parameter")

  defp invalid_parameter(key), do: Reply.new(501, "5.5.4", "Invalid #{key} parameter")

  defp bdat_in_progress, do: Reply.new(503, "5.5.1", "Error: BDAT in progress")

  defp line_too_long, do: Reply.new(500, "5.5.2", "Line too long")

  defp parse_error(_verb, :unrecognized, _session),
    do: Reply.new(500, "5.5.2", "Command not recognized")

  defp parse_error(_verb, :not_implemented, _session),
    do: Reply.new(502, "5.5.1", "Command not implemented")

  defp parse_error(_verb, :invalid_characters, _session),
    do: Reply.new(500, "5.5.2", "Invalid characters")

  defp parse_error(_verb, :invalid_sender, _session),
    do: Reply.new(501, "5.1.7", "Bad sender address syntax")

  defp parse_error(_verb, :invalid_recipient, _session),
    do: Reply.new(501, "5.1.3", "Bad recipient address syntax")

  defp parse_error(_verb, :invalid_parameter, _session),
    do: Reply.new(501, "5.5.4", "Invalid parameter syntax")

  defp parse_error(_verb, :non_smtp, session),
    do: Reply.new(421, "4.7.0", "#{session.hostname} Non-SMTP command, closing connection")

  defp parse_error(verb, :syntax, _session),
    do: Reply.new(501, "5.5.4", "Syntax: " <> usage(verb))

  defp usage(:ehlo), do: "EHLO hostname"
  defp usage(:helo), do: "HELO hostname"
  defp usage(:mail), do: "MAIL FROM:<address> [parameters]"
  defp usage(:rcpt), do: "RCPT TO:<address>"
  defp usage(:vrfy), do: "VRFY address"
  defp usage(:auth), do: "AUTH mechanism [initial-response]"
  defp usage(:bdat), do: "BDAT size [LAST]"
  defp usage(:etrn), do: "ETRN [@]domain"
  defp usage(verb), do: verb_name(verb)

  defp verb_name(nil), do: "UNKNOWN"
  defp verb_name(verb), do: verb |> Atom.to_string() |> String.upcase()

  defp reset_transaction(%{transaction: nil} = session), do: session

  defp reset_transaction(session) do
    # Chunks of a message sent with BDAT.
    session = %{abort_data(session, :reset) | data: nil}

    state =
      if function_exported?(session.handler, :handle_rset, 1),
        do: session.handler.handle_rset(session.handler_state),
        else: session.handler_state

    %{session | transaction: nil, handler_state: state}
  end

  ## Message data

  defp process_data(session, out) do
    case DataDecoder.decode(session.data.decoder, session.buffer) do
      {:more, content, decoder} ->
        session = content(%{session | buffer: <<>>}, content)
        {:continue, Enum.reverse(out), put_in(session.data.decoder, decoder)}

      {:done, content, rest} ->
        session = content(%{session | buffer: rest}, content)
        finish_data(session, out)

      {:error, reason, _content} ->
        bare_line_ending(%{session | buffer: <<>>}, out, "END-OF-MESSAGE", reason)
    end
  end

  defp content(%{data: %{error: nil}} = session, content) do
    size = session.data.size + IO.iodata_length(content)

    cond do
      size == session.data.size ->
        session

      size > session.opts.max_message_size ->
        session = abort_data(session, :too_large)
        reply = Reply.new(552, "5.3.4", "Message size exceeds fixed maximum message size")
        %{session | data: %{session.data | error: reply, size: size}}

      true ->
        case session.handler.handle_data_chunk(content, session.handler_state) do
          {:ok, state} ->
            %{session | handler_state: state, data: %{session.data | size: size}}

          {:reply, reply, state} ->
            %{session | handler_state: state, data: %{session.data | error: reply, size: size}}
        end
    end
  end

  # After an error the rest of the message is discarded.
  defp content(session, _content), do: session

  defp finish_data(session, out) do
    started = System.monotonic_time()
    transaction = session.transaction
    session = %{session | phase: :command, transaction: nil}

    case session.data do
      %{error: nil} ->
        session = %{session | data: nil}

        result = session.handler.handle_data_end(transaction, session.handler_state)

        if session.opts.lmtp,
          do: lmtp_data_end(result, session, out, transaction, started),
          else:
            accept(
              result,
              session,
              out,
              "END-OF-MESSAGE",
              nil,
              started,
              Reply.new(250, "2.0.0", "Ok"),
              & &1
            )

      %{error: reply} ->
        if session.opts.lmtp,
          do: lmtp_replies(%{session | data: nil}, out, transaction.recipients, reply, started),
          else: reply(%{session | data: nil}, out, "END-OF-MESSAGE", nil, reply, started)
    end
  end

  defp lmtp_data_end({:ok, state}, session, out, transaction, started) do
    session = %{session | handler_state: state}
    lmtp_replies(session, out, transaction.recipients, Reply.new(250, "2.0.0", "Ok"), started)
  end

  defp lmtp_data_end({:reply, reply, state}, session, out, transaction, started),
    do:
      lmtp_replies(%{session | handler_state: state}, out, transaction.recipients, reply, started)

  defp lmtp_data_end({:close, _reply, _state} = result, session, out, _transaction, started),
    do: handler_reply(session, out, "END-OF-MESSAGE", nil, result, started, & &1)

  # One reply per accepted recipient, the last one through reply/6.
  defp lmtp_replies(session, out, recipients, reply, started) do
    {earlier, [last]} = Enum.split(recipients, -1)

    {session, out} =
      Enum.reduce(earlier, {session, out}, fn recipient, {session, out} ->
        reply_event(session, "END-OF-MESSAGE", recipient, reply, started)
        errors = session.errors + if(Reply.negative?(reply), do: 1, else: 0)
        {%{session | errors: errors}, [Reply.encode(reply) | out]}
      end)

    reply(session, out, "END-OF-MESSAGE", last, reply, started)
  end

  ## BDAT chunks

  # The first chunk of a message: the handler accepts it as DATA. A
  # refusal is kept for the rest of the chunks.
  defp open_chunks(session, started) do
    decoder =
      if session.transaction.params.body != :binarymime,
        do: DataDecoder.new(session.opts.bare_line_endings, dots: false)

    data = %{decoder: decoder, size: 0, error: nil}

    case session.handler.handle_data(session.transaction, session.handler_state) do
      {:ok, state} ->
        {%{session | handler_state: state, data: data}, nil}

      {:reply, reply, state} ->
        if Reply.positive?(reply),
          do: {%{session | handler_state: state, data: data}, nil},
          else: {%{session | handler_state: state, data: %{data | error: reply}}, nil}

      {:close, reply, state} ->
        session = %{session | handler_state: state, phase: :closed}
        {session, {:close, reply, started}}
    end
  end

  defp process_chunk(%{phase: {:bdat, %{refusal: {:close, reply, started}}}} = session, out) do
    session = %{session | phase: :closed, buffer: <<>>}
    reply(session, out, "BDAT", nil, reply, started)
  end

  defp process_chunk(%{phase: {:bdat, chunk}} = session, out) do
    taken = min(chunk.remaining, byte_size(session.buffer))
    <<bytes::binary-size(^taken), rest::binary>> = session.buffer
    chunk = %{chunk | remaining: chunk.remaining - taken}
    session = %{session | buffer: rest, phase: {:bdat, chunk}}

    case chunk_content(session, bytes) do
      {:ok, session} when chunk.remaining > 0 ->
        {:continue, Enum.reverse(out), session}

      {:ok, session} ->
        chunk_done(%{session | phase: :command}, out, chunk)

      {:error, reason} ->
        bare_line_ending(%{session | buffer: <<>>, phase: :command}, out, "BDAT", reason)
    end
  end

  defp chunk_content(%{phase: {:bdat, %{refusal: nil}}, data: %{error: nil}} = session, bytes) do
    case session.data.decoder do
      nil ->
        {:ok, content(session, bytes)}

      decoder ->
        case DataDecoder.decode(decoder, bytes) do
          {:more, content, decoder} ->
            {:ok, content(put_in(session.data.decoder, decoder), content)}

          {:error, reason, _content} ->
            {:error, reason}
        end
    end
  end

  defp chunk_content(session, _bytes), do: {:ok, session}

  defp chunk_done(session, out, %{refusal: %Reply{} = reply} = chunk) do
    session = if chunk.last and session.transaction, do: reset_transaction(session), else: session
    reply(session, out, "BDAT", nil, reply, chunk.started)
  end

  defp chunk_done(session, out, %{last: false} = chunk) do
    case session.data do
      %{error: nil, size: size} ->
        reply(
          session,
          out,
          "BDAT",
          nil,
          Reply.new(250, "2.0.0", "#{size} octets received"),
          chunk.started
        )

      %{error: :aborted} ->
        reply(
          session,
          out,
          "BDAT",
          nil,
          Reply.new(554, "5.5.0", "Error: message aborted"),
          chunk.started
        )

      %{error: reply} ->
        reply(session, out, "BDAT", nil, reply, chunk.started)
    end
  end

  # The last chunk ends the message as the final dot does.
  defp chunk_done(session, out, _chunk) do
    case session.data do
      %{error: nil, decoder: decoder} when decoder != nil ->
        case DataDecoder.finish(decoder) do
          {:ok, content} -> finish_data(content(session, content), out)
          {:error, reason, _} -> bare_line_ending(session, out, "END-OF-MESSAGE", reason)
        end

      %{error: :aborted} ->
        session = %{
          session
          | data: %{session.data | error: Reply.new(554, "5.5.0", "Error: message aborted")}
        }

        finish_data(session, out)

      _data ->
        finish_data(session, out)
    end
  end

  # Tells the handler that an open message will not complete.
  defp abort_data(%{data: %{error: nil}} = session, reason) do
    state = session.handler.handle_data_abort(reason, session.handler_state)
    %{session | handler_state: state, data: %{session.data | error: :aborted}}
  end

  defp abort_data(session, _reason), do: session

  ## Replies

  defp reply(session, out, command, argument, reply, started \\ System.monotonic_time()) do
    reply_event(session, command, argument, reply, started)

    # The greeting and the EHLO/HELO response carry no enhanced code
    # (RFC 2034 §4). Errors keep theirs, as most servers do.
    reply =
      if command in ["EHLO", "HELO", "LHLO"] and Reply.positive?(reply),
        do: %{reply | enhanced: nil},
        else: reply

    out = [Reply.encode(reply) | out]

    session = if Reply.negative?(reply), do: count_error(session), else: session

    cond do
      session.phase == :closed or reply.code == 421 ->
        {:close, Enum.reverse(out), %{session | phase: :closed}}

      session.phase == :starttls ->
        {:starttls, Enum.reverse(out), %{session | buffer: <<>>}}

      session.errors >= session.opts.max_errors ->
        closing = Reply.new(421, "4.7.0", "#{session.hostname} Error: too many errors")
        {:close, Enum.reverse([Reply.encode(closing) | out]), %{session | phase: :closed}}

      true ->
        process(session, out)
    end
  end

  defp count_error(%{opts: opts} = session) do
    errors = session.errors + 1
    delay = if errors >= opts.tarpit_after, do: opts.tarpit_delay, else: 0
    %{session | errors: errors, delay: session.delay + delay}
  end

  defp reply_event(session, command, argument, reply, started) do
    :telemetry.execute(
      [:sovite, :smtp, :server, :command, :stop],
      %{duration: System.monotonic_time() - started},
      %{
        session_id: session.connection.session_id,
        remote_ip: session.connection.remote_ip,
        command: command,
        argument: argument,
        reply_code: reply.code,
        reply: Reply.to_string(reply)
      }
    )
  end
end
