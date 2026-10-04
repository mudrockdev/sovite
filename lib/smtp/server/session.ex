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

  ## Telemetry

  `[:sovite, :smtp, :server, :command, :stop]` for every reply, with
  `%{duration}` and `%{session_id, remote_ip, command, argument,
  reply_code, reply}`. `command` is the verb (`"MAIL"`), `"UNKNOWN"`, or
  `"END-OF-MESSAGE"` for the final dot. `argument` is only set for `EHLO`,
  `HELO`, `MAIL`, `RCPT`, and `VRFY`, and is network input.
  """

  alias Sovite.SMTP.{Command, DataDecoder, Reply}
  alias Sovite.Validators

  @typedoc "Who is connected. Passed to the handler's `init/2`."
  @type connection :: %{
          required(:session_id) => String.t(),
          required(:remote_ip) => :inet.ip_address(),
          optional(:remote_port) => :inet.port_number(),
          optional(:local_ip) => :inet.ip_address(),
          optional(:local_port) => :inet.port_number(),
          optional(:listener) => String.t()
        }

  @typedoc "`MAIL FROM` parameters. `body` is `nil` when not given."
  @type mail_params :: %{size: non_neg_integer() | nil, body: :"7bit" | :"8bitmime" | nil}

  @typedoc "The current mail transaction. Recipients are in the order given."
  @type transaction :: %{
          sender: String.t(),
          params: mail_params(),
          recipients: [String.t()]
        }

  @type result :: {:continue | :close, iodata(), t()}

  @defaults [
    max_message_size: 10 * 1024 * 1024,
    max_recipients: 100,
    max_errors: 10,
    max_line_length: 2048,
    command_timeout: 300_000,
    data_timeout: 300_000,
    vrfy: false,
    bare_line_endings: :reject
  ]

  defstruct [
    :connection,
    :hostname,
    :handler,
    :handler_state,
    :opts,
    :helo,
    :transaction,
    :data,
    phase: :command,
    esmtp: false,
    buffer: <<>>,
    discarding: false,
    errors: 0
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
      opts: Map.new(opts)
    }

    case module.init(connection, handler_opts) do
      {:ok, state} ->
        greeting = Reply.new(220, "#{session.hostname} ESMTP")
        {:continue, Reply.encode(greeting), %{session | handler_state: state}}

      {:close, reply, state} ->
        {:close, Reply.encode(reply), %{session | handler_state: state, phase: :closed}}
    end
  end

  @doc "Returns the session ID."
  @spec session_id(t()) :: String.t()
  def session_id(%__MODULE__{connection: connection}), do: connection.session_id

  @doc "Milliseconds to wait for more input before calling `handle_timeout/1`."
  @spec timeout(t()) :: timeout()
  def timeout(%__MODULE__{phase: :data, opts: opts}), do: opts.data_timeout
  def timeout(%__MODULE__{opts: opts}), do: opts.command_timeout

  @doc "Processes bytes received from the client."
  @spec handle_input(t(), binary()) :: result()
  def handle_input(%__MODULE__{phase: :closed} = session, _bytes), do: {:close, [], session}

  def handle_input(%__MODULE__{} = session, bytes) do
    process(%{session | buffer: session.buffer <> bytes}, [])
  end

  @doc "The client sent nothing for `timeout/1` milliseconds."
  @spec handle_timeout(t()) :: result()
  def handle_timeout(%__MODULE__{} = session) do
    session = abort_data(session, :timeout)
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

  defp process(session, out) do
    case :binary.match(session.buffer, "\n") do
      :nomatch when session.discarding ->
        {:continue, Enum.reverse(out), %{session | buffer: <<>>}}

      :nomatch when byte_size(session.buffer) > session.opts.max_line_length ->
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

          index + 1 > session.opts.max_line_length ->
            reply(session, out, "UNKNOWN", nil, line_too_long())

          true ->
            command_line(session, out, line)
        end
    end
  end

  defp command_line(session, out, line) do
    cond do
      String.ends_with?(line, "\r") ->
        command(session, out, binary_part(line, 0, byte_size(line) - 1))

      session.opts.bare_line_endings == :normalize ->
        command(session, out, line)

      true ->
        bare_line_ending(session, out, "UNKNOWN", :bare_lf)
    end
  end

  defp bare_line_ending(session, out, command, reason) do
    session = abort_data(session, reason)
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
        execute(command, session, out, started)

      {:error, verb, reason} ->
        if reason == :invalid_characters and :binary.match(line, "\r") != :nomatch and
             session.opts.bare_line_endings == :reject do
          bare_line_ending(session, out, verb_name(verb), :bare_cr)
        else
          reply(session, out, verb_name(verb), nil, parse_error(verb, reason, session), started)
        end
    end
  end

  defp execute({kind, name}, session, out, started) when kind in [:ehlo, :helo] do
    verb = verb_name(kind)

    if Validators.helo?(name) do
      session = reset_transaction(session)

      case session.handler.handle_helo(kind, name, session.handler_state) do
        {:ok, state} ->
          session = %{session | handler_state: state, helo: name, esmtp: kind == :ehlo}
          reply(session, out, verb, name, helo_reply(session, kind), started)

        result ->
          handler_reply(
            session,
            out,
            verb,
            name,
            result,
            started,
            &%{&1 | helo: name, esmtp: kind == :ehlo}
          )
      end
    else
      reply(session, out, verb, name, Reply.new(501, "5.5.2", "Invalid hostname"), started)
    end
  end

  defp execute({:mail, sender, params}, session, out, started) do
    case check_mail(params, session) do
      {:ok, mail_params} ->
        transaction = %{sender: sender, params: mail_params, recipients: []}
        accepted = Reply.new(250, "2.1.0", "Ok")

        session.handler.handle_mail(sender, mail_params, session.handler_state)
        |> accept(
          session,
          out,
          "MAIL",
          sender,
          started,
          accepted,
          &%{&1 | transaction: transaction}
        )

      {:error, reply} ->
        reply(session, out, "MAIL", sender, reply, started)
    end
  end

  defp execute({:rcpt, recipient, params}, session, out, started) do
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

      params != [] ->
        reply(session, out, "RCPT", recipient, unsupported_parameter(), started)

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
        session.handler.handle_rcpt(recipient, session.handler_state)
        |> accept(session, out, "RCPT", recipient, started, Reply.new(250, "2.1.5", "Ok"), fn s ->
          update_in(s.transaction.recipients, &(&1 ++ [recipient]))
        end)
    end
  end

  defp execute(:data, session, out, started) do
    cond do
      session.transaction == nil ->
        reply(session, out, "DATA", nil, Reply.new(503, "5.5.1", "Need MAIL command"), started)

      session.transaction.recipients == [] ->
        reply(session, out, "DATA", nil, Reply.new(554, "5.5.1", "No valid recipients"), started)

      true ->
        go_ahead = Reply.new(354, "End data with <CR><LF>.<CR><LF>")

        session.handler.handle_data(session.transaction, session.handler_state)
        |> accept(session, out, "DATA", nil, started, go_ahead, fn s ->
          decoder = DataDecoder.new(s.opts.bare_line_endings)
          %{s | phase: :data, data: %{decoder: decoder, size: 0, error: nil}}
        end)
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

  defp execute({:help, _argument}, session, out, started) do
    text = "Commands: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT VRFY HELP"
    reply(session, out, "HELP", nil, Reply.new(214, "2.0.0", text), started)
  end

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

  defp helo_reply(session, :ehlo) do
    Reply.new(250, [
      session.hostname,
      "PIPELINING",
      "SIZE #{session.opts.max_message_size}",
      "8BITMIME",
      "ENHANCEDSTATUSCODES"
    ])
  end

  defp check_mail(_params, %{helo: nil}),
    do: {:error, Reply.new(503, "5.5.1", "Send HELO/EHLO first")}

  defp check_mail(_params, %{transaction: transaction}) when transaction != nil,
    do: {:error, Reply.new(503, "5.5.1", "Nested MAIL command")}

  defp check_mail([], _session), do: {:ok, %{size: nil, body: nil}}

  defp check_mail(_params, %{esmtp: false}), do: {:error, unsupported_parameter()}

  defp check_mail(params, session) do
    keys = Enum.map(params, &elem(&1, 0))

    if length(Enum.uniq(keys)) != length(keys),
      do: {:error, Reply.new(501, "5.5.4", "Duplicate parameter")},
      else:
        Enum.reduce_while(
          params,
          {:ok, %{size: nil, body: nil}},
          &add_mail_param(&1, &2, session)
        )
  end

  defp add_mail_param(param, {:ok, acc}, session) do
    case mail_param(param, session) do
      {:ok, key, value} -> {:cont, {:ok, Map.put(acc, key, value)}}
      {:error, reply} -> {:halt, {:error, reply}}
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

  defp mail_param({"BODY", value}, _session) when is_binary(value) do
    case String.upcase(value, :ascii) do
      "7BIT" -> {:ok, :body, :"7bit"}
      "8BITMIME" -> {:ok, :body, :"8bitmime"}
      _ -> {:error, Reply.new(501, "5.5.4", "Invalid BODY parameter")}
    end
  end

  defp mail_param({key, _value}, _session) when key in ["SIZE", "BODY"],
    do: {:error, Reply.new(501, "5.5.4", "Invalid #{key} parameter")}

  defp mail_param(_param, _session), do: {:error, unsupported_parameter()}

  defp unsupported_parameter, do: Reply.new(555, "5.5.4", "Unsupported parameter")

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
  defp usage(verb), do: verb_name(verb)

  defp verb_name(nil), do: "UNKNOWN"
  defp verb_name(verb), do: verb |> Atom.to_string() |> String.upcase()

  defp reset_transaction(%{transaction: nil} = session), do: session

  defp reset_transaction(session) do
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

        session.handler.handle_data_end(transaction, session.handler_state)
        |> accept(
          session,
          out,
          "END-OF-MESSAGE",
          nil,
          started,
          Reply.new(250, "2.0.0", "Ok"),
          & &1
        )

      %{error: reply} ->
        reply(%{session | data: nil}, out, "END-OF-MESSAGE", nil, reply, started)
    end
  end

  # Tells the handler that an open message will not complete.
  defp abort_data(%{phase: :data, data: %{error: nil}} = session, reason) do
    state = session.handler.handle_data_abort(reason, session.handler_state)
    %{session | handler_state: state, data: %{session.data | error: :aborted}}
  end

  defp abort_data(session, _reason), do: session

  ## Replies

  defp reply(session, out, command, argument, reply, started \\ System.monotonic_time()) do
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

    # The greeting and the EHLO/HELO response carry no enhanced code
    # (RFC 2034 §4). Errors keep theirs, as most servers do.
    reply =
      if command in ["EHLO", "HELO"] and Reply.positive?(reply),
        do: %{reply | enhanced: nil},
        else: reply

    out = [Reply.encode(reply) | out]

    session =
      if Reply.negative?(reply), do: %{session | errors: session.errors + 1}, else: session

    cond do
      session.phase == :closed or reply.code == 421 ->
        {:close, Enum.reverse(out), %{session | phase: :closed}}

      session.errors >= session.opts.max_errors ->
        closing = Reply.new(421, "4.7.0", "#{session.hostname} Error: too many errors")
        {:close, Enum.reverse([Reply.encode(closing) | out]), %{session | phase: :closed}}

      true ->
        process(session, out)
    end
  end
end
