defmodule Sovite.Test.FakeMTA do
  @moduledoc """
  A scripted SMTP server that stands in for a remote MTA in tests.

  It listens on a random local port and accepts any number of
  connections. Each accepted message is sent to the owner process as
  `{:fake_mta, pid, {:message, message}}`, where `message` is a map with
  `:helo`, `:mail_from`, `:mail_args` (the whole `MAIL` argument, with
  parameters), `:rcpt_to` (accepted recipients only), and `:data`
  (dot-unstuffed, without the final `.`). Each new connection is reported
  as `{:fake_mta, pid, :connected}`.

      {:ok, mta} = FakeMTA.start_link(responses: %{rcpt: &reject_unknown/1})
      port = FakeMTA.port(mta)

  ## Options

    * `:owner` - the process that receives messages. Defaults to the caller.
    * `:hostname` - the name in the greeting and EHLO reply.
    * `:extensions` - EHLO keywords to advertise.
    * `:responses` - per-stage reply overrides, see below.
    * `:tls` - `:ssl` server options: offer `STARTTLS`.
    * `:implicit_tls` - with `:tls`, run the handshake before the greeting.
    * `:auth` - a map of user name to password: offer `AUTH PLAIN LOGIN`.
    * `:lmtp` - speak LMTP: answer `LHLO` instead of `EHLO`, and reply
      once per accepted recipient after the data, with the `:lmtp_data_end`
      response (called with the recipient). Messages then also carry
      `:delivered`, the recipients that got a 2xx reply.
    * `:unix` - listen on this Unix socket path instead of a TCP port.

  Messages also carry `:tls` (the `Sovite.TLS.info()` of the connection,
  or `nil`), `:auth` (the authenticated user, or `nil`), and `:xforward`
  (the arguments of the `XFORWARD` commands before `MAIL`, when an
  `XFORWARD` extension is advertised).

  ## Responses

  `:responses` maps a stage to a reply. A reply is a string such as
  `"451 4.3.0 try later"` (use `"\\r\\n"` between lines of multi-line
  replies), `:close` to drop the connection, or a one-arity function that
  receives the command argument and returns either of those.

  Stages: `:greeting`, `:ehlo`, `:helo`, `:mail`, `:rcpt`, `:data` (reply
  to `DATA`), `:data_end` (reply after the final dot), `:rset`, `:noop`,
  `:quit`. Recipients are recorded only when the `:rcpt` reply is 2xx.
  """

  use GenServer

  @default_extensions ["PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES"]
  @recv_timeout 10_000

  def start_link(opts \\ []) do
    opts = Keyword.put_new(opts, :owner, self())
    GenServer.start_link(__MODULE__, opts)
  end

  @doc "Returns the port the fake MTA listens on."
  def port(mta), do: GenServer.call(mta, :port)

  @doc "Stops the fake MTA and closes all its connections."
  def stop(mta), do: GenServer.stop(mta)

  @impl true
  def init(opts) do
    address =
      case Keyword.get(opts, :unix) do
        nil -> [ip: {127, 0, 0, 1}, reuseaddr: true]
        path -> [:local, ifaddr: {:local, path}]
      end

    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, active: false, packet: :line, buffer: 65_536] ++ address)

    {:ok, port} = if opts[:unix], do: {:ok, 0}, else: :inet.port(listen)

    config = %{
      owner: Keyword.fetch!(opts, :owner),
      server: self(),
      hostname: Keyword.get(opts, :hostname, "fake-mta.test"),
      extensions: Keyword.get(opts, :extensions, @default_extensions),
      responses: Keyword.get(opts, :responses, %{}),
      tls: Keyword.get(opts, :tls),
      implicit_tls: Keyword.get(opts, :implicit_tls, false),
      auth: Keyword.get(opts, :auth),
      lmtp: Keyword.get(opts, :lmtp, false)
    }

    acceptor = spawn_link(fn -> accept_loop(listen, config) end)
    {:ok, %{listen: listen, port: port, acceptor: acceptor}}
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, state.port, state}

  ## Connections

  defp accept_loop(listen, config) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        pid = spawn_link(fn -> serve({:gen_tcp, socket}, config) end)
        :ok = :gen_tcp.controlling_process(socket, pid)
        send(pid, :go)
        accept_loop(listen, config)

      {:error, :closed} ->
        :ok
    end
  end

  defp serve(socket, config) do
    receive do
      :go -> :ok
    end

    send(config.owner, {:fake_mta, config.server, :connected})

    {socket, tls} =
      if config.implicit_tls, do: upgrade(socket, config), else: {socket, nil}

    greeting = respond(config, :greeting, nil, "220 #{config.hostname} ESMTP fake")

    if socket && reply(socket, greeting) == :ok do
      session(socket, config, new_transaction(nil, %{tls: tls, auth: nil}))
    end
  end

  defp upgrade({:gen_tcp, raw}, config) do
    case :ssl.handshake(raw, config.tls ++ [mode: :binary, packet: :line, active: false], 5_000) do
      {:ok, ssl} ->
        {:ok, tls} = Sovite.TLS.info(ssl)
        {{:ssl, ssl}, tls}

      {:error, reason} ->
        send(config.owner, {:fake_mta, config.server, {:tls_failed, reason}})
        :gen_tcp.close(raw)
        {nil, nil}
    end
  end

  defp new_transaction(helo, session),
    do: %{
      helo: helo,
      mail_from: nil,
      mail_args: nil,
      rcpt_to: [],
      xforward: [],
      tls: session.tls,
      auth: session.auth
    }

  defp session(socket, config, txn) do
    case recv(socket) do
      {:ok, line} ->
        {verb, arg} = split_command(String.trim_trailing(line, "\r\n"))

        case handle_command(verb, arg, socket, config, txn) do
          {:continue, txn} -> session(socket, config, txn)
          :stop -> io_close(socket)
        end

      {:error, _} ->
        io_close(socket)
    end
  end

  defp handle_command(verb, arg, socket, %{lmtp: lmtp} = config, txn)
       when (verb == "EHLO" and not lmtp) or (verb == "LHLO" and lmtp) do
    starttls = if config.tls && txn.tls == nil, do: ["STARTTLS"], else: []
    auth = if config.auth, do: ["AUTH PLAIN LOGIN"], else: []
    lines = [config.hostname | config.extensions] ++ starttls ++ auth
    default = lines |> Enum.with_index(1) |> Enum.map_join("\r\n", &ehlo_line(&1, length(lines)))
    send_reply(socket, respond(config, :ehlo, arg, default), new_transaction(arg, txn))
  end

  defp handle_command("HELO", arg, socket, config, txn) do
    send_reply(
      socket,
      respond(config, :helo, arg, "250 #{config.hostname}"),
      new_transaction(arg, txn)
    )
  end

  defp handle_command("STARTTLS", _arg, socket, %{tls: tls} = config, %{tls: nil} = txn)
       when tls != nil do
    reply = respond(config, :starttls, nil, "220 2.0.0 Ready to start TLS")

    if String.starts_with?(reply, "220") do
      :ok = reply(socket, reply)

      case upgrade(socket, config) do
        {nil, nil} ->
          :stop

        {socket, tls} ->
          send(config.owner, {:fake_mta, config.server, {:tls, tls}})
          # Restart the loop with a fresh session over TLS.
          session(socket, config, new_transaction(nil, %{tls: tls, auth: nil}))
          :stop
      end
    else
      send_reply(socket, reply, txn)
    end
  end

  defp handle_command("AUTH", arg, socket, %{auth: users} = config, txn) when is_map(users) do
    case String.split(arg, " ") do
      ["PLAIN", initial] ->
        check_auth(socket, config, txn, Base.decode64!(initial))

      ["PLAIN"] ->
        :ok = reply(socket, "334 ")
        {:ok, line} = recv(socket)
        check_auth(socket, config, txn, Base.decode64!(String.trim(line)))

      ["LOGIN"] ->
        :ok = reply(socket, "334 VXNlcm5hbWU6")
        {:ok, user} = recv(socket)
        :ok = reply(socket, "334 UGFzc3dvcmQ6")
        {:ok, pass} = recv(socket)
        user = Base.decode64!(String.trim(user))

        check_auth(
          socket,
          config,
          txn,
          <<0, user::binary, 0, Base.decode64!(String.trim(pass))::binary>>
        )

      _ ->
        send_reply(socket, "504 5.5.4 Unrecognized authentication type", txn)
    end
  end

  defp handle_command("MAIL", arg, socket, config, txn) do
    from = extract_path(arg, "FROM:")
    reply = respond(config, :mail, from, "250 2.1.0 OK")
    txn = if positive?(reply), do: %{txn | mail_from: from, mail_args: arg}, else: txn
    send_reply(socket, reply, txn)
  end

  defp handle_command("RCPT", arg, socket, config, txn) do
    rcpt = extract_path(arg, "TO:")
    reply = respond(config, :rcpt, rcpt, "250 2.1.5 OK")

    send_reply(
      socket,
      reply,
      if(positive?(reply), do: %{txn | rcpt_to: txn.rcpt_to ++ [rcpt]}, else: txn)
    )
  end

  defp handle_command("DATA", _arg, socket, config, txn) do
    default =
      if txn.rcpt_to == [],
        do: "554 5.5.1 No valid recipients",
        else: "354 End data with <CR><LF>.<CR><LF>"

    reply = respond(config, :data, nil, default)

    with {:continue, txn} <- send_reply(socket, reply, txn) do
      if String.starts_with?(reply, "354"),
        do: receive_data(socket, config, txn),
        else: {:continue, txn}
    end
  end

  defp handle_command("RSET", _arg, socket, config, txn) do
    send_reply(
      socket,
      respond(config, :rset, nil, "250 2.0.0 OK"),
      new_transaction(txn.helo, txn)
    )
  end

  defp handle_command("NOOP", _arg, socket, config, txn) do
    send_reply(socket, respond(config, :noop, nil, "250 2.0.0 OK"), txn)
  end

  defp handle_command("QUIT", _arg, socket, config, _txn) do
    _ = reply(socket, respond(config, :quit, nil, "221 2.0.0 Bye"))
    :stop
  end

  defp handle_command("XFORWARD", arg, socket, config, txn) do
    if Enum.any?(config.extensions, &String.starts_with?(&1, "XFORWARD")),
      do: send_reply(socket, "250 2.0.0 Ok", %{txn | xforward: txn.xforward ++ [arg]}),
      else: send_reply(socket, "500 5.5.2 Command not recognized", txn)
  end

  defp handle_command(_verb, _arg, socket, _config, txn) do
    send_reply(socket, "500 5.5.2 Command not recognized", txn)
  end

  defp check_auth(socket, config, txn, message) do
    [_authzid, user, password] = String.split(message, <<0>>)

    if Map.get(config.auth, user) == password do
      send_reply(socket, respond(config, :auth, user, "235 2.7.0 Authentication successful"), %{
        txn
        | auth: user
      })
    else
      send_reply(socket, "535 5.7.8 Authentication credentials invalid", txn)
    end
  end

  defp receive_data(socket, config, txn, acc \\ []) do
    case recv(socket) do
      {:ok, ".\r\n"} ->
        data = acc |> Enum.reverse() |> IO.iodata_to_binary()

        if config.lmtp,
          do: lmtp_data_end(socket, config, txn, data),
          else: data_end(socket, config, txn, data)

      {:ok, <<".", rest::binary>>} ->
        receive_data(socket, config, txn, [rest | acc])

      {:ok, line} ->
        receive_data(socket, config, txn, [line | acc])

      {:error, _} ->
        :stop
    end
  end

  defp data_end(socket, config, txn, data) do
    reply = respond(config, :data_end, data, "250 2.0.0 OK queued")
    if positive?(reply), do: report(config, Map.put(txn, :data, data))
    send_reply(socket, reply, new_transaction(txn.helo, txn))
  end

  # One reply per accepted recipient (RFC 2033 §4.2).
  defp lmtp_data_end(socket, config, txn, data) do
    replies = Enum.map(txn.rcpt_to, &{&1, respond(config, :lmtp_data_end, &1, "250 2.0.0 OK")})
    delivered = for {rcpt, reply} <- replies, positive?(reply), do: rcpt

    if delivered != [],
      do: report(config, txn |> Map.put(:data, data) |> Map.put(:delivered, delivered))

    Enum.reduce_while(replies, {:continue, txn}, fn {_rcpt, reply}, _ ->
      case send_reply(socket, reply, new_transaction(txn.helo, txn)) do
        {:continue, txn} -> {:cont, {:continue, txn}}
        :stop -> {:halt, :stop}
      end
    end)
  end

  defp report(config, message),
    do: send(config.owner, {:fake_mta, config.server, {:message, message}})

  ## Helpers

  defp respond(config, stage, arg, default) do
    case Map.get(config.responses, stage, default) do
      fun when is_function(fun, 1) -> fun.(arg)
      reply -> reply
    end
  end

  defp send_reply(_socket, :close, _txn), do: :stop

  defp send_reply(socket, reply, txn) do
    case reply(socket, reply) do
      :ok -> {:continue, txn}
      _ -> :stop
    end
  end

  defp reply(_socket, :close), do: :close
  defp reply(socket, reply), do: io_send(socket, [reply, "\r\n"])

  defp recv({transport, raw}), do: transport.recv(raw, 0, @recv_timeout)
  defp io_send({transport, raw}, data), do: transport.send(raw, data)
  defp io_close({transport, raw}), do: transport.close(raw)

  defp positive?(reply), do: is_binary(reply) and String.starts_with?(reply, "2")

  defp ehlo_line({line, index}, count) when index == count, do: "250 " <> line
  defp ehlo_line({line, _index}, _count), do: "250-" <> line

  defp split_command(line) do
    case :binary.split(line, " ") do
      [verb, arg] -> {String.upcase(verb), arg}
      [verb] -> {String.upcase(verb), ""}
    end
  end

  # "FROM:<a@b> SIZE=10" -> "a@b"
  defp extract_path(arg, prefix) do
    size = byte_size(prefix)

    case arg do
      <<p::binary-size(^size), rest::binary>> ->
        if String.upcase(p) == prefix, do: strip_brackets(rest), else: arg

      _ ->
        arg
    end
  end

  defp strip_brackets(rest) do
    case Regex.run(~r/^\s*<([^>]*)>/, rest) do
      [_, path] -> path
      nil -> rest |> String.split(" ", parts: 2) |> hd()
    end
  end
end
