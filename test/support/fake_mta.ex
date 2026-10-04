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
    {:ok, listen} =
      :gen_tcp.listen(0, [
        :binary,
        ip: {127, 0, 0, 1},
        active: false,
        packet: :line,
        buffer: 65_536,
        reuseaddr: true
      ])

    {:ok, port} = :inet.port(listen)

    config = %{
      owner: Keyword.fetch!(opts, :owner),
      server: self(),
      hostname: Keyword.get(opts, :hostname, "fake-mta.test"),
      extensions: Keyword.get(opts, :extensions, @default_extensions),
      responses: Keyword.get(opts, :responses, %{})
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
        pid = spawn_link(fn -> serve(socket, config) end)
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

    greeting = respond(config, :greeting, nil, "220 #{config.hostname} ESMTP fake")

    if reply(socket, greeting) == :ok do
      session(socket, config, new_transaction(nil))
    end
  end

  defp new_transaction(helo), do: %{helo: helo, mail_from: nil, mail_args: nil, rcpt_to: []}

  defp session(socket, config, txn) do
    case :gen_tcp.recv(socket, 0, @recv_timeout) do
      {:ok, line} ->
        {verb, arg} = split_command(String.trim_trailing(line, "\r\n"))

        case handle_command(verb, arg, socket, config, txn) do
          {:continue, txn} -> session(socket, config, txn)
          :stop -> :gen_tcp.close(socket)
        end

      {:error, _} ->
        :gen_tcp.close(socket)
    end
  end

  defp handle_command("EHLO", arg, socket, config, _txn) do
    lines = [config.hostname | config.extensions]
    default = lines |> Enum.with_index(1) |> Enum.map_join("\r\n", &ehlo_line(&1, length(lines)))
    send_reply(socket, respond(config, :ehlo, arg, default), new_transaction(arg))
  end

  defp handle_command("HELO", arg, socket, config, _txn) do
    send_reply(
      socket,
      respond(config, :helo, arg, "250 #{config.hostname}"),
      new_transaction(arg)
    )
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
    send_reply(socket, respond(config, :rset, nil, "250 2.0.0 OK"), new_transaction(txn.helo))
  end

  defp handle_command("NOOP", _arg, socket, config, txn) do
    send_reply(socket, respond(config, :noop, nil, "250 2.0.0 OK"), txn)
  end

  defp handle_command("QUIT", _arg, socket, config, _txn) do
    _ = reply(socket, respond(config, :quit, nil, "221 2.0.0 Bye"))
    :stop
  end

  defp handle_command(_verb, _arg, socket, _config, txn) do
    send_reply(socket, "500 5.5.2 Command not recognized", txn)
  end

  defp receive_data(socket, config, txn, acc \\ []) do
    case :gen_tcp.recv(socket, 0, @recv_timeout) do
      {:ok, ".\r\n"} ->
        data = acc |> Enum.reverse() |> IO.iodata_to_binary()
        reply = respond(config, :data_end, data, "250 2.0.0 OK queued")

        if positive?(reply) do
          message = Map.put(txn, :data, data)
          send(config.owner, {:fake_mta, config.server, {:message, message}})
        end

        send_reply(socket, reply, new_transaction(txn.helo))

      {:ok, <<".", rest::binary>>} ->
        receive_data(socket, config, txn, [rest | acc])

      {:ok, line} ->
        receive_data(socket, config, txn, [line | acc])

      {:error, _} ->
        :stop
    end
  end

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
  defp reply(socket, reply), do: :gen_tcp.send(socket, [reply, "\r\n"])

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
