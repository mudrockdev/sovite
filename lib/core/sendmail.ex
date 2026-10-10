defmodule Sovite.Core.Sendmail do
  @moduledoc """
  The `sendmail(1)`, `mailq(1)`, and `newaliases(1)` commands, for local
  programs and cron jobs that expect them.

  Releases ship `bin/sendmail`, `bin/mailq`, and `bin/newaliases`
  wrappers that run `main/1` with `bin/sovite eval`; link them where
  programs look for them (`/usr/sbin/sendmail`, `/usr/bin/mailq`,
  `/usr/bin/newaliases`).

      sendmail [options] [recipient ...] < message
      sendmail -t [options] < message
      mailq                                       # sendmail -bp
      newaliases                                  # sendmail -bi

  ## Sending

  The message is read from standard input and sent over SMTP to
  `sendmail.server` (`[127.0.0.1]:25` by default), a listener that must
  accept mail from this host: put `127.0.0.1` in `smtp.trusted_networks`
  to let local programs send to other domains. The command waits for the
  server to queue the message, so its exit status says whether that
  worked: `0`, `75` (`EX_TEMPFAIL`) when the server is down or refused
  for now, `69` (`EX_UNAVAILABLE`) when it refused for good, `65`
  (`EX_DATAERR`) without recipients, `64` (`EX_USAGE`) for bad options.
  Recipients the server refused while it took the message for others are
  reported on standard error.

  Addresses without a domain get `@` and `sendmail.origin` (by default
  `server.hostname`). The sender is `-f`, or the user running the command
  (`$USER` or `$LOGNAME`) at that domain. A missing `From:`, `Date:`, or
  `Message-ID:` is added, and `Bcc:` is removed.

  Options:

    * `-t` - also send to the addresses in `To:`, `Cc:`, and `Bcc:`.
    * `-f sender`, `-r sender` - the envelope sender. `-f <>` is the null
      sender.
    * `-F name` - the full name for an added `From:`.
    * `-i`, `-oi` - a line with a single `.` does not end the message.
    * `-C path` - the config file. Without it, `$SOVITE_CONFIG` or
      `/etc/sovite/sovite.toml`; when it cannot be read (it holds
      secrets, so it usually is not readable by everyone), the defaults
      above apply.
    * `-bm` - send a message (the default); `-bp` - list the queue;
      `-bi` - rebuild the aliases database.
    * `-q` - accepted for compatibility; the queue runs on its own.
    * `-B`, `-N`, `-R`, `-V`, `-X`, `-L`, `-h`, `-v`, `-n`, `-G`, `-U`,
      and other `-o` options are accepted and ignored.

  `-bs`, `-bv`, `-bd`, and `-bD` are not supported.

  ## mailq

  Lists the messages in the queue as Postfix does: queue ID (`*` while
  being delivered, `!` when held), size, arrival time, sender, and the
  recipients still to be delivered with the reason of the last failure.
  It reads the queue directory, so it must run as root or the user
  Sovite runs as.

  ## newaliases

  Sovite keeps aliases in its database (`sovitectl alias`), so there is
  nothing to rebuild: it prints a note and succeeds, so scripts that call
  it keep working. See `sovitectl migrate postfix` to import
  `/etc/aliases`.
  """

  alias Sovite.Core.Config
  alias Sovite.Message.{AddressList, Date, Headers, MessageID}
  alias Sovite.Queue.{Entry, Spool}
  alias Sovite.SMTP.{Client, Reply}

  @ex_usage 64
  @ex_dataerr 65
  @ex_unavailable 69
  @ex_tempfail 75

  # Header sections larger than this are sent as they are.
  @max_header 1024 * 1024

  # Options that take an argument, attached or as the next word.
  @with_argument ~w(f r F C B N R V X L h o)

  @doc "Runs the command in `argv` and halts the VM with its exit status."
  @spec main([String.t()]) :: no_return()
  def main(argv), do: argv |> run() |> System.halt()

  @doc """
  Runs the command in `argv` and returns its exit status. Options:
  `:input` (an IO device for the message, standard input by default),
  `:env` (a map of environment variables, for the user name).
  """
  @spec run([String.t()], keyword()) :: non_neg_integer()
  def run(argv, opts \\ []) do
    case parse(argv, %{mode: :send, extract: false, dots: true, recipients: []}) do
      {:ok, options} -> execute(options, opts)
      {:error, message} -> usage(message)
    end
  end

  defp usage(message) do
    IO.puts(:stderr, "sendmail: #{message}")
    @ex_usage
  end

  ## Options

  defp parse([], options), do: {:ok, %{options | recipients: Enum.reverse(options.recipients)}}

  defp parse(["--" | rest], options),
    do: parse([], %{options | recipients: Enum.reverse(rest, options.recipients)})

  defp parse(["-" <> <<flag::binary-size(1)>> | rest], options) when flag in @with_argument do
    case rest do
      [value | rest] -> parse(rest, option(flag, value, options))
      [] -> {:error, "option -#{flag} needs a value"}
    end
  end

  defp parse(["-" <> <<flag::binary-size(1), value::binary>> | rest], options)
       when flag in @with_argument,
       do: parse(rest, option(flag, value, options))

  defp parse(["-b" <> mode | rest], options) do
    case mode do
      "m" -> parse(rest, %{options | mode: :send})
      "p" -> parse(rest, %{options | mode: :mailq})
      "i" -> parse(rest, %{options | mode: :newaliases})
      _ -> {:error, "-b#{mode} is not supported"}
    end
  end

  defp parse(["-t" | rest], options), do: parse(rest, %{options | extract: true})
  defp parse(["-i" | rest], options), do: parse(rest, %{options | dots: false})
  defp parse(["-q" <> _ | rest], options), do: parse(rest, Map.put(options, :mode, :queue_run))

  defp parse(["-" <> flag | rest], options) when flag in ~w(v n G U Am Ac),
    do: parse(rest, options)

  defp parse(["-" <> flag | _rest], _options) when flag != "",
    do: {:error, "unknown option -#{flag}"}

  defp parse([recipient | rest], options),
    do: parse(rest, %{options | recipients: [recipient | options.recipients]})

  defp option(flag, value, options) when flag in ["f", "r"], do: Map.put(options, :sender, value)
  defp option("F", value, options), do: Map.put(options, :full_name, value)
  defp option("C", value, options), do: Map.put(options, :config, value)
  defp option("o", "i", options), do: %{options | dots: false}
  defp option(_flag, _value, options), do: options

  ## Commands

  defp execute(%{mode: :newaliases}, _opts) do
    IO.puts(
      :stderr,
      "newaliases: Sovite keeps aliases in its database (see sovitectl alias); nothing to rebuild"
    )

    0
  end

  defp execute(%{mode: :queue_run}, _opts) do
    IO.puts(:stderr, "sendmail: Sovite runs its queue on its own; -q does nothing")
    0
  end

  defp execute(%{mode: :mailq} = options, _opts) do
    case Config.load(options[:config] || Config.default_path()) do
      {:ok, config} ->
        mailq(config.queue.directory)

      {:error, errors} ->
        for error <- errors, do: IO.puts(:stderr, "mailq: " <> Exception.message(error))
        @ex_unavailable
    end
  end

  defp execute(%{mode: :send} = options, opts) do
    settings = settings(options)
    env = Keyword.get_lazy(opts, :env, &System.get_env/0)
    input = Keyword.get(opts, :input, :stdio)
    # Raw bytes: messages need not be UTF-8.
    _ = :io.setopts(input, binary: true, encoding: :latin1)

    {header, body} = read_message(input, options.dots)
    fields = Headers.parse(header)
    origin = settings.origin
    user = env["USER"] || env["LOGNAME"] || "root"
    sender = sender(options[:sender], user, origin)

    recipients =
      (options.recipients ++ if(options.extract, do: header_recipients(fields), else: []))
      |> Enum.map(&qualify(&1, origin))
      |> Enum.uniq_by(&String.downcase/1)

    if recipients == [] do
      IO.puts(:stderr, "sendmail: no recipients")
      @ex_dataerr
    else
      fields = fix_header(fields, sender, user, options[:full_name], origin)
      message = Stream.concat([[Headers.encode(fields), "\r\n"]], body)
      submit(settings, sender, recipients, message)
    end
  end

  # The [sendmail] settings, or the defaults when the config cannot be read.
  defp settings(options) do
    path = options[:config] || Config.default_path()

    case File.read(path) do
      {:ok, contents} ->
        case Config.parse(contents) do
          {:ok, config} ->
            %{
              server: config.sendmail.server,
              origin: config.sendmail.origin || config.server.hostname,
              hostname: config.server.hostname
            }

          {:error, _errors} ->
            defaults()
        end

      {:error, _reason} ->
        defaults()
    end
  end

  defp defaults do
    hostname = Config.system_hostname()
    %{server: %{host: "[127.0.0.1]", port: 25, mx: false}, origin: hostname, hostname: hostname}
  end

  defp sender(nil, user, origin), do: qualify(user, origin)
  defp sender(sender, _user, _origin) when sender in ["<>", ""], do: ""

  defp sender(sender, _user, origin),
    do: sender |> String.trim("<") |> String.trim(">") |> qualify(origin)

  defp qualify(address, origin) do
    address = address |> String.trim() |> String.trim_leading("<") |> String.trim_trailing(">")
    if String.contains?(address, "@"), do: address, else: address <> "@" <> origin
  end

  ## The message

  # The header section, and the rest as a stream of CRLF lines.
  defp read_message(input, dots) do
    {header, first} = read_header(input, dots, [], 0)
    {header, Stream.concat(first, body_stream(input, dots))}
  end

  defp read_header(input, dots, acc, size) do
    header = fn -> acc |> Enum.reverse() |> IO.iodata_to_binary() end

    case next_line(input, dots) do
      :eof ->
        {header.(), []}

      {:ok, "\r\n"} ->
        {header.(), []}

      {:ok, line} when size + byte_size(line) > @max_header ->
        {header.(), [line]}

      {:ok, line} ->
        if header_line?(line),
          do: read_header(input, dots, [line | acc], size + byte_size(line)),
          # No blank line between the header and the body.
          else: {header.(), [line]}
    end
  end

  defp body_stream(input, dots) do
    Stream.unfold(:reading, fn
      :done ->
        nil

      :reading ->
        case next_line(input, dots) do
          {:ok, line} -> {line, :reading}
          :eof -> nil
        end
    end)
  end

  # Lines end in CRLF, whatever they ended in. Without -i, a line with a
  # single dot ends the message.
  defp next_line(input, dots) do
    case IO.binread(input, :line) do
      data when is_binary(data) ->
        line = data |> String.trim_trailing("\n") |> String.trim_trailing("\r")
        if dots and line == ".", do: :eof, else: {:ok, line <> "\r\n"}

      _eof_or_error ->
        :eof
    end
  end

  # A field, or the continuation of one.
  defp header_line?(<<c, _::binary>>) when c in [?\s, ?\t], do: true
  defp header_line?(line), do: line =~ ~r/\A[\x21-\x39\x3b-\x7e]+:/

  defp header_recipients(fields) do
    for {name, raw} <- fields,
        name in ["to", "cc", "bcc"],
        [_name, value] = :binary.split(raw, ":"),
        {:ok, addresses} = AddressList.addresses(value),
        address <- addresses,
        do: address
  end

  defp fix_header(fields, sender, user, full_name, origin) do
    fields = Headers.delete(fields, ["bcc"])

    fields =
      if Headers.has?(fields, "from") do
        fields
      else
        from = if sender == "", do: qualify(user, origin), else: sender
        name = full_name && ~s("#{String.replace(full_name, ~s("), "")}" )
        Headers.append(fields, "From", "#{name}<#{from}>")
      end

    fields =
      if Headers.has?(fields, "date"),
        do: fields,
        else: Headers.append(fields, "Date", Date.format(DateTime.utc_now()))

    if Headers.has?(fields, "message-id"),
      do: fields,
      else: Headers.append(fields, "Message-ID", MessageID.generate(origin))
  end

  ## Submission

  defp submit(settings, sender, recipients, message) do
    with {:ok, address} <- server_address(settings.server.host),
         {:ok, client} <-
           Client.connect(address, settings.server.port,
             helo: settings.hostname,
             connect_timeout: 30_000
           ) do
      result = Client.deliver(client, sender, recipients, message)
      Client.quit(client)
      report(result)
    else
      {:error, reason} ->
        IO.puts(
          :stderr,
          "sendmail: cannot send to #{server_name(settings.server)}: #{inspect(reason)}"
        )

        @ex_tempfail
    end
  end

  defp server_address("[" <> literal) do
    literal = literal |> String.trim_trailing("]") |> String.replace_prefix("IPv6:", "")

    case Sovite.Net.parse_ip(literal) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> resolve(literal)
    end
  end

  defp server_address(host), do: resolve(host)

  defp resolve(host) do
    case :inet.getaddr(String.to_charlist(host), :inet) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> :inet.getaddr(String.to_charlist(host), :inet6)
    end
  end

  defp server_name(%{host: host, port: port}), do: "#{host}:#{port}"

  defp report({:ok, _client, results}) do
    {accepted, refused} =
      Enum.split_with(results, fn {_rcpt, stage, reply} ->
        stage == :data_end and Reply.positive?(reply)
      end)

    for {rcpt, _stage, reply} <- refused,
        do: IO.puts(:stderr, "sendmail: #{rcpt}: #{Reply.to_string(reply)}")

    cond do
      accepted != [] -> 0
      Enum.any?(refused, fn {_rcpt, _stage, reply} -> reply.code < 500 end) -> @ex_tempfail
      true -> @ex_unavailable
    end
  end

  defp report({:error, _client, refusal}) do
    IO.puts(:stderr, "sendmail: message refused: #{inspect(refusal)}")
    @ex_unavailable
  end

  defp report({:error, {stage, reason}}) do
    IO.puts(:stderr, "sendmail: lost connection at #{stage}: #{inspect(reason)}")
    @ex_tempfail
  end

  ## mailq

  @doc """
  Prints the queue in `directory` as Postfix's `mailq` does. Returns the
  exit status.
  """
  @spec mailq(Path.t()) :: non_neg_integer()
  def mailq(directory) do
    messages =
      for {queue, mark} <- [incoming: "", active: "*", deferred: "", hold: "!"],
          {:ok, ids} <- [Spool.list(directory, queue)],
          id <- ids,
          {:ok, loaded} <- [Spool.load(Spool.path(directory, queue, id))],
          do: {mark, loaded}

    if messages == [] do
      IO.puts("Mail queue is empty")
    else
      IO.puts("-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------")
      Enum.each(Enum.sort_by(messages, &arrival(elem(&1, 1)), DateTime), &print_message/1)
      kbytes = messages |> Enum.map(&elem(&1, 1).message_size) |> Enum.sum() |> div(1024)
      count = length(messages)
      IO.puts("-- #{kbytes} Kbytes in #{count} Request#{if count == 1, do: "", else: "s"}.")
    end

    0
  end

  defp arrival(loaded), do: loaded.envelope.received_at || ~U[1970-01-01 00:00:00Z]

  defp print_message({mark, loaded}) do
    envelope = loaded.envelope
    entry = Entry.new(envelope, loaded.records)
    sender = if envelope.sender == "", do: "MAILER-DAEMON", else: envelope.sender
    time = Calendar.strftime(arrival(loaded), "%a %b %d %H:%M:%S")

    IO.puts(
      String.pad_trailing(envelope.queue_id <> mark, 12) <>
        String.pad_leading(Integer.to_string(loaded.message_size), 8) <>
        " " <> time <> "  " <> sender
    )

    entry
    |> Entry.pending()
    |> Enum.group_by(&reason(entry.recipients[&1].details))
    |> Enum.sort_by(fn {reason, _recipients} -> {reason == nil, reason} end)
    |> Enum.each(fn {reason, recipients} ->
      if reason, do: IO.puts(String.duplicate(" ", 41) <> "(#{reason})")
      for rcpt <- recipients, do: IO.puts(String.duplicate(" ", 41) <> rcpt)
    end)

    IO.puts("")
  end

  defp reason(nil), do: nil
  defp reason(details), do: details.reply
end
