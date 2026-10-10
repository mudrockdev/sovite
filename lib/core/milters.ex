defmodule Sovite.Core.Milters do
  @moduledoc """
  The mail filters (`[[milter]]`) of an SMTP session, such as Rspamd,
  OpenDKIM, OpenDMARC, or ClamAV-milter, run with `Sovite.Milter` as
  Postfix runs `smtpd_milters`.

  Each milter of the listener (`listener.milters`, by default all of
  them except on LMTP and re-injection listeners) gets its own
  connection when the client connects, and sees every step of the
  session: the client, `EHLO`, `MAIL`, each `RCPT`, then the header
  fields and body of the message as they arrive. Milters run in order;
  the first that rejects decides. Each sees the message as received.

  Replies:

    * reject: `550 5.7.1 Command rejected`; temporary failure: `451
      4.7.1 Service unavailable - try again later`; or the milter's own
      reply. At `RCPT`, for that recipient only.
    * discard: the message is accepted and dropped.
    * quarantine: the message goes to the hold queue.
    * shutdown: `421` and the session closes.

  At the end of the message, the milters' changes are applied in order:
  header fields added, inserted, changed, or deleted, recipients added
  or removed, the sender changed, and the body replaced. The message is
  then written again (`Sovite.Queue.Spool.replace/3`).

  A milter that cannot be reached, times out, or breaks the protocol
  gets its `default_action`: `tempfail` (the default) answers every
  later command of the session with `451 4.7.1`, `reject` with `550
  5.7.1`, and `accept` goes on without it.

  ## Macros

  Milters get the macros Postfix sends by default: `j`, `{daemon_name}`,
  `{daemon_addr}`, `v`, `_`, `{client_addr}`, `{client_name}`,
  `{client_port}`, `{client_ptr}` at connect; `{tls_version}`,
  `{cipher}`, `{cipher_bits}` at `EHLO`; `i`, `{auth_type}`,
  `{auth_authen}`, `{mail_addr}`, `{mail_host}`, `{mail_mailer}` at
  `MAIL`; `{rcpt_addr}`, `{rcpt_host}`, `{rcpt_mailer}` at `RCPT`; and
  `i` with the data, the end of the header, and the end of the message.
  `i` is the queue ID.
  """

  require Logger

  alias Sovite.Milter
  alias Sovite.SMTP.Reply

  @version Mix.Project.config()[:version]

  @typedoc "One milter of the session."
  @type milter :: %{
          config: map(),
          client: Milter.t() | nil,
          failed: nil | :tempfail | :reject
        }

  @typedoc "The milters of a session: `nil` when the listener has none."
  @type t :: [milter()] | nil

  @typedoc """
  What the SMTP handler knows, for the macros: `:hostname`,
  `:connection`, `:client_dns`, `:tls`, `:identity`, `:mechanism`,
  `:queue_id`.
  """
  @type info :: map()

  @typedoc "The outcome of a step."
  @type result :: {:ok, t()} | {:reply, Reply.t(), t()} | {:close, Reply.t(), t()}

  @typedoc """
  The outcome of the end of the message: what to do with it, and the
  changes to make.
  """
  @type verdict ::
          :ok | {:reject, Reply.t()} | {:discard, String.t()} | {:hold, String.t()}

  @doc "The `[[milter]]` sections a listener uses, by name, in order."
  @spec opts(Sovite.Core.Config.t(), [String.t()]) :: [map()]
  def opts(config, names), do: Enum.filter(config.milter, &(&1.name in names))

  @doc """
  Connects to the milters and tells them about the client. Returns
  `{:close, reply, milters}` when one refuses it.
  """
  @spec connect([map()], info()) :: result()
  def connect([], _info), do: {:ok, nil}

  def connect(configs, info) do
    milters = Enum.map(configs, &open/1)
    {client_name, _ptr} = names(info.client_dns)
    connection = info.connection

    client =
      case connection do
        %{remote_ip: ip, remote_port: port} -> {ip, port}
        %{remote_ip: ip} -> {ip, 0}
      end

    case run(
           milters,
           :connect,
           &Milter.connect_info(&1, client_name, client, connect_macros(info))
         ) do
      {:reply, reply, milters} -> {:close, session_reply(reply), milters}
      other -> other
    end
  end

  defp open(config) do
    opts = [
      name: config.name,
      connect_timeout: config.connect_timeout,
      command_timeout: config.command_timeout,
      content_timeout: config.content_timeout
    ]

    case Milter.connect(config.address.address, opts) do
      {:ok, client} -> %{config: config, client: client, failed: nil}
      {:error, reason} -> failed(%{config: config, client: nil, failed: nil}, reason)
    end
  end

  # A refusal at connect ends the session.
  defp session_reply(%Reply{code: code} = reply) when code in 400..499,
    do: %{reply | code: 421}

  defp session_reply(reply), do: reply

  @doc "`EHLO` or `HELO`."
  @spec helo(t(), String.t(), info()) :: result()
  def helo(nil, _name, _info), do: {:ok, nil}

  def helo(milters, name, info) do
    tls = info.tls

    macros =
      if tls,
        do: [
          {"{tls_version}", tls.protocol},
          {"{cipher}", tls.cipher},
          {"{cipher_bits}", to_string(tls[:bits] || "")}
        ],
        else: []

    run(milters, :helo, &Milter.helo(&1, name, macros))
  end

  @doc "`MAIL FROM`."
  @spec mail(t(), String.t(), map(), info()) :: result()
  def mail(nil, _sender, _params, _info), do: {:ok, nil}

  def mail(milters, sender, params, info) do
    args =
      Enum.reject(
        [
          params[:size] && "SIZE=#{params.size}",
          params[:body] == :"8bitmime" && "BODY=8BITMIME",
          params[:body] == :"7bit" && "BODY=7BIT",
          params[:requiretls] && "REQUIRETLS"
        ],
        &(&1 in [nil, false])
      )

    macros =
      [
        {"i", info.queue_id || ""},
        {"{mail_addr}", sender},
        {"{mail_host}", domain(sender)},
        {"{mail_mailer}", "smtp"}
      ] ++
        if info.identity,
          do: [{"{auth_type}", info.mechanism || ""}, {"{auth_authen}", info.identity}],
          else: []

    run(milters, :mail, &Milter.mail(&1, sender, args, macros))
  end

  @doc "`RCPT TO`. A rejection is about this recipient only."
  @spec rcpt(t(), String.t()) :: result()
  def rcpt(nil, _recipient), do: {:ok, nil}

  def rcpt(milters, recipient) do
    macros = [
      {"{rcpt_addr}", recipient},
      {"{rcpt_host}", domain(recipient)},
      {"{rcpt_mailer}", "smtp"}
    ]

    run(milters, :rcpt, &Milter.rcpt(&1, recipient, [], macros))
  end

  @doc "`DATA`."
  @spec data(t(), info()) :: result()
  def data(nil, _info), do: {:ok, nil}
  def data(milters, info), do: run(milters, :data, &Milter.data(&1, [{"i", info.queue_id}]))

  @doc """
  The header fields of the message (`Sovite.Message.Headers` fields,
  `Received:` first), then the end of the header.
  """
  @spec header(t(), [Sovite.Message.Headers.field()], info()) :: result()
  def header(nil, _fields, _info), do: {:ok, nil}

  def header(milters, fields, info) do
    pairs = fields |> Enum.map(&Milter.Headers.name_value/1) |> Enum.reject(&is_nil/1)

    run(milters, :header, fn client ->
      case send_headers(client, pairs) do
        {:ok, :continue, client} -> Milter.end_of_headers(client, [{"i", info.queue_id}])
        other -> other
      end
    end)
  end

  defp send_headers(client, pairs) do
    Enum.reduce_while(pairs, {:ok, :continue, client}, fn {name, value}, {:ok, _reply, client} ->
      case Milter.header(client, name, value) do
        {:ok, :continue, client} -> {:cont, {:ok, :continue, client}}
        other -> {:halt, other}
      end
    end)
  end

  @doc "A part of the body."
  @spec body(t(), iodata()) :: result()
  def body(nil, _chunk), do: {:ok, nil}
  def body(milters, chunk), do: run(milters, :body, &Milter.body(&1, chunk))

  @doc """
  The end of the message. Returns the verdict and the changes the
  milters asked for, in order.
  """
  @spec end_of_message(t(), info()) :: {verdict(), [Milter.modification()], t()}
  def end_of_message(nil, _info), do: {:ok, [], nil}

  def end_of_message(milters, info) do
    macros = [{"i", info.queue_id}]

    {milters, {verdict, modifications}} =
      Enum.map_reduce(milters, {:ok, []}, &finish(&1, &2, macros))

    {verdict, modifications, milters}
  end

  # After a rejection or a discard, the other milters are not asked.
  defp finish(milter, {verdict, _modifications} = acc, _macros)
       when elem(verdict, 0) in [:reject, :discard],
       do: {milter, acc}

  defp finish(milter, {verdict, modifications}, macros) do
    case end_of_message_result(milter, macros) do
      {{:ok, new}, milter} ->
        {quarantine, new} = Enum.split_with(new, &match?({:quarantine, _}, &1))

        verdict =
          case quarantine do
            [{:quarantine, reason} | _] when verdict == :ok ->
              {:hold, "quarantined by milter: #{reason}"}

            _ ->
              verdict
          end

        {milter, {verdict, modifications ++ new}}

      {stop, milter} ->
        {milter, {stop, []}}
    end
  end

  defp end_of_message_result(%{failed: failed} = milter, _macros) when failed != nil,
    do: {{:reject, failure_reply(failed)}, milter}

  defp end_of_message_result(%{client: nil} = milter, _macros), do: {{:ok, []}, milter}

  defp end_of_message_result(milter, macros) do
    case Milter.end_of_message(milter.client, macros) do
      {:ok, reply, modifications, client} ->
        milter = %{milter | client: client}

        case reply do
          reply when reply in [:continue, :accept] -> {{:ok, modifications}, milter}
          :discard -> {{:discard, "discarded by milter #{milter.config.name}"}, milter}
          :shutdown -> {{:reject, shutdown_reply()}, milter}
          reply -> {{:reject, reply(reply)}, milter}
        end

      {:error, reason} ->
        case failed(milter, reason) do
          %{failed: nil} = milter -> {{:ok, []}, milter}
          milter -> {{:reject, failure_reply(milter.failed)}, milter}
        end
    end
  end

  @doc """
  The transaction ended without a message (`RSET`, or an aborted
  message): the milters forget it.
  """
  @spec abort(t()) :: t()
  def abort(nil), do: nil

  def abort(milters) do
    Enum.map(milters, fn
      %{client: nil} = milter ->
        milter

      milter ->
        case Milter.abort(milter.client) do
          {:ok, client} -> %{milter | client: client}
          {:error, reason} -> failed(milter, reason)
        end
    end)
  end

  @doc "The session ended."
  @spec close(t()) :: :ok
  def close(nil), do: :ok

  def close(milters) do
    for %{client: client} <- milters, client != nil, do: Milter.quit(client)
    :ok
  end

  # Runs a step on each milter in order, until one does not continue.
  defp run(milters, stage, fun) do
    {result, done, rest} = run_each(milters, stage, fun, [])

    milters = Enum.reverse(done, rest)

    case result do
      :ok -> {:ok, milters}
      {:reply, reply} -> {:reply, reply, milters}
      {:close, reply} -> {:close, reply, milters}
    end
  end

  defp run_each([], _stage, _fun, done), do: {:ok, done, []}

  defp run_each([%{failed: failed} = milter | rest], _stage, _fun, done) when failed != nil,
    do: {{:reply, failure_reply(failed)}, [milter | done], rest}

  defp run_each([%{client: nil} = milter | rest], stage, fun, done),
    do: run_each(rest, stage, fun, [milter | done])

  defp run_each([milter | rest], stage, fun, done) do
    case fun.(milter.client) do
      {:ok, reply, client} ->
        milter = %{milter | client: client}

        case reply do
          reply when reply in [:continue, :accept, :discard] ->
            run_each(rest, stage, fun, [milter | done])

          :shutdown ->
            {{:close, shutdown_reply()}, [milter | done], rest}

          reply ->
            {{:reply, reply(reply)}, [milter | done], rest}
        end

      {:error, reason} ->
        case failed(milter, reason) do
          %{failed: nil} = milter -> run_each(rest, stage, fun, [milter | done])
          milter -> {{:reply, failure_reply(milter.failed)}, [milter | done], rest}
        end
    end
  end

  # The milter is gone: its default action applies from now on.
  defp failed(milter, reason) do
    Logger.error("milter #{milter.config.name} failed: #{inspect(reason)}")
    if milter.client, do: Milter.close(milter.client)

    case milter.config.default_action do
      :accept -> %{milter | client: nil, failed: nil}
      action -> %{milter | client: nil, failed: action}
    end
  end

  defp reply(:reject), do: failure_reply(:reject)
  defp reply(:tempfail), do: failure_reply(:tempfail)
  defp reply({:reply, code, enhanced, text}), do: Reply.new(code, enhanced, text)

  defp failure_reply(:reject), do: Reply.new(550, "5.7.1", "Command rejected")

  defp failure_reply(:tempfail),
    do: Reply.new(451, "4.7.1", "Service unavailable - try again later")

  defp shutdown_reply,
    do: Reply.new(421, "4.7.0", "Service unavailable - closing connection")

  defp connect_macros(info) do
    connection = info.connection
    ip = connection.remote_ip |> :inet.ntoa() |> to_string()
    {client_name, ptr} = names(info.client_dns)

    [
      {"j", info.hostname},
      {"{daemon_name}", Map.get(connection, :listener, "smtpd")},
      {"{daemon_addr}",
       connection |> Map.get(:local_ip, {0, 0, 0, 0}) |> :inet.ntoa() |> to_string()},
      {"v", "Sovite #{@version}"},
      {"_", "#{client_name} [#{ip}]"},
      {"{client_addr}", ip},
      {"{client_name}", client_name},
      {"{client_port}", to_string(Map.get(connection, :remote_port, 0))},
      {"{client_ptr}", ptr}
    ]
  end

  defp names({:ok, name}), do: {name, name}
  defp names({:unconfirmed, [name | _]}), do: {"unknown", name}
  defp names(_client_dns), do: {"unknown", "unknown"}

  defp domain(address) do
    case String.split(address, "@") do
      [_no_domain] -> ""
      parts -> List.last(parts)
    end
  end
end
