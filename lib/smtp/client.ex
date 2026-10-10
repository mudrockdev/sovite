defmodule Sovite.SMTP.Client do
  @moduledoc """
  An SMTP client (RFC 5321) for relaying messages to another server.

      {:ok, client} = Client.connect({192, 0, 2, 25}, 25, helo: "mx.example.com")
      {:ok, client, results} = Client.deliver(client, "a@example.com", ["b@example.net"], body)
      :ok = Client.quit(client)

  `connect/3` reads the greeting and sends `EHLO`, falling back to `HELO`
  when the server rejects `EHLO` with a 5xx reply. One connection can
  carry any number of `deliver/5` transactions.

  With `PIPELINING` (RFC 2920), `MAIL`, every `RCPT`, and `DATA` are sent
  in one batch. `SIZE` (RFC 1870) and `BODY=8BITMIME` (RFC 6152) are sent
  when the server supports them, and `REQUIRETLS` (RFC 8689) when asked
  for. The body is dot-stuffed while streaming
  with `Sovite.SMTP.DataEncoder`.

  Replies are parsed with `Sovite.SMTP.Reply.decode/2`, so a hostile
  server cannot make the client buffer without limit. Every wait has a
  timeout; the defaults are those of RFC 5321 §4.5.3.2.

  `starttls/2` upgrades a connection (RFC 3207) and `authenticate/3`
  logs in with SASL (RFC 4954). With the `:tls` option the connection is
  encrypted from the start instead (implicit TLS, RFC 8314).

  ## LMTP

  With `protocol: :lmtp` the client speaks LMTP (RFC 2033) instead: it
  greets with `LHLO`, and after the data the server answers once for
  each accepted recipient, so every recipient gets its own result at
  `:data_end`. LMTP servers usually listen on a Unix socket: pass
  `{:local, path}` as the address (the port is ignored).

  ## Options

    * `:helo` - name to send in `EHLO`/`HELO` (or `LHLO`). Required.
    * `:protocol` - `:smtp` (default) or `:lmtp`.
    * `:connect_timeout` - milliseconds. Defaults to 30 seconds.
    * `:greeting_timeout` - for the `220` greeting. Defaults to 5 minutes.
    * `:command_timeout` - for `EHLO`, `MAIL`, `RCPT`, `RSET`, and `QUIT`
      replies. Defaults to 5 minutes.
    * `:data_timeout` - for the reply to `DATA`. Defaults to 2 minutes.
    * `:send_timeout` - for each block of message data. Defaults to 3
      minutes.
    * `:data_end_timeout` - for the reply after the final dot. Defaults
      to 10 minutes.
    * `:local_address` - local IP address to connect from. Not used for
      Unix sockets.
    * `:max_line_length` / `:max_lines` - reply limits, see
      `Sovite.SMTP.Reply.decode/2`.
    * `:tls` - `:ssl` client options to use implicit TLS: the handshake
      runs right after connecting, before the greeting.
    * `:tls_timeout` - for TLS handshakes. Defaults to 60 seconds.
  """

  alias Sovite.SASL
  alias Sovite.SMTP.{DataEncoder, Reply}
  alias Sovite.Validators

  @defaults [
    connect_timeout: 30_000,
    greeting_timeout: 300_000,
    command_timeout: 300_000,
    data_timeout: 120_000,
    send_timeout: 180_000,
    data_end_timeout: 600_000,
    local_address: nil,
    max_line_length: 2048,
    max_lines: 100,
    tls: nil,
    tls_timeout: 60_000,
    protocol: :smtp
  ]

  @mechanisms %{
    "SCRAM-SHA-256" => SASL.ScramSHA256,
    "PLAIN" => SASL.Plain,
    "LOGIN" => SASL.Login,
    "OAUTHBEARER" => SASL.OAuthBearer
  }

  @enforce_keys [:socket, :opts]
  defstruct [
    :socket,
    :opts,
    :address,
    :port,
    :greeting,
    :server_name,
    :tls,
    transport: :gen_tcp,
    buffer: <<>>,
    extensions: %{}
  ]

  @opaque t :: %__MODULE__{}

  @typedoc """
  The command a reply or error belongs to. `:data_end` is the final dot:
  after an error there, the server may or may not have accepted the
  message.
  """
  @type stage ::
          :connect
          | :tls
          | :greeting
          | :ehlo
          | :helo
          | :lhlo
          | :starttls
          | :auth
          | :mail
          | :rcpt
          | :data
          | :data_end
          | :rset
          | :quit

  @typedoc """
  A failure that ends the connection. The reason is a rejection reply
  (at `:greeting`, `:ehlo`, `:helo`, or `:lhlo`), `:timeout`, `:closed`, a
  `Sovite.SMTP.Reply.decode_error()`, a socket error, or `{:tls, reason}`
  for a failed TLS handshake (at `:tls` or `:starttls`).
  """
  @type error ::
          {stage(),
           Reply.t() | :timeout | :closed | Reply.decode_error() | {:tls, term()} | atom()}

  @typedoc """
  Why `deliver/5` did not start a transaction. The connection stays
  usable.

    * `{:message_too_large, limit}` - larger than the server's `SIZE`.
    * `:eight_bit_not_supported` - an 8-bit message (`body_type:
      :"8bitmime"`), but the server does not support `8BITMIME`.
    * `{:invalid_address, address}` - not a valid mailbox.
    * `:requiretls_not_supported` - `requiretls: true`, but the
      connection is not encrypted or the server does not offer
      `REQUIRETLS`.
  """
  @type refusal ::
          {:message_too_large, pos_integer()}
          | :eight_bit_not_supported
          | {:invalid_address, String.t()}
          | :requiretls_not_supported

  @typedoc """
  The outcome for one recipient: the reply that decided it, and the
  command it answered. A 2xx reply at `:data_end` means the server took
  the message for this recipient.
  """
  @type result :: {recipient :: String.t(), stage(), Reply.t()}

  @typedoc "Where to connect: an IP address, or a Unix socket."
  @type address :: :inet.ip_address() | {:local, Path.t()}

  @doc "Connects, reads the greeting, and sends `EHLO` (or `HELO`, or `LHLO`)."
  @spec connect(address(), :inet.port_number(), keyword()) ::
          {:ok, t()} | {:error, error()}
  def connect(address, port, opts) do
    opts = Keyword.validate!(opts, [:helo] ++ @defaults)
    helo = Keyword.fetch!(opts, :helo)

    tcp_opts =
      [:binary, active: false, packet: :raw]
      |> Kernel.++(send_timeout: opts[:send_timeout], send_timeout_close: true)
      |> Kernel.++(family_options(address, opts[:local_address]))

    port = if match?({:local, _}, address), do: 0, else: port

    case :gen_tcp.connect(address, port, tcp_opts, opts[:connect_timeout]) do
      {:ok, socket} ->
        client = %__MODULE__{socket: socket, opts: Map.new(opts), address: address, port: port}

        with {:ok, client} <- implicit_tls(client),
             {:ok, client} <- greeting(client),
             {:ok, client} <- hello(client, helo) do
          {:ok, client}
        else
          {:error, _} = error ->
            close(client)
            error
        end

      {:error, reason} ->
        {:error, {:connect, reason}}
    end
  end

  defp family_options({:local, _path}, _local_address), do: [:local]

  defp family_options(address, local_address) do
    [nodelay: true] ++
      if(tuple_size(address) == 8, do: [:inet6], else: []) ++
      if(local_address, do: [ip: local_address], else: [])
  end

  defp implicit_tls(%{opts: %{tls: nil}} = client), do: {:ok, client}
  defp implicit_tls(client), do: handshake(client, client.opts.tls, :tls)

  defp handshake(client, ssl_opts, stage) do
    case :ssl.connect(client.socket, ssl_opts, client.opts.tls_timeout) do
      {:ok, ssl} ->
        {:ok, tls} = Sovite.TLS.info(ssl)
        {:ok, %{client | socket: ssl, transport: :ssl, tls: tls, buffer: <<>>}}

      {:error, reason} ->
        close(client)
        {:error, {stage, {:tls, reason}}}
    end
  end

  @doc """
  Upgrades the connection with `STARTTLS` and sends `EHLO` again, as
  RFC 3207 requires.

  Returns `{:error, client, reason}` when the connection stays usable
  without TLS: `:not_offered` (no `STARTTLS` extension), or
  `{:refused, reply}`. Returns `{:error, {:starttls, reason}}` when it is
  gone, for example after a failed handshake (`{:tls, ssl_reason}`).
  """
  @spec starttls(t(), [:ssl.tls_client_option()]) ::
          {:ok, t()} | {:error, t(), :not_offered | {:refused, Reply.t()}} | {:error, error()}
  def starttls(%__MODULE__{} = client, ssl_opts) do
    cond do
      client.tls != nil ->
        {:error, client, :not_offered}

      not Map.has_key?(client.extensions, "STARTTLS") ->
        {:error, client, :not_offered}

      true ->
        client |> command(:starttls, "STARTTLS") |> after_starttls(ssl_opts)
    end
  end

  defp after_starttls({:ok, %Reply{code: 220}, client}, ssl_opts) do
    # Anything the server sent before the handshake is untrusted.
    with {:ok, client} <- handshake(%{client | buffer: <<>>}, ssl_opts, :starttls) do
      hello(%{client | extensions: %{}, server_name: nil}, client.opts.helo)
    end
  end

  defp after_starttls({:ok, reply, client}, _ssl_opts), do: {:error, client, {:refused, reply}}
  defp after_starttls({:error, _} = error, _ssl_opts), do: error

  @doc "Returns the TLS details if the connection is encrypted, else `nil`."
  @spec tls(t()) :: Sovite.TLS.info() | nil
  def tls(%__MODULE__{tls: tls}), do: tls

  @doc """
  Authenticates with SASL (RFC 4954), using the first of `mechanisms`
  the server offers.

  `credentials` has `:username` and `:password` (or `:token` for
  `OAUTHBEARER`). Mechanisms default to `["SCRAM-SHA-256", "PLAIN",
  "LOGIN"]`. Do not send passwords over an unencrypted connection.

  Returns `{:error, client, reason}` with the connection still usable:
  `:no_mechanism` (none offered in common), `{:rejected, reply}`, or a
  `{:sasl, reason}` from the mechanism (such as a server whose
  `SCRAM-SHA-256` signature is wrong).
  """
  @spec authenticate(t(), map(), [String.t()]) ::
          {:ok, t()} | {:error, t(), term()} | {:error, error()}
  def authenticate(
        %__MODULE__{} = client,
        credentials,
        mechanisms \\ ["SCRAM-SHA-256", "PLAIN", "LOGIN"]
      ) do
    offered =
      client.extensions
      |> Map.get("AUTH", "")
      |> String.upcase(:ascii)
      |> String.split(" ", trim: true)

    case Enum.find(mechanisms, &(&1 in offered and Map.has_key?(@mechanisms, &1))) do
      nil ->
        {:error, client, :no_mechanism}

      name ->
        module = Map.fetch!(@mechanisms, name)
        {:ok, initial, state} = module.client_start(credentials)
        line = ["AUTH ", name] ++ if(initial, do: [" ", encode_initial(initial)], else: [])

        with {:ok, reply, client} <- command(client, :auth, line),
             do: auth_loop(client, module, state, reply)
    end
  end

  defp encode_initial(""), do: "="
  defp encode_initial(data), do: Base.encode64(data)

  defp auth_loop(client, _module, _state, %Reply{code: 235}), do: {:ok, client}

  defp auth_loop(client, module, state, %Reply{code: 334, lines: [text | _]}) do
    result =
      case Base.decode64(String.trim(text)) do
        {:ok, challenge} -> module.client_step(state, challenge)
        :error -> {:error, :malformed_challenge}
      end

    case result do
      {:ok, response, state} ->
        with {:ok, reply, client} <- command(client, :auth, Base.encode64(response)),
             do: auth_loop(client, module, state, reply)

      # Cancel the exchange (RFC 4954 §4) and read the 501.
      {:error, reason} ->
        with {:ok, _reply, client} <- command(client, :auth, "*"),
             do: {:error, client, {:sasl, reason}}
    end
  end

  defp auth_loop(client, _module, _state, reply), do: {:error, client, {:rejected, reply}}

  @doc "Returns the server's address and port."
  @spec peer(t()) :: {address(), :inet.port_number()}
  def peer(%__MODULE__{address: address, port: port}), do: {address, port}

  @doc """
  Returns the name the server gave in its `EHLO`/`HELO` reply, for
  example to detect a connection to itself.
  """
  @spec server_name(t()) :: String.t() | nil
  def server_name(%__MODULE__{server_name: name}), do: name

  @doc """
  Returns the extensions the server announced: upper-cased keywords
  mapped to their parameters (`""` if none).
  """
  @spec extensions(t()) :: %{String.t() => String.t()}
  def extensions(%__MODULE__{extensions: extensions}), do: extensions

  @doc """
  Sends one message to `recipients`.

  `body` is an enumerable of iodata chunks with CRLF line endings, not
  dot-stuffed. Use `sender` `""` for the null reverse-path.

  Returns one result per recipient, in order. The transaction is reset
  when it fails, so the connection can be reused after `{:ok, ...}` and
  `{:error, client, refusal}`.

  ## Options

    * `:size` - the message size in bytes, sent with `SIZE` and checked
      against the server's limit.
    * `:body_type` - `:"7bit"`, `:"8bitmime"`, or `nil` (not declared).
    * `:requiretls` - send `REQUIRETLS`, so the server must relay the
      message only over verified TLS too (RFC 8689). Defaults to `false`.
  """
  @spec deliver(t(), String.t(), [String.t(), ...], Enumerable.t(), keyword()) ::
          {:ok, t(), [result()]} | {:error, t(), refusal()} | {:error, error()}
  def deliver(%__MODULE__{} = client, sender, [_ | _] = recipients, body, opts \\ []) do
    size = Keyword.get(opts, :size)
    body_type = Keyword.get(opts, :body_type)
    requiretls = Keyword.get(opts, :requiretls, false)

    case check(client, sender, recipients, size, body_type, requiretls) do
      :ok ->
        mail = [
          "MAIL FROM:<",
          sender,
          ">",
          mail_params(client, size, body_type),
          if(requiretls, do: " REQUIRETLS", else: [])
        ]

        run_transaction(client, mail, recipients, body)

      {:error, refusal} ->
        {:error, client, refusal}
    end
  end

  @doc "Sends `QUIT` and closes the connection. Errors are ignored."
  @spec quit(t()) :: :ok
  def quit(%__MODULE__{} = client) do
    with :ok <- send_line(client, "QUIT"),
         do: read_reply(client, :quit, min(client.opts.command_timeout, 5_000))

    close(client)
  end

  @doc "Closes the connection without `QUIT`."
  @spec close(t()) :: :ok
  def close(%__MODULE__{transport: transport, socket: socket}) do
    _ = transport.close(socket)
    :ok
  end

  ## Session setup

  defp greeting(client) do
    case read_reply(client, :greeting, client.opts.greeting_timeout) do
      {:ok, %Reply{code: 220} = reply, client} -> {:ok, %{client | greeting: reply}}
      {:ok, reply, _client} -> {:error, {:greeting, reply}}
      {:error, _} = error -> error
    end
  end

  defp hello(%{opts: %{protocol: :lmtp}} = client, name) do
    case command(client, :lhlo, ["LHLO ", name]) do
      {:ok, %Reply{code: 250} = reply, client} ->
        [first | lines] = reply.lines
        {:ok, %{client | server_name: first_word(first), extensions: parse_extensions(lines)}}

      {:ok, reply, _client} ->
        {:error, {:lhlo, reply}}

      {:error, _} = error ->
        error
    end
  end

  defp hello(client, name) do
    case command(client, :ehlo, ["EHLO ", name]) do
      {:ok, %Reply{code: 250} = reply, client} ->
        [first | lines] = reply.lines
        {:ok, %{client | server_name: first_word(first), extensions: parse_extensions(lines)}}

      {:ok, %Reply{code: code}, client} when code >= 500 ->
        helo(client, name)

      {:ok, reply, _client} ->
        {:error, {:ehlo, reply}}

      {:error, _} = error ->
        error
    end
  end

  defp helo(client, name) do
    case command(client, :helo, ["HELO ", name]) do
      {:ok, %Reply{code: 250} = reply, client} ->
        {:ok, %{client | server_name: first_word(hd(reply.lines)), extensions: %{}}}

      {:ok, reply, _client} ->
        {:error, {:helo, reply}}

      {:error, _} = error ->
        error
    end
  end

  defp first_word(line), do: line |> String.split(" ", parts: 2) |> hd()

  defp parse_extensions(lines) do
    Map.new(lines, fn line ->
      case String.split(line, " ", parts: 2) do
        [keyword, params] -> {String.upcase(keyword, :ascii), params}
        [keyword] -> {String.upcase(keyword, :ascii), ""}
      end
    end)
  end

  ## Transactions

  defp check(client, _sender, _recipients, _size, _body_type, true)
       when client.tls == nil or not is_map_key(client.extensions, "REQUIRETLS"),
       do: {:error, :requiretls_not_supported}

  defp check(client, sender, recipients, size, body_type, _requiretls) do
    limit = size_limit(client)

    cond do
      invalid = Enum.find([sender | recipients], &invalid_address?/1) ->
        {:error, {:invalid_address, invalid}}

      limit && size && size > limit ->
        {:error, {:message_too_large, limit}}

      body_type == :"8bitmime" and not Map.has_key?(client.extensions, "8BITMIME") ->
        {:error, :eight_bit_not_supported}

      true ->
        :ok
    end
  end

  defp invalid_address?(""), do: false
  defp invalid_address?(address), do: not Validators.mailbox?(address)

  # A SIZE without a value, or SIZE 0, announces no fixed limit.
  defp size_limit(client) do
    with {:ok, value} <- Map.fetch(client.extensions, "SIZE"),
         {limit, ""} when limit > 0 <- Integer.parse(value) do
      limit
    else
      _ -> nil
    end
  end

  defp mail_params(client, size, body_type) do
    size =
      if size && Map.has_key?(client.extensions, "SIZE"),
        do: [" SIZE=", Integer.to_string(size)],
        else: []

    body =
      if body_type && Map.has_key?(client.extensions, "8BITMIME"),
        do: [" BODY=", if(body_type == :"8bitmime", do: "8BITMIME", else: "7BIT")],
        else: []

    [size, body]
  end

  defp run_transaction(client, mail, recipients, body) do
    if Map.has_key?(client.extensions, "PIPELINING"),
      do: pipelined(client, mail, recipients, body),
      else: sequential(client, mail, recipients, body)
  end

  defp pipelined(client, mail, recipients, body) do
    commands = [mail | Enum.map(recipients, &["RCPT TO:<", &1, ">"])] ++ ["DATA"]
    read_rcpt = &read_reply(&1, :rcpt, &1.opts.command_timeout)

    with :ok <- send_lines(client, commands, :mail),
         {:ok, mail_reply, client} <- read_reply(client, :mail, client.opts.command_timeout),
         {:ok, rcpt_replies, client} <-
           collect(client, recipients, fn client, _rcpt -> read_rcpt.(client) end),
         {:ok, data_reply, client} <- read_reply(client, :data, client.opts.data_timeout) do
      if Reply.positive?(mail_reply),
        do: after_data_reply(client, rcpt_replies, data_reply, body),
        # DATA can only have failed too, so there is no transaction left.
        else: finish_data_if_started(client, data_reply, all(recipients, :mail, mail_reply))
    end
  end

  defp sequential(client, mail, recipients, body) do
    with {:ok, mail_reply, client} <- command(client, :mail, mail) do
      if Reply.positive?(mail_reply),
        do: sequential_rcpts(client, recipients, body),
        else: {:ok, client, all(recipients, :mail, mail_reply)}
    end
  end

  defp sequential_rcpts(client, recipients, body) do
    send_rcpt = &command(&1, :rcpt, ["RCPT TO:<", &2, ">"])

    with {:ok, rcpt_replies, client} <- collect(client, recipients, send_rcpt),
         {:ok, data_reply, client} <- send_data_command(client, rcpt_replies) do
      after_data_reply(client, rcpt_replies, data_reply, body)
    end
  end

  # Without an accepted recipient there is nothing to send.
  defp send_data_command(client, rcpt_replies) do
    if accepted(rcpt_replies) == [],
      do: {:ok, nil, client},
      else: command(client, :data, "DATA", client.opts.data_timeout)
  end

  # Runs `fun` for each recipient and collects `{recipient, reply}` pairs.
  defp collect(client, recipients, fun) do
    Enum.reduce_while(recipients, {:ok, [], client}, fn rcpt, {:ok, acc, client} ->
      case fun.(client, rcpt) do
        {:ok, reply, client} -> {:cont, {:ok, [{rcpt, reply} | acc], client}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, acc, client} -> {:ok, Enum.reverse(acc), client}
      error -> error
    end
  end

  defp after_data_reply(client, rcpt_replies, data_reply, body) do
    case {accepted(rcpt_replies), data_reply} do
      {[], _} ->
        with {:ok, client} <- finish_data_if_started(client, data_reply),
             {:ok, client} <- reset(client),
             do: {:ok, client, rejected(rcpt_replies)}

      {_accepted, %Reply{code: 354}} ->
        send_body(client, rcpt_replies, body)

      {accepted, _} ->
        with {:ok, client} <- reset(client),
             do: {:ok, client, rejected(rcpt_replies) ++ all(accepted, :data, data_reply)}
    end
  end

  # RFC 2920 §3.1: if DATA got 354 although no recipient was accepted, the
  # client must still send the terminating dot. An LMTP server answers it
  # once per accepted recipient: not at all.
  defp finish_data_if_started(client, data_reply, results \\ nil)

  defp finish_data_if_started(client, %Reply{code: 354}, results) do
    with :ok <- send_raw(client, ".\r\n", :data_end),
         {:ok, _replies, client} <- read_data_end(client, if(lmtp?(client), do: 0, else: 1)) do
      if results, do: {:ok, client, results}, else: {:ok, client}
    end
  end

  defp finish_data_if_started(client, _data_reply, nil), do: {:ok, client}
  defp finish_data_if_started(client, _data_reply, results), do: {:ok, client, results}

  defp send_body(client, rcpt_replies, body) do
    result =
      Enum.reduce_while(body, {:ok, DataEncoder.new()}, fn chunk, {:ok, encoder} ->
        {data, encoder} = DataEncoder.encode(encoder, chunk)

        case send_raw(client, data, :data_end) do
          :ok -> {:cont, {:ok, encoder}}
          {:error, _} = error -> {:halt, error}
        end
      end)

    accepted = accepted(rcpt_replies)

    with {:ok, encoder} <- result,
         :ok <- send_raw(client, DataEncoder.finish(encoder), :data_end),
         {:ok, replies, client} <-
           read_data_end(client, if(lmtp?(client), do: length(accepted), else: 1)) do
      {:ok, client, rejected(rcpt_replies) ++ data_end_results(accepted, replies)}
    end
  end

  # SMTP answers the final dot once; LMTP once per accepted recipient, in
  # the order of the RCPT commands (RFC 2033 §4.2).
  defp read_data_end(client, count) do
    Enum.reduce_while(1..count//1, {:ok, [], client}, fn _, {:ok, acc, client} ->
      case read_reply(client, :data_end, client.opts.data_end_timeout) do
        {:ok, reply, client} -> {:cont, {:ok, [reply | acc], client}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, acc, client} -> {:ok, Enum.reverse(acc), client}
      error -> error
    end
  end

  defp data_end_results(accepted, [reply]) when length(accepted) != 1,
    do: all(accepted, :data_end, reply)

  defp data_end_results(accepted, replies),
    do: Enum.zip_with(accepted, replies, &{&1, :data_end, &2})

  defp lmtp?(client), do: client.opts.protocol == :lmtp

  defp accepted(rcpt_replies),
    do: for({rcpt, reply} <- rcpt_replies, Reply.positive?(reply), do: rcpt)

  defp rejected(rcpt_replies),
    do: for({rcpt, reply} <- rcpt_replies, Reply.negative?(reply), do: {rcpt, :rcpt, reply})

  defp all(recipients, stage, reply), do: Enum.map(recipients, &{&1, stage, reply})

  defp reset(client) do
    case command(client, :rset, "RSET") do
      {:ok, %Reply{code: 250}, client} ->
        {:ok, client}

      {:ok, reply, client} ->
        close(client)
        {:error, {:rset, reply}}

      {:error, _} = error ->
        error
    end
  end

  ## I/O

  defp command(client, stage, line, timeout \\ nil) do
    with :ok <- send_line(client, line, stage),
         do: read_reply(client, stage, timeout || client.opts.command_timeout)
  end

  defp send_line(client, line, stage \\ :quit), do: send_raw(client, [line, "\r\n"], stage)

  defp send_lines(client, lines, stage),
    do: send_raw(client, Enum.map(lines, &[&1, "\r\n"]), stage)

  defp send_raw(client, data, stage) do
    case client.transport.send(client.socket, data) do
      :ok ->
        :ok

      {:error, reason} ->
        close(client)
        {:error, {stage, reason}}
    end
  end

  defp read_reply(client, stage, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    read_reply(client, stage, deadline, client.buffer)
  end

  defp read_reply(client, stage, deadline, buffer) do
    decode_opts = [max_line_length: client.opts.max_line_length, max_lines: client.opts.max_lines]

    case Reply.decode(buffer, decode_opts) do
      {:ok, reply, rest} ->
        {:ok, reply, %{client | buffer: rest}}

      :more ->
        remaining = max(deadline - System.monotonic_time(:millisecond), 0)

        case client.transport.recv(client.socket, 0, remaining) do
          {:ok, data} ->
            read_reply(client, stage, deadline, buffer <> data)

          {:error, reason} ->
            close(client)
            {:error, {stage, reason}}
        end

      {:error, reason} ->
        close(client)
        {:error, {stage, reason}}
    end
  end
end
