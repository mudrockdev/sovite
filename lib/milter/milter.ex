defmodule Sovite.Milter do
  @moduledoc """
  A milter client: passes SMTP sessions to a mail filter such as Rspamd,
  OpenDKIM, OpenDMARC, or ClamAV-milter over Sendmail's milter protocol
  (version 6), with the semantics of Postfix's milter support.

      {:ok, milter} = Milter.connect({:inet, "127.0.0.1", 11332}, name: "rspamd")
      {:ok, :continue, milter} = Milter.connect_info(milter, "mx.example.net", {{192, 0, 2, 1}, 52_314})
      {:ok, :continue, milter} = Milter.helo(milter, "mx.example.net")
      {:ok, :continue, milter} = Milter.mail(milter, "alice@example.net", ["SIZE=1234"])
      {:ok, :continue, milter} = Milter.rcpt(milter, "bob@example.com")
      {:ok, :continue, milter} = Milter.data(milter)
      {:ok, :continue, milter} = Milter.header(milter, "Subject", " Hello")
      {:ok, :continue, milter} = Milter.end_of_headers(milter)
      {:ok, :continue, milter} = Milter.body(milter, "Hi Bob.\\r\\n")
      {:ok, :accept, modifications, milter} = Milter.end_of_message(milter)
      :ok = Milter.quit(milter)

  The client is a struct owned by the calling process; every call blocks
  until the milter answers or a timeout expires. `connect/2` negotiates
  the protocol version, the actions the milter may take, the steps it
  wants to see, and the macros it wants at each step. One connection
  carries one SMTP session, which can have any number of transactions:
  `end_of_message/2` or `abort/1` ends a transaction.

  ## Steps

  There is one function per SMTP step. Each returns `{:ok, reply, milter}`
  (or, at the end of the message, the modifications too):

    * A step the milter declined at negotiation (or that its protocol
      version does not know) is not sent, and returns `:continue`. The
      macros for a declined step are still sent, as Postfix does, so the
      milter can read them at later steps.
    * A step the milter will not reply to is sent without waiting, and
      returns `:continue`.
    * After the milter accepted, discarded, or rejected the message, the
      remaining steps of the transaction are not sent and return that
      reply. A reply to `rcpt/4` other than `:accept` or `:discard` is
      about that recipient only.
    * After a reply other than `:continue` to `connect_info/4` or
      `helo/3`, or a `:shutdown` reply, the milter is done with the whole
      session: every later step returns that reply without I/O.
    * When the milter answers a body chunk with `SMFIR_SKIP`, the rest of
      the body is not sent.

  `SMFIR_PROGRESS` makes the client wait on, with a fresh timeout.

  ## Replies

    * `:continue` - go on. At the end of the message, the same as `:accept`.
    * `:accept` - accept the message (or, at the connection steps, the
      session) without further filtering.
    * `:reject` - reject with a generic 5xx reply.
    * `:tempfail` - reject with a generic 4xx reply.
    * `:discard` - accept the message and throw it away.
    * `{:reply, code, enhanced, text}` - reject with this SMTP reply.
      `code` is 4xx or 5xx, `enhanced` an RFC 3463 code or `nil`, and
      `text` a string, or a list of lines for a multi-line reply.
    * `:shutdown` - close the SMTP session with a 421 reply
      (`SMFIR_SHUTDOWN` or `SMFIR_CONN_FAIL`).

  ## Headers

  Header values are as they come after the colon in the message,
  continuation lines and all: `header/3` takes `" Hello"` for
  `Subject: Hello`, and header modifications carry values in the same
  form, with CRLF line breaks. The client adds or strips the one leading
  space as the milter negotiated (`SMFIP_HDR_LEADSPC`).
  `Sovite.Milter.Headers.apply/2` applies header modifications to the
  header fields of a message.

  ## Options

    * `:name` - label in telemetry metadata. Defaults to the address, as
      in `"inet:127.0.0.1:11332"`.
    * `:connect_timeout` - milliseconds to connect. Defaults to 30 seconds.
    * `:command_timeout` - milliseconds to wait for the negotiation and
      the replies to the SMTP steps. Defaults to 30 seconds.
    * `:content_timeout` - milliseconds to wait for the replies to
      headers, the body, and the end of the message, and to send data.
      Defaults to 5 minutes.
    * `:actions` - the actions the milter may take, see
      `Sovite.Milter.Packet`. Defaults to all of them.
    * `:max_packet_size` - bytes in a packet from the milter. Defaults to
      64 MiB.

  ## Errors

  `connect/2` returns `{:error, {:connect, reason}}` when the connection
  fails. Any call returns `{:error, reason}` when the milter does not
  answer in time (`:timeout`), closes the connection (`:closed`), the
  socket fails (an `:inet.posix()` reason), or it breaks the protocol
  (`{:protocol, protocol_error()}`). The connection is closed then, and
  the client cannot be used again.

  ## Telemetry

    * `[:sovite, :milter, :connect, :start]` - `%{system_time}`,
      `%{milter, address}`
    * `[:sovite, :milter, :connect, :stop]` - `%{duration}`, `%{milter,
      address, result}`, where `result` is `{:ok, version}` or `{:error,
      reason}`
    * `[:sovite, :milter, :reply]` - `%{duration}`, `%{milter, stage,
      reply}`, for each step the milter replied to. `stage` is the name of
      the function (`:connect_info`, `:helo`, ..., `:end_of_message`), and
      `reply` a `t:reply/0`, or `:skip` for a body chunk.
      At `:end_of_message` the metadata also has `modifications`, their
      number.
    * `[:sovite, :milter, :error]` - `%{}`, `%{milter, stage, reason}`,
      when a call fails and closes the connection.
  """

  import Bitwise

  alias Sovite.Milter.Packet
  alias Sovite.SMTP.Reply

  @version 6
  @all_actions 0x1FF
  # The MTA offers every protocol flag of version 6.
  @offered_protocol 0x1FFFFF
  # Body chunks are at most 64 KiB - 1 (MILTER_CHUNK_SIZE).
  @chunk_size 65_535

  # Header leading space (SMFIP_HDR_LEADSPC).
  @leading_space 0x100000

  @defaults [
    name: nil,
    connect_timeout: 30_000,
    command_timeout: 30_000,
    content_timeout: 300_000,
    actions: nil,
    max_packet_size: 64 * 1024 * 1024
  ]

  # stage => {declined flag, no-reply flag, macro command byte, macro stage, minimum version}
  @stages %{
    connect_info: {0x1, 0x1000, ?C, 0, 2},
    helo: {0x2, 0x2000, ?H, 1, 2},
    mail: {0x4, 0x4000, ?M, 2, 2},
    rcpt: {0x8, 0x8000, ?R, 3, 2},
    data: {0x200, 0x10000, ?T, 4, 4},
    header: {0x20, 0x80, nil, nil, 2},
    end_of_headers: {0x40, 0x40000, ?N, 6, 2},
    body: {0x10, 0x80000, nil, nil, 2},
    end_of_message: {0, 0, ?E, 5, 2},
    unknown: {0x100, 0x20000, nil, nil, 3}
  }

  @macro_stages %{
    0 => :connect,
    1 => :helo,
    2 => :mail,
    3 => :rcpt,
    4 => :data,
    5 => :end_of_message,
    6 => :end_of_headers
  }

  @session_stages [:connect_info, :helo]
  @content_stages [:header, :end_of_headers, :body, :end_of_message]

  @enforce_keys [:socket, :name]
  defstruct [
    :socket,
    :name,
    :version,
    :actions,
    :protocol,
    :command_timeout,
    :content_timeout,
    :max_packet_size,
    :session,
    :message,
    macros: %{},
    skip_body: false,
    buffer: <<>>
  ]

  @opaque t :: %__MODULE__{}

  @typedoc """
  Where the milter listens. A host is a name or an IP address; with
  `:inet6`, names are resolved to IPv6 addresses.
  """
  @type address ::
          {:inet, String.t() | :inet.ip_address(), :inet.port_number()}
          | {:inet6, String.t() | :inet.ip6_address(), :inet.port_number()}
          | {:unix, Path.t()}

  @typedoc """
  Macros for a step (Sendmail's `{client_addr}`, `i`, `{auth_authen}`,
  ...): a map or a list of name and value pairs. When the milter asked
  for certain macros at a step, only those are sent.
  """
  @type macros :: %{optional(String.t()) => String.t()} | [{String.t(), String.t()}]

  @typedoc "The SMTP client, as passed to `connect_info/4`."
  @type client :: {:inet.ip_address(), :inet.port_number()} | {:unix, Path.t()} | :unknown

  @typedoc "A reply to a step. See the module documentation."
  @type reply ::
          :continue
          | :accept
          | :reject
          | :tempfail
          | :discard
          | :shutdown
          | {:reply, 400..599, String.t() | nil, String.t() | [String.t()]}

  @typedoc """
  A change the milter asks for at the end of the message, in the order it
  sent them.

    * `{:add_header, name, value}` - append a header field.
    * `{:insert_header, index, name, value}` - insert a header field at
      position `index` of the header (0 is the top).
    * `{:change_header, index, name, value}` - replace the `index`th
      (from 1) field called `name`.
    * `{:delete_header, index, name}` - delete the `index`th field called
      `name`.
    * `{:add_recipient, address, args}` - add a recipient, with ESMTP
      arguments.
    * `{:delete_recipient, address}` - remove a recipient.
    * `{:change_sender, address, args}` - replace the envelope sender.
    * `{:replace_body, iodata}` - replace the body (CRLF line endings).
    * `{:quarantine, reason}` - hold the message.

  Addresses are without angle brackets; the null sender is `""`.
  """
  @type modification ::
          {:add_header, String.t(), String.t()}
          | {:insert_header, non_neg_integer(), String.t(), String.t()}
          | {:change_header, non_neg_integer(), String.t(), String.t()}
          | {:delete_header, non_neg_integer(), String.t()}
          | {:add_recipient, String.t(), [String.t()]}
          | {:delete_recipient, String.t()}
          | {:change_sender, String.t(), [String.t()]}
          | {:replace_body, iodata()}
          | {:quarantine, String.t()}

  @typedoc """
  How the milter broke the protocol: a `Sovite.Milter.Packet.error()`,
  a response that does not belong at this step, a protocol version below
  2, a modification of an action it did not negotiate, or a malformed
  reply code.
  """
  @type protocol_error ::
          Packet.error()
          | {:unexpected_response, byte()}
          | {:unsupported_version, non_neg_integer()}
          | {:action_not_negotiated, Packet.action()}
          | {:malformed_reply_code, String.t()}

  @typedoc "Why a call failed. The connection is closed."
  @type error :: :timeout | :closed | {:protocol, protocol_error()} | :inet.posix()

  @typedoc "What was negotiated, from `info/1`."
  @type info :: %{
          name: String.t(),
          version: 2..6,
          actions: [Packet.action()],
          protocol: [Packet.protocol_flag()],
          macros: %{atom() => [String.t()]}
        }

  ## Addresses

  @doc """
  Parses a milter address in Postfix or Sendmail syntax: `inet:host:port`,
  `inet:port@host`, `inet6:port@host`, `unix:/path`, or `local:/path`.
  IPv6 addresses may be in brackets.

      iex> Sovite.Milter.parse_address("inet:127.0.0.1:11332")
      {:ok, {:inet, {127, 0, 0, 1}, 11332}}
      iex> Sovite.Milter.parse_address("inet:8891@localhost")
      {:ok, {:inet, "localhost", 8891}}
      iex> Sovite.Milter.parse_address("unix:/run/opendkim/opendkim.sock")
      {:ok, {:unix, "/run/opendkim/opendkim.sock"}}
  """
  @spec parse_address(String.t()) :: {:ok, address()} | {:error, :invalid_address}
  def parse_address("unix:" <> path) when path != "", do: {:ok, {:unix, path}}
  def parse_address("local:" <> path) when path != "", do: {:ok, {:unix, path}}
  def parse_address("inet:" <> rest), do: parse_inet(rest, :inet)
  def parse_address("inet6:" <> rest), do: parse_inet(rest, :inet6)
  def parse_address(_address), do: {:error, :invalid_address}

  defp parse_inet(rest, family) do
    {host, port} =
      case String.split(rest, "@", parts: 2) do
        [port, host] ->
          {host, port}

        [host_port] ->
          case String.split(host_port, ":") do
            [_] -> {"", ""}
            parts -> {parts |> Enum.drop(-1) |> Enum.join(":"), List.last(parts)}
          end
      end

    host = host |> String.trim_leading("[") |> String.trim_trailing("]")

    with {port, ""} when port in 1..65_535 <- Integer.parse(port),
         true <- host != "" do
      {:ok, inet_address(family, host, port)}
    else
      _ -> {:error, :invalid_address}
    end
  end

  defp inet_address(family, host, port) do
    case :inet.parse_strict_address(String.to_charlist(host)) do
      {:ok, ip} -> {:inet, ip, port}
      {:error, _} -> {family, host, port}
    end
  end

  ## Connection

  @doc """
  Connects to a milter and negotiates the protocol. See the module
  documentation for options.

  Milters that answer with protocol version 2 to 5 are accepted, without
  the steps, flags, and actions their version does not know.
  """
  @spec connect(address(), keyword()) ::
          {:ok, t()} | {:error, {:connect, :inet.posix() | :timeout} | error()}
  def connect(address, opts \\ []) do
    opts = Keyword.validate!(opts, @defaults)
    name = opts[:name] || format_address(address)
    metadata = %{milter: name, address: address}

    :telemetry.span([:sovite, :milter, :connect], metadata, fn ->
      result = open(address, name, opts)
      {result, Map.put(metadata, :result, connect_result(result))}
    end)
  end

  defp connect_result({:ok, milter}), do: {:ok, milter.version}
  defp connect_result(error), do: error

  defp open(address, name, opts) do
    {host, port, family} = socket_address(address)

    tcp_opts =
      [:binary, active: false, packet: :raw] ++
        [send_timeout: opts[:content_timeout], send_timeout_close: true] ++ family

    case :gen_tcp.connect(host, port, tcp_opts, opts[:connect_timeout]) do
      {:ok, socket} ->
        milter = %__MODULE__{
          socket: socket,
          name: name,
          command_timeout: opts[:command_timeout],
          content_timeout: opts[:content_timeout],
          max_packet_size: opts[:max_packet_size]
        }

        allowed = if opts[:actions], do: Packet.action_mask(opts[:actions]), else: @all_actions
        negotiate(milter, allowed)

      {:error, reason} ->
        {:error, {:connect, reason}}
    end
  end

  defp socket_address({:unix, path}), do: {{:local, path}, 0, [:local]}

  defp socket_address({family, host, port}) do
    host = if is_binary(host), do: String.to_charlist(host), else: host
    ipv6 = family == :inet6 or (is_tuple(host) and tuple_size(host) == 8)
    {host, port, if(ipv6, do: [:inet6], else: [])}
  end

  defp format_address({:unix, path}), do: "unix:" <> path

  defp format_address({family, host, port}) do
    host = if is_tuple(host), do: :inet.ntoa(host) |> to_string(), else: host
    host = if String.contains?(host, ":"), do: "[#{host}]", else: host
    "#{family}:#{host}:#{port}"
  end

  defp negotiate(milter, allowed) do
    command = Packet.encode_command({:optneg, @version, allowed, @offered_protocol})
    deadline = deadline(milter.command_timeout)

    with :ok <- send_data(milter, command),
         {:ok, {byte, data}, milter} <- read_packet(milter, deadline),
         {:ok, {:optneg, version, actions, protocol, macros}} <- optneg(byte, data),
         :ok <- check_version(version) do
      version = min(version, @version)

      {:ok,
       %{
         milter
         | version: version,
           actions: actions &&& allowed &&& version_actions(version),
           protocol: protocol &&& @offered_protocol &&& version_protocol(version),
           macros: if(version >= 6, do: macro_requests(macros), else: %{})
       }}
    else
      {:error, reason} -> fail(milter, :connect, reason)
    end
  end

  defp optneg(?O, data), do: protocol_error(Packet.decode_response(?O, data))
  defp optneg(byte, _data), do: {:error, {:protocol, {:unexpected_response, byte}}}

  defp check_version(version) when version >= 2, do: :ok
  defp check_version(version), do: {:error, {:protocol, {:unsupported_version, version}}}

  # What older protocol versions know (as in Postfix's milter8.c).
  defp version_protocol(2), do: 0x7F
  defp version_protocol(3), do: 0x17F
  defp version_protocol(v) when v in [4, 5], do: 0x37F
  defp version_protocol(6), do: @offered_protocol

  defp version_actions(6), do: @all_actions
  defp version_actions(_version), do: 0x3F

  defp macro_requests(requests) do
    for {stage, names} <- requests, Map.has_key?(@macro_stages, stage), into: %{} do
      {stage, String.split(names, [" ", ","], trim: true)}
    end
  end

  @doc "Returns what was negotiated with the milter."
  @spec info(t()) :: info()
  def info(%__MODULE__{} = milter) do
    %{
      name: milter.name,
      version: milter.version,
      actions: Packet.actions(milter.actions),
      protocol: Packet.protocol(milter.protocol),
      macros: Map.new(milter.macros, fn {stage, names} -> {@macro_stages[stage], names} end)
    }
  end

  ## Steps

  @doc """
  Reports the SMTP client connection. `hostname` is the client's verified
  host name; Postfix sends the address in brackets, `"[192.0.2.1]"`,
  when it has none.
  """
  @spec connect_info(t(), String.t(), client(), macros()) ::
          {:ok, reply(), t()} | {:error, error()}
  def connect_info(milter, hostname, client, macros \\ []) do
    command =
      case client do
        {:unix, path} -> {:connect, hostname, :unix, 0, path}
        :unknown -> {:connect, hostname, :unknown, nil, nil}
        {ip, port} -> {:connect, hostname, ip_family(ip), port, to_string(:inet.ntoa(ip))}
      end

    step(milter, :connect_info, command, macros)
  end

  defp ip_family(ip) when tuple_size(ip) == 4, do: :inet
  defp ip_family(ip) when tuple_size(ip) == 8, do: :inet6

  @doc "Reports the `HELO` or `EHLO` name."
  @spec helo(t(), String.t(), macros()) :: {:ok, reply(), t()} | {:error, error()}
  def helo(milter, name, macros \\ []), do: step(milter, :helo, {:helo, name}, macros)

  @doc """
  Reports `MAIL FROM`, which starts a transaction: the sender (`""` for
  the null sender) and its ESMTP arguments, such as `"SIZE=1000"`.
  """
  @spec mail(t(), String.t(), [String.t()], macros()) ::
          {:ok, reply(), t()} | {:error, error()}
  def mail(milter, sender, args \\ [], macros \\ []) do
    milter = %{milter | message: nil, skip_body: false}
    step(milter, :mail, {:mail, ["<#{sender}>" | args]}, macros)
  end

  @doc """
  Reports a `RCPT TO` recipient and its ESMTP arguments. A milter that
  negotiated `:rejected_recipients` (see `info/1`) also wants recipients
  the MTA rejected, with the `{rcpt_mailer}` macro set to `"error"`.
  """
  @spec rcpt(t(), String.t(), [String.t()], macros()) ::
          {:ok, reply(), t()} | {:error, error()}
  def rcpt(milter, recipient, args \\ [], macros \\ []),
    do: step(milter, :rcpt, {:rcpt, ["<#{recipient}>" | args]}, macros)

  @doc "Reports the `DATA` command."
  @spec data(t(), macros()) :: {:ok, reply(), t()} | {:error, error()}
  def data(milter, macros \\ []), do: step(milter, :data, :data, macros)

  @doc """
  Sends a header field. `value` is everything after the colon, with
  continuation lines, without the final line break.
  """
  @spec header(t(), String.t(), String.t()) :: {:ok, reply(), t()} | {:error, error()}
  def header(milter, name, value) do
    value = String.replace(value, "\r\n", "\n")

    value =
      case value do
        " " <> rest when (milter.protocol &&& @leading_space) == 0 -> rest
        value -> value
      end

    step(milter, :header, {:header, name, value}, [])
  end

  @doc "Reports the end of the header."
  @spec end_of_headers(t(), macros()) :: {:ok, reply(), t()} | {:error, error()}
  def end_of_headers(milter, macros \\ []),
    do: step(milter, :end_of_headers, :end_of_headers, macros)

  @doc """
  Sends a piece of the body, as received (CRLF line endings, not
  dot-stuffed). It goes in chunks of up to 64 KiB, each one answered
  unless the milter negotiated otherwise, so pass large pieces.
  """
  @spec body(t(), iodata()) :: {:ok, reply(), t()} | {:error, error()}
  def body(milter, data), do: body_chunks(milter, IO.iodata_to_binary(data))

  defp body_chunks(milter, <<>>), do: {:ok, :continue, milter}
  defp body_chunks(%{skip_body: true} = milter, _data), do: {:ok, :continue, milter}

  defp body_chunks(milter, data) do
    {chunk, rest} =
      case data do
        <<chunk::binary-size(@chunk_size), rest::binary>> -> {chunk, rest}
        chunk -> {chunk, <<>>}
      end

    case step(milter, :body, {:body, chunk}, []) do
      {:ok, :skip, milter} -> {:ok, :continue, %{milter | skip_body: true}}
      {:ok, :continue, milter} -> body_chunks(milter, rest)
      other -> other
    end
  end

  @doc """
  Reports the end of the message and collects the milter's
  modifications. This ends the transaction.

  Modifications come only with a final `:continue` or `:accept`; the
  caller should drop them with any other reply.
  """
  @spec end_of_message(t(), macros()) ::
          {:ok, reply(), [modification()], t()} | {:error, error()}
  def end_of_message(milter, macros \\ [])

  def end_of_message(%__MODULE__{session: reply} = milter, _macros) when reply != nil,
    do: {:ok, reply, [], milter}

  def end_of_message(%__MODULE__{message: reply} = milter, _macros) when reply != nil,
    do: {:ok, reply, [], end_transaction(milter)}

  def end_of_message(%__MODULE__{} = milter, macros) do
    data = [macro_packet(milter, :end_of_message, macros), Packet.encode_command(:end_of_message)]
    start = System.monotonic_time()

    with :ok <- send_data(milter, data),
         {:ok, reply, modifications, milter} <-
           read_modifications(milter, deadline(milter.content_timeout), [], nil) do
      emit_reply(milter, :end_of_message, start, reply, %{modifications: length(modifications)})
      {:ok, reply, modifications, end_transaction(update_state(milter, :end_of_message, reply))}
    else
      {:error, reason} -> fail(milter, :end_of_message, reason)
    end
  end

  @doc """
  Reports an SMTP command the MTA does not know, such as `"FOO bar"`.
  The milter's reply is about that command only.
  """
  @spec unknown(t(), String.t()) :: {:ok, reply(), t()} | {:error, error()}
  def unknown(milter, line), do: step(milter, :unknown, {:unknown, line}, [])

  @doc """
  Ends a transaction that did not reach `end_of_message/2` (`RSET`, a
  rejected message, or a lost client). The connection stays usable for
  the next transaction.
  """
  @spec abort(t()) :: {:ok, t()} | {:error, error()}
  def abort(%__MODULE__{session: reply} = milter) when reply != nil,
    do: {:ok, end_transaction(milter)}

  def abort(%__MODULE__{} = milter) do
    case send_data(milter, Packet.encode_command(:abort)) do
      :ok -> {:ok, end_transaction(milter)}
      {:error, reason} -> fail(milter, :abort, reason)
    end
  end

  @doc "Ends the session politely and closes the connection."
  @spec quit(t()) :: :ok
  def quit(%__MODULE__{} = milter) do
    _ = send_data(milter, Packet.encode_command(:quit))
    close(milter)
  end

  @doc "Closes the connection."
  @spec close(t()) :: :ok
  def close(%__MODULE__{socket: socket}) do
    _ = :gen_tcp.close(socket)
    :ok
  end

  ## Step machinery

  defp step(%__MODULE__{session: reply} = milter, _stage, _command, _macros) when reply != nil,
    do: {:ok, reply, milter}

  defp step(%__MODULE__{message: reply} = milter, stage, _command, _macros)
       when reply != nil and stage not in [:connect_info, :helo, :unknown],
       do: {:ok, reply, milter}

  defp step(milter, stage, command, macros) do
    {declined, no_reply, _byte, _macro_stage, min_version} = @stages[stage]

    cond do
      milter.version < min_version ->
        {:ok, :continue, milter}

      (milter.protocol &&& declined) != 0 ->
        send_step(milter, stage, macro_packet(milter, stage, macros))

      (milter.protocol &&& no_reply) != 0 ->
        send_step(milter, stage, [macro_packet(milter, stage, macros), encode(command)])

      true ->
        exchange(milter, stage, [macro_packet(milter, stage, macros), encode(command)])
    end
  end

  defp encode(command), do: Packet.encode_command(command)

  defp send_step(milter, _stage, []), do: {:ok, :continue, milter}

  defp send_step(milter, stage, data) do
    case send_data(milter, data) do
      :ok -> {:ok, :continue, milter}
      {:error, reason} -> fail(milter, stage, reason)
    end
  end

  defp exchange(milter, stage, data) do
    start = System.monotonic_time()

    with :ok <- send_data(milter, data),
         {:ok, reply, milter} <- read_reply(milter, stage, deadline(timeout(milter, stage))) do
      emit_reply(milter, stage, start, reply, %{})
      {:ok, reply, update_state(milter, stage, reply)}
    else
      {:error, reason} -> fail(milter, stage, reason)
    end
  end

  defp timeout(milter, stage) when stage in @content_stages, do: milter.content_timeout
  defp timeout(milter, _stage), do: milter.command_timeout

  defp read_reply(milter, stage, deadline) do
    case read_response(milter, deadline) do
      {:ok, _byte, :progress, milter} ->
        read_reply(milter, stage, deadline(timeout(milter, stage)))

      {:ok, _byte, :skip, milter} when stage == :body ->
        {:ok, :skip, milter}

      {:ok, byte, response, milter} ->
        final_reply(response, byte, milter)

      {:error, _} = error ->
        error
    end
  end

  defp read_response(milter, deadline) do
    with {:ok, {byte, data}, milter} <- read_packet(milter, deadline),
         {:ok, response} <- protocol_error(Packet.decode_response(byte, data)) do
      {:ok, byte, response, milter}
    end
  end

  defp final_reply(response, byte, milter) do
    with {:ok, reply} <- reply(response, byte), do: {:ok, reply, milter}
  end

  defp reply(:continue, _byte), do: {:ok, :continue}
  defp reply(:accept, _byte), do: {:ok, :accept}
  defp reply(:reject, _byte), do: {:ok, :reject}
  defp reply(:tempfail, _byte), do: {:ok, :tempfail}
  defp reply(:discard, _byte), do: {:ok, :discard}
  defp reply(:shutdown, _byte), do: {:ok, :shutdown}
  defp reply(:connection_failure, _byte), do: {:ok, :shutdown}
  defp reply({:reply_code, text}, _byte), do: reply_code(text)
  defp reply(_response, byte), do: {:error, {:protocol, {:unexpected_response, byte}}}

  defp reply_code(text) do
    trimmed = String.trim_trailing(text, "\r\n")
    limit = byte_size(trimmed) + 2

    case Reply.decode(trimmed <> "\r\n", max_line_length: limit, max_lines: limit) do
      {:ok, %Reply{code: code, enhanced: enhanced, lines: lines}, ""} when code >= 400 ->
        {:ok, {:reply, code, enhanced, if(match?([_], lines), do: hd(lines), else: lines)}}

      _ ->
        {:error, {:protocol, {:malformed_reply_code, text}}}
    end
  end

  defp update_state(milter, _stage, reply) when reply in [:continue, :skip], do: milter
  defp update_state(milter, _stage, :shutdown), do: %{milter | session: :shutdown}

  defp update_state(milter, stage, reply) when stage in @session_stages,
    do: %{milter | session: reply}

  defp update_state(milter, :unknown, _reply), do: milter
  defp update_state(milter, :end_of_message, _reply), do: milter

  defp update_state(milter, :rcpt, reply) when reply in [:accept, :discard],
    do: %{milter | message: reply}

  defp update_state(milter, :rcpt, _reply), do: milter
  defp update_state(milter, _stage, reply), do: %{milter | message: reply}

  defp end_transaction(milter), do: %{milter | message: nil, skip_body: false}

  ## End of message

  defp read_modifications(milter, deadline, acc, body) do
    case read_response(milter, deadline) do
      {:ok, byte, response, milter} -> collect(milter, deadline, acc, body, byte, response)
      {:error, _} = error -> error
    end
  end

  defp collect(milter, deadline, acc, body, byte, response) do
    case modification(milter, response) do
      :progress ->
        read_modifications(milter, deadline(milter.content_timeout), acc, body)

      {:ok, {:replace_body, chunk}} when body == nil ->
        read_modifications(milter, deadline, [:replace_body | acc], [chunk])

      {:ok, {:replace_body, chunk}} ->
        read_modifications(milter, deadline, acc, [chunk | body])

      {:ok, modification} ->
        read_modifications(milter, deadline, [modification | acc], body)

      {:error, _} = error ->
        error

      :final ->
        with {:ok, reply, milter} <- final_reply(response, byte, milter),
             do: {:ok, reply, finish_modifications(acc, body), milter}
    end
  end

  defp finish_modifications(acc, body) do
    acc
    |> Enum.reverse()
    |> Enum.map(fn
      :replace_body -> {:replace_body, Enum.reverse(body)}
      modification -> modification
    end)
  end

  defp modification(_milter, :progress), do: :progress

  defp modification(milter, {:add_header, name, value}),
    do: allowed(milter, :add_headers, {:add_header, name, header_value(milter, value)})

  defp modification(milter, {:insert_header, index, name, value}),
    do: allowed(milter, :add_headers, {:insert_header, index, name, header_value(milter, value)})

  defp modification(milter, {:change_header, index, name, ""}),
    do: allowed(milter, :change_headers, {:delete_header, index, name})

  defp modification(milter, {:change_header, index, name, value}),
    do:
      allowed(milter, :change_headers, {:change_header, index, name, header_value(milter, value)})

  defp modification(milter, {:add_recipient, rcpt}),
    do: allowed(milter, :add_recipients, {:add_recipient, unbracket(rcpt), []})

  defp modification(milter, {:add_recipient_with_args, rcpt, args}),
    do: allowed(milter, :add_recipients_with_args, {:add_recipient, unbracket(rcpt), esmtp(args)})

  defp modification(milter, {:delete_recipient, rcpt}),
    do: allowed(milter, :delete_recipients, {:delete_recipient, unbracket(rcpt)})

  defp modification(milter, {:change_sender, sender, args}),
    do: allowed(milter, :change_sender, {:change_sender, unbracket(sender), esmtp(args)})

  defp modification(milter, {:replace_body, chunk}),
    do: allowed(milter, :change_body, {:replace_body, chunk})

  defp modification(milter, {:quarantine, reason}),
    do: allowed(milter, :quarantine, {:quarantine, reason})

  defp modification(_milter, _response), do: :final

  defp allowed(milter, action, modification) do
    if (milter.actions &&& Packet.action_mask([action])) != 0,
      do: {:ok, modification},
      else: {:error, {:protocol, {:action_not_negotiated, action}}}
  end

  defp header_value(milter, value) do
    value = String.replace(value, ~r/\r?\n/, "\r\n")
    if (milter.protocol &&& @leading_space) == 0, do: " " <> value, else: value
  end

  defp unbracket("<" <> rest), do: String.trim_trailing(rest, ">")
  defp unbracket(address), do: address

  defp esmtp(nil), do: []
  defp esmtp(args), do: String.split(args, " ", trim: true)

  ## Macros

  defp macro_packet(milter, stage, macros) do
    case @stages[stage] do
      {_, _, byte, macro_stage, _} when byte != nil ->
        case select_macros(milter, macro_stage, macros) do
          [] -> []
          pairs -> Packet.encode_command({:macro, byte, pairs})
        end

      _ ->
        []
    end
  end

  defp select_macros(milter, macro_stage, macros) do
    case Map.fetch(milter.macros, macro_stage) do
      {:ok, names} ->
        available = Map.new(macros)

        for name <- names, value = lookup_macro(available, name), value != nil, do: {name, value}

      :error ->
        Enum.to_list(macros)
    end
  end

  # "{name}" and "name" are the same macro.
  defp lookup_macro(macros, name) do
    alternative =
      case name do
        "{" <> rest -> String.trim_trailing(rest, "}")
        name -> "{#{name}}"
      end

    Map.get(macros, name) || Map.get(macros, alternative)
  end

  ## I/O

  defp send_data(milter, data) do
    case :gen_tcp.send(milter.socket, data) do
      :ok -> :ok
      {:error, {:timeout, _}} -> {:error, :timeout}
      {:error, reason} -> {:error, reason}
    end
  end

  defp deadline(timeout), do: System.monotonic_time(:millisecond) + timeout

  defp read_packet(milter, deadline) do
    case Packet.decode(milter.buffer, milter.max_packet_size) do
      {:ok, packet, rest} ->
        {:ok, packet, %{milter | buffer: rest}}

      {:error, reason} ->
        {:error, {:protocol, reason}}

      :more ->
        remaining = max(deadline - System.monotonic_time(:millisecond), 0)

        case :gen_tcp.recv(milter.socket, 0, remaining) do
          {:ok, data} -> read_packet(%{milter | buffer: milter.buffer <> data}, deadline)
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp protocol_error({:error, reason}), do: {:error, {:protocol, reason}}
  defp protocol_error(ok), do: ok

  defp fail(milter, stage, reason) do
    close(milter)

    :telemetry.execute([:sovite, :milter, :error], %{}, %{
      milter: milter.name,
      stage: stage,
      reason: reason
    })

    {:error, reason}
  end

  defp emit_reply(milter, stage, start, reply, extra) do
    :telemetry.execute(
      [:sovite, :milter, :reply],
      %{duration: System.monotonic_time() - start},
      Map.merge(%{milter: milter.name, stage: stage, reply: reply}, extra)
    )
  end
end
