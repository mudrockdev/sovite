defmodule Sovite.Milter.Packet do
  @moduledoc """
  Encodes and decodes milter protocol packets (Sendmail's libmilter,
  protocol version 6) in both directions: commands from the MTA, and the
  milter's responses. `Sovite.Milter` uses it as the MTA side; a milter
  written in Elixir can use it the other way round.

  A packet is a 32-bit length in network byte order, a command byte, and
  the command's data. The length counts the command byte and the data.
  Strings are NUL-terminated; numbers are in network byte order.

  Decoding never creates atoms: command bytes are mapped by fixed
  clauses, and unknown bytes are errors.

  ## Flags

  Actions and protocol flags are bit masks on the wire, and lists of
  atoms in the rest of `Sovite.Milter`. `action_mask/1`, `actions/1`,
  `protocol_mask/1` and `protocol/1` convert between them.

  Actions (`SMFIF_*`): `:add_headers`, `:change_body`, `:add_recipients`,
  `:delete_recipients`, `:change_headers`, `:quarantine`, `:change_sender`,
  `:add_recipients_with_args`, `:set_macros`.

  Protocol flags (`SMFIP_*`): steps the milter does not want,
  `:no_connect`, `:no_helo`, `:no_mail`, `:no_rcpt`, `:no_body`,
  `:no_headers`, `:no_end_of_headers`, `:no_unknown`, `:no_data`; steps it
  will not reply to, `:no_connect_reply`, `:no_helo_reply`,
  `:no_mail_reply`, `:no_rcpt_reply`, `:no_data_reply`,
  `:no_unknown_reply`, `:no_header_reply`, `:no_end_of_headers_reply`,
  `:no_body_reply`; and `:skip` (the milter may answer body chunks with
  `:skip`), `:rejected_recipients` (it wants to see rejected recipients
  too), `:header_leading_space` (header values are sent and taken with
  their leading space).
  """

  import Bitwise

  @actions [
    add_headers: 0x01,
    change_body: 0x02,
    add_recipients: 0x04,
    delete_recipients: 0x08,
    change_headers: 0x10,
    quarantine: 0x20,
    change_sender: 0x40,
    add_recipients_with_args: 0x80,
    set_macros: 0x100
  ]

  @protocol [
    no_connect: 0x1,
    no_helo: 0x2,
    no_mail: 0x4,
    no_rcpt: 0x8,
    no_body: 0x10,
    no_headers: 0x20,
    no_end_of_headers: 0x40,
    no_header_reply: 0x80,
    no_unknown: 0x100,
    no_data: 0x200,
    skip: 0x400,
    rejected_recipients: 0x800,
    no_connect_reply: 0x1000,
    no_helo_reply: 0x2000,
    no_mail_reply: 0x4000,
    no_rcpt_reply: 0x8000,
    no_data_reply: 0x10000,
    no_unknown_reply: 0x20000,
    no_end_of_headers_reply: 0x40000,
    no_body_reply: 0x80000,
    header_leading_space: 0x100000
  ]

  @typedoc "An action the MTA allows and the milter asks for."
  @type action ::
          :add_headers
          | :change_body
          | :add_recipients
          | :delete_recipients
          | :change_headers
          | :quarantine
          | :change_sender
          | :add_recipients_with_args
          | :set_macros

  @typedoc "A protocol flag: a step the milter does not want or will not reply to."
  @type protocol_flag ::
          :no_connect
          | :no_helo
          | :no_mail
          | :no_rcpt
          | :no_body
          | :no_headers
          | :no_end_of_headers
          | :no_header_reply
          | :no_unknown
          | :no_data
          | :skip
          | :rejected_recipients
          | :no_connect_reply
          | :no_helo_reply
          | :no_mail_reply
          | :no_rcpt_reply
          | :no_data_reply
          | :no_unknown_reply
          | :no_end_of_headers_reply
          | :no_body_reply
          | :header_leading_space

  @typedoc "The address family of a connecting client."
  @type family :: :inet | :inet6 | :unix | :unknown

  @typedoc """
  A command from the MTA. `:mail` and `:rcpt` carry the address in angle
  brackets followed by the ESMTP arguments. A `:macro` packet names the
  command byte its macros belong to. A `:connect` with family `:unknown`
  has no port and address.
  """
  @type command ::
          {:optneg, version :: non_neg_integer(), actions :: non_neg_integer(),
           protocol :: non_neg_integer()}
          | {:macro, command :: byte(), [{String.t(), String.t()}]}
          | {:connect, hostname :: String.t(), family(), :inet.port_number() | nil,
             address :: String.t() | nil}
          | {:helo, String.t()}
          | {:mail, [String.t(), ...]}
          | {:rcpt, [String.t(), ...]}
          | :data
          | {:header, name :: String.t(), value :: String.t()}
          | :end_of_headers
          | {:body, binary()}
          | :end_of_message
          | :abort
          | :quit
          | :quit_new_connection
          | {:unknown, String.t()}

  @typedoc """
  A response from the milter, as on the wire: addresses keep their angle
  brackets and ESMTP arguments are one string (or `nil`).

  `:optneg` carries the macro requests, as stage numbers and
  space-separated macro names. `:connection_failure` is `SMFIR_CONN_FAIL`.
  """
  @type response ::
          {:optneg, version :: non_neg_integer(), actions :: non_neg_integer(),
           protocol :: non_neg_integer(), [{stage :: non_neg_integer(), String.t()}]}
          | :continue
          | :accept
          | :reject
          | :tempfail
          | :discard
          | :skip
          | :progress
          | :connection_failure
          | :shutdown
          | {:reply_code, String.t()}
          | {:add_recipient, String.t()}
          | {:add_recipient_with_args, String.t(), String.t() | nil}
          | {:delete_recipient, String.t()}
          | {:replace_body, binary()}
          | {:add_header, String.t(), String.t()}
          | {:insert_header, non_neg_integer(), String.t(), String.t()}
          | {:change_header, non_neg_integer(), String.t(), String.t()}
          | {:change_sender, String.t(), String.t() | nil}
          | {:quarantine, String.t()}
          | {:set_macros, stage :: non_neg_integer(), String.t()}

  @typedoc "Why a packet could not be decoded."
  @type error ::
          :empty_packet
          | {:packet_too_large, non_neg_integer()}
          | {:unknown_command, byte()}
          | {:malformed, byte()}

  ## Flags

  @doc """
  Returns the bit mask of a list of actions.

      iex> Sovite.Milter.Packet.action_mask([:add_headers, :change_headers])
      0x11
  """
  @spec action_mask([action()]) :: non_neg_integer()
  def action_mask(actions), do: mask(actions, @actions)

  @doc """
  Returns the actions in a bit mask. Unknown bits are dropped.

      iex> Sovite.Milter.Packet.actions(0x11)
      [:add_headers, :change_headers]
  """
  @spec actions(non_neg_integer()) :: [action()]
  def actions(mask), do: flags(mask, @actions)

  @doc "Returns the bit mask of a list of protocol flags."
  @spec protocol_mask([protocol_flag()]) :: non_neg_integer()
  def protocol_mask(flags), do: mask(flags, @protocol)

  @doc "Returns the protocol flags in a bit mask. Unknown bits are dropped."
  @spec protocol(non_neg_integer()) :: [protocol_flag()]
  def protocol(mask), do: flags(mask, @protocol)

  defp mask(names, table),
    do: Enum.reduce(names, 0, fn name, acc -> acc ||| Keyword.fetch!(table, name) end)

  defp flags(mask, table), do: for({name, bit} <- table, (mask &&& bit) != 0, do: name)

  ## Framing

  @doc """
  Frames a packet: the length, the command byte, and the data.

      iex> Sovite.Milter.Packet.frame(?c, "") |> IO.iodata_to_binary()
      <<0, 0, 0, 1, ?c>>
  """
  @spec frame(byte(), iodata()) :: iodata()
  def frame(command, data), do: [<<IO.iodata_length(data) + 1::32>>, command, data]

  @doc """
  Takes one packet from the start of `buffer`.

    * `{:ok, {command, data}, rest}` - a whole packet and the bytes after it.
    * `:more` - the packet is not complete yet.
    * `{:error, reason}` - an empty packet, or one longer than `max_size`
      bytes (command byte and data), checked as soon as the length is in.
  """
  @spec decode(binary(), pos_integer()) ::
          {:ok, {byte(), binary()}, binary()} | :more | {:error, error()}
  def decode(<<0::32, _::binary>>, _max_size), do: {:error, :empty_packet}

  def decode(<<length::32, _::binary>>, max_size) when length > max_size,
    do: {:error, {:packet_too_large, length}}

  def decode(<<length::32, command, rest::binary>>, _max_size)
      when byte_size(rest) >= length - 1 do
    size = length - 1
    <<data::binary-size(^size), rest::binary>> = rest
    {:ok, {command, data}, rest}
  end

  def decode(_buffer, _max_size), do: :more

  ## Commands

  @doc "Encodes a command from the MTA as a framed packet."
  @spec encode_command(command()) :: iodata()
  def encode_command({:optneg, version, actions, protocol}),
    do: frame(?O, <<version::32, actions::32, protocol::32>>)

  def encode_command({:macro, command, macros}),
    do: frame(?D, [command | Enum.map(macros, fn {name, value} -> strings([name, value]) end)])

  def encode_command({:connect, hostname, :unknown, _port, _address}),
    do: frame(?C, [hostname, 0, ?U])

  def encode_command({:connect, hostname, family, port, address}),
    do: frame(?C, [hostname, 0, family_byte(family), <<port::16>>, address, 0])

  def encode_command({:helo, name}), do: frame(?H, [name, 0])
  def encode_command({:mail, args}), do: frame(?M, strings(args))
  def encode_command({:rcpt, args}), do: frame(?R, strings(args))
  def encode_command(:data), do: frame(?T, "")
  def encode_command({:header, name, value}), do: frame(?L, strings([name, value]))
  def encode_command(:end_of_headers), do: frame(?N, "")
  def encode_command({:body, chunk}), do: frame(?B, chunk)
  def encode_command(:end_of_message), do: frame(?E, "")
  def encode_command(:abort), do: frame(?A, "")
  def encode_command(:quit), do: frame(?Q, "")
  def encode_command(:quit_new_connection), do: frame(?K, "")
  def encode_command({:unknown, line}), do: frame(?U, [line, 0])

  defp family_byte(:inet), do: ?4
  defp family_byte(:inet6), do: ?6
  defp family_byte(:unix), do: ?L

  @doc "Decodes the command byte and data of a packet from the MTA."
  @spec decode_command(byte(), binary()) :: {:ok, command()} | {:error, error()}
  def decode_command(?O, <<version::32, actions::32, protocol::32, _::binary>>),
    do: {:ok, {:optneg, version, actions, protocol}}

  def decode_command(?D, <<command>>), do: {:ok, {:macro, command, []}}

  def decode_command(?D, <<command, data::binary>>) do
    with {:ok, strings} <- split(data),
         {:ok, pairs} <- pairs(strings) do
      {:ok, {:macro, command, pairs}}
    else
      :error -> malformed(?D)
    end
  end

  def decode_command(?C, data) do
    case :binary.split(data, <<0>>) do
      [hostname, <<?U, _::binary>>] ->
        {:ok, {:connect, hostname, :unknown, nil, nil}}

      [hostname, <<family, port::16, address::binary>>] when family in [?4, ?6, ?L] ->
        case split(address) do
          {:ok, [address]} -> {:ok, {:connect, hostname, family(family), port, address}}
          _ -> malformed(?C)
        end

      _ ->
        malformed(?C)
    end
  end

  def decode_command(?H, data), do: one_string(?H, data, &{:helo, &1})
  def decode_command(?M, data), do: args(?M, data, &{:mail, &1})
  def decode_command(?R, data), do: args(?R, data, &{:rcpt, &1})
  def decode_command(?T, _data), do: {:ok, :data}

  def decode_command(?L, data) do
    case split(data) do
      {:ok, [name, value]} -> {:ok, {:header, name, value}}
      _ -> malformed(?L)
    end
  end

  def decode_command(?N, _data), do: {:ok, :end_of_headers}
  def decode_command(?B, data), do: {:ok, {:body, data}}
  def decode_command(?E, _data), do: {:ok, :end_of_message}
  def decode_command(?A, _data), do: {:ok, :abort}
  def decode_command(?Q, _data), do: {:ok, :quit}
  def decode_command(?K, _data), do: {:ok, :quit_new_connection}
  def decode_command(?U, data), do: one_string(?U, data, &{:unknown, &1})
  def decode_command(command, _data) when command in [?O, ?D], do: malformed(command)
  def decode_command(command, _data), do: {:error, {:unknown_command, command}}

  defp family(?4), do: :inet
  defp family(?6), do: :inet6
  defp family(?L), do: :unix

  defp args(command, data, build) do
    case split(data) do
      {:ok, [_ | _] = args} -> {:ok, build.(args)}
      _ -> malformed(command)
    end
  end

  ## Responses

  @doc "Encodes a response from the milter as a framed packet."
  @spec encode_response(response()) :: iodata()
  def encode_response({:optneg, version, actions, protocol, macros}) do
    requests = Enum.map(macros, fn {stage, names} -> [<<stage::32>>, names, 0] end)
    frame(?O, [<<version::32, actions::32, protocol::32>> | requests])
  end

  def encode_response(:continue), do: frame(?c, "")
  def encode_response(:accept), do: frame(?a, "")
  def encode_response(:reject), do: frame(?r, "")
  def encode_response(:tempfail), do: frame(?t, "")
  def encode_response(:discard), do: frame(?d, "")
  def encode_response(:skip), do: frame(?s, "")
  def encode_response(:progress), do: frame(?p, "")
  def encode_response(:connection_failure), do: frame(?f, "")
  def encode_response(:shutdown), do: frame(?4, "")
  def encode_response({:reply_code, text}), do: frame(?y, [text, 0])
  def encode_response({:add_recipient, rcpt}), do: frame(?+, [rcpt, 0])

  def encode_response({:add_recipient_with_args, rcpt, args}),
    do: frame(?2, strings([rcpt | List.wrap(args)]))

  def encode_response({:delete_recipient, rcpt}), do: frame(?-, [rcpt, 0])
  def encode_response({:replace_body, chunk}), do: frame(?b, chunk)
  def encode_response({:add_header, name, value}), do: frame(?h, strings([name, value]))

  def encode_response({:insert_header, index, name, value}),
    do: frame(?i, [<<index::32>> | strings([name, value])])

  def encode_response({:change_header, index, name, value}),
    do: frame(?m, [<<index::32>> | strings([name, value])])

  def encode_response({:change_sender, sender, args}),
    do: frame(?e, strings([sender | List.wrap(args)]))

  def encode_response({:quarantine, reason}), do: frame(?q, [reason, 0])
  def encode_response({:set_macros, stage, names}), do: frame(?l, [<<stage::32>>, names, 0])

  @doc "Decodes the command byte and data of a packet from the milter."
  @spec decode_response(byte(), binary()) :: {:ok, response()} | {:error, error()}
  def decode_response(?O, <<version::32, actions::32, protocol::32, rest::binary>>) do
    case macro_requests(rest, []) do
      {:ok, macros} -> {:ok, {:optneg, version, actions, protocol, macros}}
      :error -> malformed(?O)
    end
  end

  def decode_response(?c, _data), do: {:ok, :continue}
  def decode_response(?a, _data), do: {:ok, :accept}
  def decode_response(?r, _data), do: {:ok, :reject}
  def decode_response(?t, _data), do: {:ok, :tempfail}
  def decode_response(?d, _data), do: {:ok, :discard}
  def decode_response(?s, _data), do: {:ok, :skip}
  def decode_response(?p, _data), do: {:ok, :progress}
  def decode_response(?f, _data), do: {:ok, :connection_failure}
  def decode_response(?4, _data), do: {:ok, :shutdown}
  def decode_response(?y, data), do: one_string(?y, data, &{:reply_code, &1})
  def decode_response(?+, data), do: one_string(?+, data, &{:add_recipient, &1})

  def decode_response(?2, data) do
    case split(data) do
      {:ok, [rcpt]} -> {:ok, {:add_recipient_with_args, rcpt, nil}}
      {:ok, [rcpt, args]} -> {:ok, {:add_recipient_with_args, rcpt, args}}
      _ -> malformed(?2)
    end
  end

  def decode_response(?-, data), do: one_string(?-, data, &{:delete_recipient, &1})
  def decode_response(?b, data), do: {:ok, {:replace_body, data}}

  def decode_response(?h, data) do
    case split(data) do
      {:ok, [name, value]} -> {:ok, {:add_header, name, value}}
      _ -> malformed(?h)
    end
  end

  def decode_response(command, <<index::32, data::binary>>) when command in [?i, ?m] do
    case split(data) do
      {:ok, [name, value]} when command == ?i -> {:ok, {:insert_header, index, name, value}}
      {:ok, [name, value]} -> {:ok, {:change_header, index, name, value}}
      _ -> malformed(command)
    end
  end

  def decode_response(?e, data) do
    case split(data) do
      {:ok, [sender]} -> {:ok, {:change_sender, sender, nil}}
      {:ok, [sender, args]} -> {:ok, {:change_sender, sender, args}}
      _ -> malformed(?e)
    end
  end

  def decode_response(?q, data), do: one_string(?q, data, &{:quarantine, &1})

  def decode_response(?l, <<stage::32, data::binary>>),
    do: one_string(?l, data, &{:set_macros, stage, &1})

  def decode_response(command, _data) when command in [?O, ?i, ?m, ?l], do: malformed(command)
  def decode_response(command, _data), do: {:error, {:unknown_command, command}}

  defp macro_requests(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp macro_requests(<<stage::32, rest::binary>>, acc) do
    case :binary.split(rest, <<0>>) do
      [names, rest] -> macro_requests(rest, [{stage, names} | acc])
      [_] -> :error
    end
  end

  defp macro_requests(_rest, _acc), do: :error

  ## Strings

  defp strings(list), do: Enum.map(list, &[&1, 0])

  # NUL-terminated strings: the data must end with a NUL.
  defp split(data) do
    case :binary.split(data, <<0>>, [:global]) do
      [_] -> :error
      parts -> if List.last(parts) == "", do: {:ok, Enum.drop(parts, -1)}, else: :error
    end
  end

  defp one_string(command, data, build) do
    case split(data) do
      {:ok, [string]} -> {:ok, build.(string)}
      _ -> malformed(command)
    end
  end

  defp pairs([]), do: {:ok, []}

  defp pairs([name, value | rest]) do
    with {:ok, pairs} <- pairs(rest), do: {:ok, [{name, value} | pairs]}
  end

  defp pairs([_name]), do: :error

  defp malformed(command), do: {:error, {:malformed, command}}
end
