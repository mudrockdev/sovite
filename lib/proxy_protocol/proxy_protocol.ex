defmodule Sovite.ProxyProtocol do
  @moduledoc """
  The HAProxy PROXY protocol, versions 1 (text) and 2 (binary), which a
  proxy or load balancer sends first on a connection to pass on the
  original client and server addresses.

  `parse/2` decodes a header at the start of a binary and `read/3` reads
  one from a socket; `encode_v1/1` and `encode_v2/1` build headers for
  clients. A parsed header is a `Sovite.ProxyProtocol.Header`.

      {:ok, socket} = :gen_tcp.accept(listen_socket)
      {:ok, %Header{command: :proxy, source: {client_ip, client_port}}} =
        Sovite.ProxyProtocol.read(socket, 10_000)

  Parsing is strict, as the specification requires: anything that is not
  exactly a valid header is an error, and the connection should be
  closed. Only accept headers from trusted proxies: a header is just
  what its sender claims.

  ## Version 1

  A line such as `PROXY TCP4 192.0.2.1 198.51.100.1 56324 25\\r\\n` of at
  most 107 bytes. Addresses and ports are decimal without leading zeros.
  `PROXY UNKNOWN` is parsed as `:unspec`, with the rest of its line
  ignored. Version 1 has no `LOCAL` command and no TLVs.

  ## Version 2

  A 16-byte prefix (signature, version and command, family and
  protocol, length) followed by the addresses and TLVs. A `LOCAL` header
  is parsed without its address block, which the receiver must ignore.
  With `AF_UNSPEC` the whole block is TLVs. Headers longer than
  `:max_length` are rejected. A `PP2_TYPE_CRC32C` checksum is verified;
  the well-known TLVs must be well-formed and appear at most once.

  ## Errors

    * `:invalid_signature` - neither a version 1 nor a version 2 header.
    * Version 1: `:line_too_long`, `:invalid_line` (bad syntax or
      characters, a lone CR or LF), `:invalid_transport` (not `TCP4`,
      `TCP6`, or `UNKNOWN`), `:invalid_address`, `:invalid_port`.
    * Version 2: `:invalid_version`, `:invalid_command`, `:invalid_family`
      (an undefined family or protocol), `:invalid_length` (too short
      for the family's addresses), `:header_too_long`, `:invalid_tlv`
      (truncated, malformed, or repeated), `:crc32c_mismatch`.
  """

  import Bitwise

  alias Sovite.Net
  alias Sovite.ProxyProtocol.{CRC32C, Header}

  @v2_signature <<0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A>>

  # "PROXY UNKNOWN\r\n" is the shortest header of either version.
  @min_length 15
  @v1_max_length 107
  @max_length 4096
  @unique_id_max 128

  @families %{
    0x00 => :unspec,
    0x11 => :tcp4,
    0x12 => :udp4,
    0x21 => :tcp6,
    0x22 => :udp6,
    0x31 => :unix,
    0x32 => :unix_dgram
  }
  @family_bytes Map.new(@families, fn {byte, transport} -> {transport, byte} end)

  @tlv_types %{
    alpn: 0x01,
    authority: 0x02,
    crc32c: 0x03,
    noop: 0x04,
    unique_id: 0x05,
    ssl: 0x20,
    netns: 0x30
  }
  @ssl_subtypes [version: 0x21, cn: 0x22, cipher: 0x23, sig_alg: 0x24, key_alg: 0x25]
  @ssl_flags [ssl: 0x01, cert_conn: 0x02, cert_sess: 0x04]

  @type error_reason ::
          :invalid_signature
          | :line_too_long
          | :invalid_line
          | :invalid_transport
          | :invalid_address
          | :invalid_port
          | :invalid_version
          | :invalid_command
          | :invalid_family
          | :invalid_length
          | :header_too_long
          | :invalid_tlv
          | :crc32c_mismatch

  @doc """
  Parses a header at the start of `data`. Returns the header and the
  bytes after it, which belong to the application protocol.

  On incomplete input, returns `{:more, n}` when at least `n` more bytes
  are needed (version 2), or `{:more, :unknown}` when the end cannot be
  known yet (version 1, or too little input to tell the version).

  Options:

    * `:max_length` - the longest version 2 header accepted, in bytes.
      Defaults to 4096.

  Examples:

      iex> {:ok, header, rest} =
      ...>   Sovite.ProxyProtocol.parse("PROXY TCP4 192.0.2.1 198.51.100.1 56324 25\\r\\nEHLO")
      iex> {header.source, header.destination, rest}
      {{{192, 0, 2, 1}, 56324}, {{198, 51, 100, 1}, 25}, "EHLO"}
      iex> Sovite.ProxyProtocol.parse("PROXY TCP4 192.0.2.1")
      {:more, :unknown}
      iex> Sovite.ProxyProtocol.parse("EHLO client.example\\r\\n")
      {:error, :invalid_signature}
  """
  @spec parse(binary(), keyword()) ::
          {:ok, Header.t(), rest :: binary()}
          | {:more, pos_integer() | :unknown}
          | {:error, error_reason()}
  def parse(data, opts \\ []) when is_binary(data) do
    cond do
      data == "" -> {:more, :unknown}
      String.starts_with?(data, @v2_signature) -> parse_v2(data, max_length(opts))
      String.starts_with?(data, "PROXY ") -> parse_v1(data)
      String.starts_with?(@v2_signature, data) -> {:more, 16 - byte_size(data)}
      String.starts_with?("PROXY ", data) -> {:more, :unknown}
      true -> {:error, :invalid_signature}
    end
  end

  defp max_length(opts), do: Keyword.get(opts, :max_length, @max_length)

  @doc """
  Reads a header from `socket`, a passive (`active: false`) `:gen_tcp`
  socket in binary mode with `packet: :raw`. Fails unless the whole
  header arrives within `timeout` milliseconds.

  Exactly the header is read: what the client sent after it is left
  on the socket for the application protocol. A version 1 line is read
  a byte at a time past its first 15 bytes (from the socket's buffer,
  not a system call each), a version 2 header by its length.

  Takes the options of `parse/2`. Returns `{:error, reason}` with a
  reason from `parse/2`, `:timeout`, `:closed`, or another
  `:inet.posix()` error.
  """
  @spec read(:gen_tcp.socket(), non_neg_integer(), keyword()) ::
          {:ok, Header.t()} | {:error, error_reason() | :timeout | :closed | :inet.posix()}
  def read(socket, timeout, opts \\ []) do
    read(socket, <<>>, System.monotonic_time(:millisecond) + timeout, opts)
  end

  defp read(socket, acc, deadline, opts) do
    case parse(acc, opts) do
      {:ok, header, _rest} ->
        {:ok, header}

      {:more, needed} ->
        # Never ask for more than the shortest header could still need.
        count = if is_integer(needed), do: needed, else: max(@min_length - byte_size(acc), 1)
        remaining = deadline - System.monotonic_time(:millisecond)

        with true <- remaining > 0 || {:error, :timeout},
             {:ok, data} <- :gen_tcp.recv(socket, count, remaining) do
          read(socket, acc <> data, deadline, opts)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  ## Version 1

  defp parse_v1(data) do
    case :binary.match(data, "\r\n") do
      {position, 2} when position + 2 <= @v1_max_length ->
        <<line::binary-size(^position), "\r\n", rest::binary>> = data
        with {:ok, header} <- parse_v1_line(line), do: {:ok, header, rest}

      {_position, 2} ->
        {:error, :line_too_long}

      :nomatch when byte_size(data) >= @v1_max_length ->
        {:error, :line_too_long}

      :nomatch ->
        if printable_partial?(data), do: {:more, :unknown}, else: {:error, :invalid_line}
    end
  end

  defp parse_v1_line("PROXY " <> rest = line) do
    if printable?(line),
      do: parse_v1_fields(String.split(rest, " ")),
      else: {:error, :invalid_line}
  end

  defp parse_v1_fields(["UNKNOWN" | _ignored]), do: {:ok, %Header{version: 1}}

  defp parse_v1_fields([protocol, source, destination, source_port, destination_port])
       when protocol in ["TCP4", "TCP6"] do
    transport = if protocol == "TCP4", do: :tcp4, else: :tcp6

    with {:ok, source_ip} <- v1_ip(source, transport),
         {:ok, destination_ip} <- v1_ip(destination, transport),
         {:ok, source_port} <- v1_port(source_port),
         {:ok, destination_port} <- v1_port(destination_port) do
      {:ok,
       %Header{
         version: 1,
         transport: transport,
         source: {source_ip, source_port},
         destination: {destination_ip, destination_port}
       }}
    end
  end

  defp parse_v1_fields([protocol | _fields]) when protocol in ["TCP4", "TCP6"],
    do: {:error, :invalid_line}

  defp parse_v1_fields(_fields), do: {:error, :invalid_transport}

  defp printable?(data), do: Regex.match?(~r/\A[\x20-\x7E]*\z/, data)

  # A line still waiting for its LF.
  defp printable_partial?(data), do: Regex.match?(~r/\A[\x20-\x7E]*\r?\z/, data)

  # No leading zeros, unlike :inet's parser.
  defp v1_ip(string, :tcp4) do
    with true <- Regex.match?(~r/\A(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}\z/, string),
         {:ok, ip} when tuple_size(ip) == 4 <- Net.parse_ip(string) do
      {:ok, ip}
    else
      _ -> {:error, :invalid_address}
    end
  end

  defp v1_ip(string, :tcp6) do
    case Net.parse_ip(string) do
      {:ok, ip} when tuple_size(ip) == 8 -> {:ok, ip}
      _ -> {:error, :invalid_address}
    end
  end

  defp v1_port(string) do
    with true <- Regex.match?(~r/\A(0|[1-9][0-9]{0,4})\z/, string),
         port when port <= 65_535 <- String.to_integer(string) do
      {:ok, port}
    else
      _ -> {:error, :invalid_port}
    end
  end

  ## Version 2

  defp parse_v2(<<prefix::binary-size(16), rest::binary>>, max_length) do
    <<_signature::binary-size(12), version::4, command::4, family, length::16>> = prefix

    cond do
      version != 2 -> {:error, :invalid_version}
      command not in [0, 1] -> {:error, :invalid_command}
      16 + length > max_length -> {:error, :header_too_long}
      byte_size(rest) < length -> {:more, length - byte_size(rest)}
      true -> parse_v2_block(command, family, prefix, rest, length)
    end
  end

  defp parse_v2(data, _max_length), do: {:more, 16 - byte_size(data)}

  defp parse_v2_block(command, family, prefix, data, length) do
    <<block::binary-size(^length), rest::binary>> = data

    if command == 0 do
      # LOCAL: the receiver ignores the whole block, family included.
      {:ok, %Header{command: :local}, rest}
    else
      with {:ok, transport} <- family(family),
           {:ok, source, destination, addresses, tlv_data} <- split_addresses(transport, block),
           {:ok, tlvs} <- split_tlvs(tlv_data, []),
           :ok <- check_crc32c(prefix, addresses, tlvs),
           header = %Header{
             transport: transport,
             source: source,
             destination: destination,
             tlvs: tlvs
           },
           {:ok, header} <- decode_tlvs(tlvs, header) do
        {:ok, header, rest}
      end
    end
  end

  defp family(byte) do
    case Map.fetch(@families, byte) do
      {:ok, transport} -> {:ok, transport}
      :error -> {:error, :invalid_family}
    end
  end

  defp split_addresses(:unspec, block), do: {:ok, nil, nil, <<>>, block}

  defp split_addresses(transport, block) when transport in [:tcp4, :udp4] do
    case block do
      <<addresses::binary-size(12), tlvs::binary>> ->
        <<s::binary-size(4), d::binary-size(4), sp::16, dp::16>> = addresses
        {:ok, {ip(s, 8), sp}, {ip(d, 8), dp}, addresses, tlvs}

      _ ->
        {:error, :invalid_length}
    end
  end

  defp split_addresses(transport, block) when transport in [:tcp6, :udp6] do
    case block do
      <<addresses::binary-size(36), tlvs::binary>> ->
        <<s::binary-size(16), d::binary-size(16), sp::16, dp::16>> = addresses
        {:ok, {ip(s, 16), sp}, {ip(d, 16), dp}, addresses, tlvs}

      _ ->
        {:error, :invalid_length}
    end
  end

  defp split_addresses(_unix, block) do
    case block do
      <<addresses::binary-size(216), tlvs::binary>> ->
        <<s::binary-size(108), d::binary-size(108)>> = addresses
        {:ok, {:local, unix_path(s)}, {:local, unix_path(d)}, addresses, tlvs}

      _ ->
        {:error, :invalid_length}
    end
  end

  defp ip(bytes, size), do: List.to_tuple(for <<part::size(^size) <- bytes>>, do: part)

  # NUL-terminated. Abstract socket names start with a NUL; all NULs is
  # no path.
  defp unix_path(<<0, name::binary>>) do
    case until_nul(name) do
      "" -> ""
      name -> <<0>> <> name
    end
  end

  defp unix_path(path), do: until_nul(path)

  defp until_nul(path), do: path |> :binary.split(<<0>>) |> hd()

  defp split_tlvs(<<type, length::16, value::binary-size(length), rest::binary>>, acc),
    do: split_tlvs(rest, [{type, value} | acc])

  defp split_tlvs(<<>>, acc), do: {:ok, Enum.reverse(acc)}
  defp split_tlvs(_truncated, _acc), do: {:error, :invalid_tlv}

  defp check_crc32c(prefix, addresses, tlvs) do
    case for({0x03, value} <- tlvs, do: value) do
      [] ->
        :ok

      [<<crc::32>>] ->
        if crc32c(prefix, addresses, tlvs) == crc, do: :ok, else: {:error, :crc32c_mismatch}

      _ ->
        {:error, :invalid_tlv}
    end
  end

  # Over the whole header, with the checksum itself zeroed.
  defp crc32c(prefix, addresses, tlvs) do
    tlvs =
      for {type, value} <- tlvs, do: if(type == 0x03, do: {type, <<0::32>>}, else: {type, value})

    CRC32C.checksum([prefix, addresses, encode_tlvs(tlvs)])
  end

  defp decode_tlvs([], header), do: {:ok, header}

  defp decode_tlvs([tlv | tlvs], header) do
    case decode_tlv(tlv, header) do
      {:ok, header} -> decode_tlvs(tlvs, header)
      :error -> {:error, :invalid_tlv}
    end
  end

  defp decode_tlv({0x01, alpn}, header), do: put_once(header, :alpn, alpn)

  defp decode_tlv({0x02, authority}, header),
    do: if(String.valid?(authority), do: put_once(header, :authority, authority), else: :error)

  defp decode_tlv({0x05, id}, header) when byte_size(id) <= @unique_id_max,
    do: put_once(header, :unique_id, id)

  defp decode_tlv({0x05, _id}, _header), do: :error

  defp decode_tlv({0x20, value}, header) do
    with {:ok, ssl} <- decode_ssl(value), do: put_once(header, :ssl, ssl)
  end

  defp decode_tlv({0x30, netns}, header),
    do: if(printable?(netns), do: put_once(header, :netns, netns), else: :error)

  # CRC32C was checked already; NOOP and other types are kept raw only.
  defp decode_tlv(_tlv, header), do: {:ok, header}

  defp put_once(map, key, value),
    do: if(Map.fetch!(map, key) == nil, do: {:ok, Map.put(map, key, value)}, else: :error)

  defp decode_ssl(<<client, verify::32, sub_tlvs::binary>>) do
    ssl = %{
      client: for({flag, bit} <- @ssl_flags, (client &&& bit) != 0, do: flag),
      verify: verify,
      version: nil,
      cn: nil,
      cipher: nil,
      sig_alg: nil,
      key_alg: nil,
      tlvs: []
    }

    case split_tlvs(sub_tlvs, []) do
      {:ok, tlvs} -> decode_ssl_fields(tlvs, %{ssl | tlvs: tlvs})
      {:error, _reason} -> :error
    end
  end

  defp decode_ssl(_value), do: :error

  defp decode_ssl_fields([], ssl), do: {:ok, ssl}

  defp decode_ssl_fields([{type, value} | tlvs], ssl) do
    case List.keyfind(@ssl_subtypes, type, 1) do
      nil ->
        decode_ssl_fields(tlvs, ssl)

      {key, _type} ->
        with {:ok, ssl} <- decode_ssl_field(ssl, key, value), do: decode_ssl_fields(tlvs, ssl)
    end
  end

  defp decode_ssl_field(ssl, key, value),
    do: if(String.valid?(value), do: put_once(ssl, key, value), else: :error)

  ## Encoding

  @doc """
  Encodes a version 1 header. A `:proxy` header over `:tcp4` or `:tcp6`
  carries its addresses; anything else becomes `PROXY UNKNOWN`. TLVs
  are not sent. Raises `ArgumentError` on addresses that do not match
  the transport.

      iex> Sovite.ProxyProtocol.encode_v1(%Sovite.ProxyProtocol.Header{
      ...>   transport: :tcp4,
      ...>   source: {{192, 0, 2, 1}, 56324},
      ...>   destination: {{198, 51, 100, 1}, 25}
      ...> })
      "PROXY TCP4 192.0.2.1 198.51.100.1 56324 25\\r\\n"
      iex> Sovite.ProxyProtocol.encode_v1(%Sovite.ProxyProtocol.Header{command: :local})
      "PROXY UNKNOWN\\r\\n"
  """
  @spec encode_v1(Header.t()) :: binary()
  def encode_v1(%Header{command: :proxy, transport: transport} = header)
      when transport in [:tcp4, :tcp6] do
    {source_ip, source_port} = endpoint!(header.source, transport)
    {destination_ip, destination_port} = endpoint!(header.destination, transport)
    protocol = if transport == :tcp4, do: "TCP4", else: "TCP6"

    "PROXY #{protocol} #{:inet.ntoa(source_ip)} #{:inet.ntoa(destination_ip)} " <>
      "#{source_port} #{destination_port}\r\n"
  end

  def encode_v1(%Header{}), do: "PROXY UNKNOWN\r\n"

  @doc """
  Encodes a version 2 header with the TLVs in `:tlvs` (the decoded TLV
  fields are ignored). A `PP2_TYPE_CRC32C` TLV among them, such as
  `tlv(:crc32c)`, gets the header's checksum. A `:local` header is sent
  with no addresses and no TLVs. Raises `ArgumentError` on addresses
  that do not match the transport, or a header over 64 KiB.
  """
  @spec encode_v2(Header.t()) :: binary()
  def encode_v2(%Header{command: :local}), do: @v2_signature <> <<0x20, 0x00, 0::16>>

  def encode_v2(%Header{command: :proxy, transport: transport, tlvs: tlvs} = header) do
    family = Map.fetch!(@family_bytes, transport)
    addresses = encode_addresses(transport, header.source, header.destination)
    length = byte_size(addresses) + IO.iodata_length(encode_tlvs(tlvs))

    if length > 0xFFFF, do: raise(ArgumentError, "PROXY header too long")

    prefix = @v2_signature <> <<0x21, family, length::16>>
    crc = crc32c(prefix, addresses, tlvs)

    tlvs =
      for {type, value} <- tlvs,
          do: if(type == 0x03, do: {type, <<crc::32>>}, else: {type, value})

    IO.iodata_to_binary([prefix, addresses, encode_tlvs(tlvs)])
  end

  defp encode_addresses(:unspec, _source, _destination), do: <<>>

  defp encode_addresses(transport, source, destination) when transport in [:unix, :unix_dgram],
    do: unix_address!(source) <> unix_address!(destination)

  defp encode_addresses(transport, source, destination) do
    family = if transport in [:tcp4, :udp4], do: :tcp4, else: :tcp6
    size = if family == :tcp4, do: 8, else: 16
    {source_ip, source_port} = endpoint!(source, family)
    {destination_ip, destination_port} = endpoint!(destination, family)

    <<ip_bytes(source_ip, size)::binary, ip_bytes(destination_ip, size)::binary, source_port::16,
      destination_port::16>>
  end

  defp ip_bytes(ip, size),
    do: for(part <- Tuple.to_list(ip), into: <<>>, do: <<part::size(size)>>)

  defp endpoint!({ip, port} = endpoint, family) when port in 0..65_535 do
    valid = if family == :tcp4, do: :inet.is_ipv4_address(ip), else: :inet.is_ipv6_address(ip)
    if valid, do: endpoint, else: raise(ArgumentError, "invalid #{family} address #{inspect(ip)}")
  end

  defp endpoint!(endpoint, family),
    do: raise(ArgumentError, "invalid #{family} endpoint #{inspect(endpoint)}")

  defp unix_address!({:local, path}) when is_binary(path) and byte_size(path) <= 108,
    do: path <> :binary.copy(<<0>>, 108 - byte_size(path))

  defp unix_address!(address),
    do: raise(ArgumentError, "invalid UNIX socket address #{inspect(address)}")

  defp encode_tlvs(tlvs) do
    for {type, value} <- tlvs do
      unless type in 0..255 and is_binary(value) and byte_size(value) <= 0xFFFF,
        do: raise(ArgumentError, "invalid TLV #{inspect({type, value})}")

      [type, <<byte_size(value)::16>>, value]
    end
  end

  @doc """
  Builds a well-known version 2 TLV for `Header` `:tlvs`.

    * `:alpn`, `:authority`, `:unique_id`, `:netns`, `:noop` - `value` is
      the binary to send.
    * `:ssl` - `value` is a map like `t:Sovite.ProxyProtocol.Header.ssl/0`,
      every key optional (`:client` defaults to `[]`, `:verify` to `0`,
      `:tlvs` is ignored).

  `tlv(:crc32c)` is a placeholder that `encode_v2/1` fills in.

      iex> Sovite.ProxyProtocol.tlv(:alpn, "h2")
      {0x01, "h2"}
      iex> Sovite.ProxyProtocol.tlv(:ssl, %{client: [:ssl], version: "TLSv1.3"})
      {0x20, <<1, 0, 0, 0, 0, 0x21, 0, 7, "TLSv1.3">>}
  """
  @spec tlv(:alpn | :authority | :unique_id | :netns | :noop | :ssl, binary() | map()) ::
          Header.tlv()
  def tlv(:ssl, ssl) when is_map(ssl) do
    client =
      for {flag, bit} <- @ssl_flags, flag in Map.get(ssl, :client, []), reduce: 0 do
        acc -> acc ||| bit
      end

    sub_tlvs =
      for {key, type} <- @ssl_subtypes,
          value <- [Map.get(ssl, key)],
          value != nil,
          do: {type, value}

    value = IO.iodata_to_binary([client, <<Map.get(ssl, :verify, 0)::32>>, encode_tlvs(sub_tlvs)])
    {@tlv_types.ssl, value}
  end

  def tlv(type, value)
      when type in [:alpn, :authority, :unique_id, :netns, :noop] and is_binary(value),
      do: {Map.fetch!(@tlv_types, type), value}

  @doc "Returns a `PP2_TYPE_CRC32C` placeholder, see `tlv/2`."
  @spec tlv(:crc32c) :: Header.tlv()
  def tlv(:crc32c), do: {@tlv_types.crc32c, <<0::32>>}
end
