defmodule Sovite.ProxyProtocolTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Sovite.ProxyProtocol

  alias Sovite.ProxyProtocol.{CRC32C, Header}

  doctest Sovite.ProxyProtocol
  doctest Sovite.ProxyProtocol.CRC32C

  @signature <<0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A>>

  @tcp4 %Header{
    transport: :tcp4,
    source: {{192, 0, 2, 1}, 56_324},
    destination: {{198, 51, 100, 1}, 25}
  }

  @tcp6 %Header{
    transport: :tcp6,
    source: {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, 1234},
    destination: {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 2}, 587}
  }

  # A hand-built version 2 header: PROXY, TCP over IPv4, no TLVs.
  @tcp4_v2 @signature <>
             <<0x21, 0x11, 12::16, 192, 0, 2, 1, 198, 51, 100, 1, 56_324::16, 25::16>>

  defp v2(command_byte, family, block),
    do: @signature <> <<command_byte, family, byte_size(block)::16>> <> block

  defp tcp4_block(tlvs), do: <<192, 0, 2, 1, 198, 51, 100, 1, 1::16, 2::16>> <> tlvs

  defp raw_tlv(type, value), do: <<type, byte_size(value)::16>> <> value

  defp round_trip(header, encoder) do
    assert {:ok, parsed, "rest"} = parse(encoder.(header) <> "rest")
    parsed
  end

  describe "CRC32C" do
    test "matches the RFC 3720 test vectors" do
      assert CRC32C.checksum(:binary.copy(<<0>>, 32)) == 0x8A9136AA
      assert CRC32C.checksum(:binary.copy(<<0xFF>>, 32)) == 0x62A8AB43
      assert CRC32C.checksum(:binary.list_to_bin(Enum.to_list(0..31))) == 0x46DD794E
      assert CRC32C.checksum(:binary.list_to_bin(Enum.to_list(31..0//-1))) == 0x113FDB5C
      assert CRC32C.checksum(["1234", ["5", "6789"]]) == 0xE3069283
    end
  end

  describe "parse/2, version 1" do
    test "parses TCP over IPv4 and IPv6" do
      assert parse("PROXY TCP4 192.0.2.1 198.51.100.1 56324 25\r\nEHLO x\r\n") ==
               {:ok, %Header{@tcp4 | version: 1}, "EHLO x\r\n"}

      assert parse("PROXY TCP6 2001:db8::1 2001:db8::2 1234 587\r\n") ==
               {:ok, %Header{@tcp6 | version: 1}, ""}

      assert {:ok, %Header{source: {{0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0201}, 0}}, ""} =
               parse("PROXY TCP6 ::ffff:192.0.2.1 :: 0 65535\r\n")

      assert {:ok,
              %Header{source: {{0, 0, 0, 0}, 0}, destination: {{255, 255, 255, 255}, 65_535}}, ""} =
               parse("PROXY TCP4 0.0.0.0 255.255.255.255 0 65535\r\n")
    end

    test "parses UNKNOWN and ignores the rest of its line" do
      unknown = %Header{version: 1, transport: :unspec}
      assert parse("PROXY UNKNOWN\r\nX") == {:ok, unknown, "X"}
      assert parse("PROXY UNKNOWN \r\n") == {:ok, unknown, ""}
      assert parse("PROXY UNKNOWN ffff::1 ffff::2 65535 65535\r\n") == {:ok, unknown, ""}
    end

    test "accepts lines of up to 107 bytes, CRLF included" do
      line = "PROXY UNKNOWN " <> String.duplicate("x", 91) <> "\r\n"
      assert byte_size(line) == 107
      assert {:ok, %Header{}, ""} = parse(line)

      assert parse("PROXY UNKNOWN " <> String.duplicate("x", 92) <> "\r\n") ==
               {:error, :line_too_long}

      assert parse("PROXY UNKNOWN " <> String.duplicate("x", 93)) == {:error, :line_too_long}

      assert parse("PROXY UNKNOWN " <> String.duplicate("x", 92) <> "\r") ==
               {:error, :line_too_long}
    end

    test "asks for more input until the CRLF" do
      line = "PROXY TCP4 192.0.2.1 198.51.100.1 56324 25\r\n"

      for size <- 0..(byte_size(line) - 1) do
        assert parse(binary_part(line, 0, size)) == {:more, :unknown}
      end
    end

    test "rejects bad syntax and characters" do
      for line <- [
            "PROXY TCP4 192.0.2.1 198.51.100.1 56324 25\n",
            "PROXY TCP4 192.0.2.1 198.51.100.1 56324 25\rX",
            "PROXY UNKNOWN\n",
            "PROXY UNKNOWN \t\r\n",
            "PROXY UNKNOWN \xFF\r\n",
            "PROXY TCP4 192.0.2.1 198.51.100.1 56324\r\n",
            "PROXY TCP4 192.0.2.1 198.51.100.1 56324 25 \r\n",
            "PROXY TCP4  192.0.2.1 198.51.100.1 56324 25\r\n",
            "PROXY TCP4\r\n"
          ] do
        assert parse(line) == {:error, :invalid_line}, inspect(line)
      end
    end

    test "rejects other transports" do
      for line <- [
            "PROXY TCP5 192.0.2.1 198.51.100.1 56324 25\r\n",
            "PROXY tcp4 192.0.2.1 198.51.100.1 56324 25\r\n",
            "PROXY UDP4 192.0.2.1 198.51.100.1 56324 25\r\n",
            "PROXY  UNKNOWN\r\n",
            "PROXY UNKNOWNX\r\n",
            "PROXY \r\n"
          ] do
        assert parse(line) == {:error, :invalid_transport}, inspect(line)
      end
    end

    test "rejects bad addresses" do
      for {protocol, source} <- [
            {"TCP4", "01.0.2.1"},
            {"TCP4", "192.0.2.01"},
            {"TCP4", "256.0.2.1"},
            {"TCP4", "192.0.2"},
            {"TCP4", "192.0.2.1.5"},
            {"TCP4", "2001:db8::1"},
            {"TCP4", "::ffff:192.0.2.1"},
            {"TCP6", "192.0.2.1"},
            {"TCP6", "2001:db8:::1"},
            {"TCP6", "[::1]"},
            {"TCP6", "fe80::1%1"},
            {"TCP6", "x"}
          ] do
        line = "PROXY #{protocol} #{source} #{source} 1 2\r\n"
        assert parse(line) == {:error, :invalid_address}, line
      end
    end

    test "rejects bad ports" do
      for port <- ["65536", "99999", "010", "00", "-1", "+1", "1a", "0x10", "123456"] do
        line = "PROXY TCP4 192.0.2.1 198.51.100.1 1 #{port}\r\n"
        assert parse(line) == {:error, :invalid_port}, line
        line = "PROXY TCP4 192.0.2.1 198.51.100.1 #{port} 1\r\n"
        assert parse(line) == {:error, :invalid_port}, line
      end
    end

    test "rejects other protocols" do
      assert parse("EHLO client.example\r\n") == {:error, :invalid_signature}
      assert parse("PROXX") == {:error, :invalid_signature}
      assert parse("proxy ") == {:error, :invalid_signature}
      assert parse("PROXYTCP4") == {:error, :invalid_signature}
      assert parse(<<0x16, 0x03, 0x01>>) == {:error, :invalid_signature}
      assert parse("") == {:more, :unknown}
      assert parse("PROX") == {:more, :unknown}
    end
  end

  describe "parse/2, version 2" do
    test "parses a hand-built header" do
      assert parse(@tcp4_v2 <> "EHLO") == {:ok, @tcp4, "EHLO"}
      assert encode_v2(@tcp4) == @tcp4_v2
    end

    test "round-trips every transport" do
      for header <- [
            @tcp4,
            @tcp6,
            %Header{@tcp4 | transport: :udp4},
            %Header{@tcp6 | transport: :udp6},
            %Header{
              transport: :unix,
              source: {:local, "/run/client.sock"},
              destination: {:local, :binary.copy("d", 108)}
            },
            %Header{
              transport: :unix_dgram,
              source: {:local, <<0, "abstract">>},
              destination: {:local, ""}
            },
            %Header{transport: :unspec},
            %Header{transport: :unspec, tlvs: [{0xE0, "x"}]}
          ] do
        assert round_trip(header, &encode_v2/1) == header
      end
    end

    test "parses LOCAL without its address block" do
      assert parse(v2(0x20, 0x00, <<>>) <> "X") == {:ok, %Header{command: :local}, "X"}

      # The block and family are ignored, whatever they are.
      assert parse(v2(0x20, 0xFF, <<1, 2, 3>>)) == {:ok, %Header{command: :local}, ""}
      assert parse(v2(0x20, 0x11, tcp4_block(<<0xFF>>))) == {:ok, %Header{command: :local}, ""}

      assert encode_v2(%Header{@tcp4 | command: :local, tlvs: [{1, "h2"}]}) ==
               v2(0x20, 0x00, <<>>)
    end

    test "reads UNIX paths up to the first NUL" do
      path = fn name -> name <> :binary.copy(<<0>>, 108 - byte_size(name)) end
      block = path.("/a\0junk") <> path.(<<0, "abs", 0, "junk">>)

      assert {:ok, %Header{source: {:local, "/a"}, destination: {:local, <<0, "abs">>}}, ""} =
               parse(v2(0x21, 0x31, block))
    end

    test "asks for the missing bytes" do
      header = encode_v2(%Header{@tcp4 | tlvs: [{0x01, "h2"}]})

      for size <- 1..(byte_size(header) - 1) do
        expected = if size < 16, do: 16 - size, else: byte_size(header) - size
        assert parse(binary_part(header, 0, size)) == {:more, expected}
      end
    end

    test "rejects other versions and commands" do
      for byte <- [0x01, 0x11, 0x31, 0xF1] do
        assert parse(v2(byte, 0x11, tcp4_block(<<>>))) == {:error, :invalid_version}
      end

      for byte <- 0x22..0x2F do
        assert parse(v2(byte, 0x11, tcp4_block(<<>>))) == {:error, :invalid_command}
      end

      # Detected from the prefix alone.
      assert parse(@signature <> <<0x13, 0x11, 0xFFFF::16>>) == {:error, :invalid_version}
    end

    test "rejects undefined families and protocols" do
      for family <- [0x01, 0x02, 0x03, 0x10, 0x13, 0x20, 0x30, 0x41, 0xFF] do
        assert parse(v2(0x21, family, :binary.copy(<<0>>, 216))) == {:error, :invalid_family}
      end
    end

    test "rejects address blocks too short for the family" do
      for {family, size} <- [
            {0x11, 11},
            {0x12, 0},
            {0x21, 35},
            {0x22, 12},
            {0x31, 215},
            {0x32, 1}
          ] do
        assert parse(v2(0x21, family, :binary.copy(<<0>>, size))) == {:error, :invalid_length}
      end
    end

    test "rejects headers longer than :max_length" do
      header = encode_v2(%Header{@tcp4 | tlvs: [{0xE0, :binary.copy("x", 4096 - 31)}]})
      assert byte_size(header) == 4096
      assert {:ok, _header, ""} = parse(header)

      too_long = encode_v2(%Header{@tcp4 | tlvs: [{0xE0, :binary.copy("x", 4096 - 30)}]})
      assert parse(too_long) == {:error, :header_too_long}
      assert {:ok, _header, ""} = parse(too_long, max_length: 65_551)

      # Rejected before the body arrives.
      assert parse(binary_part(too_long, 0, 16)) == {:error, :header_too_long}
      assert parse(@tcp4_v2, max_length: 27) == {:error, :header_too_long}
      assert {:ok, _header, ""} = parse(@tcp4_v2, max_length: 28)
    end

    test "rejects truncated TLVs" do
      for tlvs <- [<<1>>, <<1, 0>>, <<1, 0, 2, ?h>>, raw_tlv(1, "h2") <> <<0xE0, 0>>] do
        assert parse(v2(0x21, 0x11, tcp4_block(tlvs))) == {:error, :invalid_tlv}
        assert parse(v2(0x21, 0x00, tlvs)) == {:error, :invalid_tlv}
      end
    end

    test "rejects malformed or repeated well-known TLVs" do
      for tlvs <- [
            raw_tlv(0x01, "h2") <> raw_tlv(0x01, "h2"),
            raw_tlv(0x02, <<0xFF>>),
            raw_tlv(0x02, "a") <> raw_tlv(0x02, "b"),
            raw_tlv(0x03, <<0, 0, 0>>),
            raw_tlv(0x05, :binary.copy("i", 129)),
            raw_tlv(0x20, <<1, 0, 0, 0>>),
            raw_tlv(0x20, <<1, 0, 0, 0, 0, 0x21, 0, 9, "TLS">>),
            raw_tlv(0x20, <<1, 0, 0, 0, 0>> <> raw_tlv(0x22, <<0xC3>>)),
            raw_tlv(0x20, <<1, 0, 0, 0, 0>> <> raw_tlv(0x21, "a") <> raw_tlv(0x21, "b")),
            raw_tlv(0x20, <<0, 0, 0, 0, 0>>) <> raw_tlv(0x20, <<0, 0, 0, 0, 0>>),
            raw_tlv(0x30, "ns\n"),
            raw_tlv(0x30, "a") <> raw_tlv(0x30, "b")
          ] do
        assert parse(v2(0x21, 0x11, tcp4_block(tlvs))) == {:error, :invalid_tlv}, inspect(tlvs)
      end
    end

    test "decodes the well-known TLVs and keeps all of them raw" do
      ssl =
        <<0x07, 3::32>> <>
          raw_tlv(0x21, "TLSv1.3") <>
          raw_tlv(0x22, "Zoë") <>
          raw_tlv(0x23, "TLS_AES_256_GCM_SHA384") <>
          raw_tlv(0x24, "SHA256") <>
          raw_tlv(0x25, "RSA2048") <> raw_tlv(0x99, "other")

      tlvs = [
        {0x04, <<0, 0, 0>>},
        {0x01, "h2"},
        {0x02, "mx.example.com"},
        {0x05, :binary.copy("i", 128)},
        {0x20, ssl},
        {0x30, "blue"},
        {0xEA, <<1, "vpce-1">>}
      ]

      block = tcp4_block(Enum.map_join(tlvs, fn {type, value} -> raw_tlv(type, value) end))
      assert {:ok, header, ""} = parse(v2(0x21, 0x11, block))

      assert %Header{
               tlvs: ^tlvs,
               alpn: "h2",
               authority: "mx.example.com",
               netns: "blue",
               ssl: %{
                 client: [:ssl, :cert_conn, :cert_sess],
                 verify: 3,
                 version: "TLSv1.3",
                 cn: "Zoë",
                 cipher: "TLS_AES_256_GCM_SHA384",
                 sig_alg: "SHA256",
                 key_alg: "RSA2048",
                 tlvs: [{0x21, _}, {0x22, _}, {0x23, _}, {0x24, _}, {0x25, _}, {0x99, "other"}]
               }
             } = header

      assert header.unique_id == :binary.copy("i", 128)
      assert round_trip(header, &encode_v2/1) == header
    end

    test "decodes an empty SSL TLV" do
      assert {:ok, %Header{ssl: ssl}, ""} =
               parse(v2(0x21, 0x11, tcp4_block(raw_tlv(0x20, <<0, 0xFFFFFFFF::32>>))))

      assert ssl == %{
               client: [],
               verify: 0xFFFFFFFF,
               version: nil,
               cn: nil,
               cipher: nil,
               sig_alg: nil,
               key_alg: nil,
               tlvs: []
             }
    end

    test "verifies the CRC32C checksum" do
      header = %Header{@tcp4 | tlvs: [tlv(:alpn, "h2"), tlv(:crc32c), {0xE0, "x"}]}
      encoded = encode_v2(header)

      # The checksum covers the whole header with the checksum zeroed.
      [before, <<crc::32, after_crc::binary>>] = :binary.split(encoded, <<0x03, 4::16>>)
      assert crc == CRC32C.checksum([before, <<0x03, 4::16, 0::32>>, after_crc])
      assert crc != 0

      assert {:ok, parsed, ""} = parse(encoded)
      assert [{0x01, "h2"}, {0x03, <<^crc::32>>}, {0xE0, "x"}] = parsed.tlvs
      assert encode_v2(parsed) == encoded

      # Any changed byte, the checksum included, is caught, except for the
      # checksum's own type: that drops the checksum.
      for position <- 16..(byte_size(encoded) - 1), position != byte_size(before) do
        <<a::binary-size(^position), byte, b::binary>> = encoded
        corrupted = a <> <<Bitwise.bxor(byte, 0x01)>> <> b

        assert match?({:error, _}, parse(corrupted)), "byte #{position}"
      end

      assert parse(v2(0x21, 0x11, tcp4_block(raw_tlv(0x03, <<0::32>>)))) ==
               {:error, :crc32c_mismatch}

      twice = encode_v2(%Header{@tcp4 | tlvs: [tlv(:crc32c), tlv(:crc32c)]})
      assert parse(twice) == {:error, :invalid_tlv}
    end

    test "checks the CRC32C of UNIX and UNSPEC headers" do
      for header <- [
            %Header{transport: :unspec, tlvs: [tlv(:crc32c)]},
            %Header{
              transport: :unix,
              source: {:local, "/a"},
              destination: {:local, "/b"},
              tlvs: [tlv(:crc32c)]
            }
          ] do
        assert {:ok, _header, ""} = parse(encode_v2(header))
      end
    end
  end

  describe "encode_v1/1" do
    test "round-trips TCP headers" do
      assert round_trip(@tcp4, &encode_v1/1) == %Header{@tcp4 | version: 1}
      assert round_trip(@tcp6, &encode_v1/1) == %Header{@tcp6 | version: 1}

      mapped = %Header{@tcp6 | source: {{0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0201}, 1}}
      assert encode_v1(mapped) =~ "PROXY TCP6 ::ffff:192.0.2.1 2001:db8::2 1 587\r\n"
      assert round_trip(mapped, &encode_v1/1) == %Header{mapped | version: 1}
    end

    test "sends UNKNOWN for anything else" do
      assert encode_v1(%Header{@tcp4 | transport: :udp4}) == "PROXY UNKNOWN\r\n"
      assert encode_v1(%Header{@tcp4 | command: :local}) == "PROXY UNKNOWN\r\n"
      assert encode_v1(%Header{}) == "PROXY UNKNOWN\r\n"
    end

    test "raises on addresses that do not match the transport" do
      for header <- [
            %Header{@tcp4 | transport: :tcp6},
            %Header{@tcp6 | transport: :tcp4},
            %Header{@tcp4 | source: {{192, 0, 2, 1}, 65_536}},
            %Header{@tcp4 | source: {{192, 0, 2, 256}, 1}},
            %Header{@tcp4 | destination: nil}
          ] do
        assert_raise ArgumentError, fn -> encode_v1(header) end
      end
    end
  end

  describe "encode_v2/1" do
    test "raises on invalid headers" do
      for header <- [
            %Header{@tcp4 | transport: :tcp6},
            %Header{@tcp6 | transport: :udp4},
            %Header{transport: :unix, source: {:local, :binary.copy("x", 109)}, destination: nil},
            %Header{transport: :unix, source: {{192, 0, 2, 1}, 1}, destination: {:local, ""}},
            %Header{@tcp4 | tlvs: [{256, ""}]},
            %Header{@tcp4 | tlvs: [{1, :binary.copy("x", 65_536)}]},
            %Header{@tcp4 | tlvs: [{0xE0, :binary.copy("x", 65_520)}, {0xE1, "xxxxxxxxx"}]}
          ] do
        assert_raise ArgumentError, fn -> encode_v2(header) end
      end
    end
  end

  describe "tlv/2" do
    test "builds the well-known TLVs" do
      assert tlv(:alpn, "h2") == {0x01, "h2"}
      assert tlv(:authority, "mx.example.com") == {0x02, "mx.example.com"}
      assert tlv(:crc32c) == {0x03, <<0::32>>}
      assert tlv(:noop, <<0, 0>>) == {0x04, <<0, 0>>}
      assert tlv(:unique_id, "id") == {0x05, "id"}
      assert tlv(:netns, "blue") == {0x30, "blue"}
      assert tlv(:ssl, %{}) == {0x20, <<0, 0::32>>}

      ssl = %{
        client: [:cert_sess, :ssl],
        verify: 1,
        version: "TLSv1.2",
        cn: "client",
        cipher: "ECDHE-RSA-AES128-GCM-SHA256",
        sig_alg: "SHA256",
        key_alg: "RSA2048",
        tlvs: [{0x99, "ignored"}]
      }

      header = round_trip(%Header{@tcp4 | tlvs: [tlv(:ssl, ssl)]}, &encode_v2/1)
      assert %{header.ssl | tlvs: []} == %{ssl | client: [:ssl, :cert_sess], tlvs: []}
      assert length(header.ssl.tlvs) == 5
    end
  end

  describe "properties" do
    defp ip4, do: tuple({byte(), byte(), byte(), byte()})

    defp ip6 do
      word = integer(0..0xFFFF)
      tuple({word, word, word, word, word, word, word, word})
    end

    defp port, do: integer(0..65_535)

    defp tcp_header do
      gen all(
            transport <- member_of([:tcp4, :tcp6]),
            ip = if(transport == :tcp4, do: ip4(), else: ip6()),
            source <- ip,
            destination <- ip,
            source_port <- port(),
            destination_port <- port()
          ) do
        %Header{
          transport: transport,
          source: {source, source_port},
          destination: {destination, destination_port}
        }
      end
    end

    property "version 1 headers round-trip" do
      check all(%Header{} = header <- tcp_header(), rest <- binary()) do
        assert parse(encode_v1(header) <> rest) == {:ok, %Header{header | version: 1}, rest}
      end
    end

    property "version 2 headers round-trip, with any custom TLVs" do
      check all(
              %Header{} = header <- tcp_header(),
              udp <- boolean(),
              tlvs <-
                list_of(tuple({integer(0xE0..0xFF), binary(max_length: 100)}), max_length: 5),
              crc <- boolean(),
              rest <- binary()
            ) do
        transport =
          if udp, do: %{tcp4: :udp4, tcp6: :udp6}[header.transport], else: header.transport

        tlvs = if crc, do: [tlv(:crc32c) | tlvs], else: tlvs
        header = %Header{header | transport: transport, tlvs: tlvs}

        assert {:ok, %Header{} = parsed, ^rest} = parse(encode_v2(header) <> rest)
        assert %Header{parsed | tlvs: tlvs} == header
        if crc, do: assert(encode_v2(parsed) == encode_v2(header))
      end
    end

    property "never crashes on garbage, after either signature or none" do
      check all(
              prefix <-
                member_of(["", "PROXY ", "PROXY TCP4 ", @signature, @signature <> <<0x21>>]),
              data <- binary(max_length: 300)
            ) do
        case parse(prefix <> data) do
          {:ok, %Header{}, rest} -> assert is_binary(rest)
          {:more, n} -> assert n == :unknown or n > 0
          {:error, reason} -> assert is_atom(reason)
        end
      end
    end
  end

  describe "read/3" do
    defp socket_pair do
      {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, port} = :inet.port(listen)
      {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
      {:ok, server} = :gen_tcp.accept(listen, 1_000)
      :gen_tcp.close(listen)
      on_exit(fn -> :gen_tcp.close(client) end)
      {client, server}
    end

    # Sends `data` in pieces, `delay` milliseconds apart.
    defp trickle(socket, data, size, delay) do
      spawn_link(fn ->
        for <<piece::binary-size(^size) <- data>> do
          :gen_tcp.send(socket, piece)
          Process.sleep(delay)
        end
      end)
    end

    test "reads exactly the header and leaves the rest on the socket" do
      for header <- [
            "PROXY TCP4 192.0.2.1 198.51.100.1 56324 25\r\n",
            "PROXY UNKNOWN\r\n",
            "PROXY UNKNOWN 1\r\n",
            encode_v2(@tcp4),
            encode_v2(%Header{@tcp6 | tlvs: [tlv(:authority, "a"), tlv(:crc32c)]}),
            encode_v2(%Header{command: :local})
          ] do
        {client, server} = socket_pair()
        :ok = :gen_tcp.send(client, header <> "EHLO client.example\r\n")

        assert {:ok, %Header{}} = read(server, 1_000)
        assert :gen_tcp.recv(server, 0, 1_000) == {:ok, "EHLO client.example\r\n"}
      end
    end

    test "reads a header delivered a byte at a time" do
      for header <- ["PROXY TCP6 2001:db8::1 2001:db8::2 1234 587\r\n", encode_v2(@tcp6)] do
        {client, server} = socket_pair()
        trickle(client, header <> "QUIT", 1, 1)

        assert read(server, 5_000) == {:ok, parse(header) |> elem(1)}
        assert :gen_tcp.recv(server, 4, 1_000) == {:ok, "QUIT"}
      end
    end

    test "fails on an invalid header without waiting" do
      {client, server} = socket_pair()
      :ok = :gen_tcp.send(client, "EHLO client.example\r\n")
      assert read(server, 5_000) == {:error, :invalid_signature}

      {client, server} = socket_pair()
      :ok = :gen_tcp.send(client, @signature <> <<0x21, 0x11, 1_000::16>>)
      assert read(server, 5_000, max_length: 100) == {:error, :header_too_long}
    end

    test "times out on a missing or partial header" do
      {_client, server} = socket_pair()
      assert read(server, 50) == {:error, :timeout}

      {client, server} = socket_pair()
      :ok = :gen_tcp.send(client, "PROXY TCP4 192.0.2.1 198.51.100.1 56324")
      assert read(server, 50) == {:error, :timeout}

      {client, server} = socket_pair()
      :ok = :gen_tcp.send(client, binary_part(encode_v2(@tcp4), 0, 20))
      assert read(server, 50) == {:error, :timeout}

      assert read(server, 0) == {:error, :timeout}
    end

    test "the timeout covers the whole header, not each read" do
      {client, server} = socket_pair()
      trickle(client, "PROXY TCP4 192.0.2.1 198.51.100.1 56324 25\r\n", 1, 20)

      started = System.monotonic_time(:millisecond)
      assert read(server, 200) == {:error, :timeout}
      assert System.monotonic_time(:millisecond) - started < 400
    end

    test "fails when the client closes the connection" do
      {client, server} = socket_pair()
      :ok = :gen_tcp.send(client, "PROXY UNKNOWN")
      :gen_tcp.close(client)
      assert read(server, 1_000) == {:error, :closed}
    end
  end
end
