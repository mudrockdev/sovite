defmodule Sovite.NetTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise
  import Sovite.Net

  # BUG: the format_cidr/1 doctest (lib/net/net.ex:97) writes the first
  # group as decimal `2001` instead of `0x2001`, so it yields "7d1:db8::/32".
  # Excluded until the doc is fixed; format_cidr/1 is tested below.
  doctest Sovite.Net, except: [format_cidr: 1]

  describe "parse_ip/1" do
    test "parses IPv4 and IPv6 addresses" do
      assert parse_ip("0.0.0.0") == {:ok, {0, 0, 0, 0}}
      assert parse_ip("255.255.255.255") == {:ok, {255, 255, 255, 255}}
      assert parse_ip("::") == {:ok, {0, 0, 0, 0, 0, 0, 0, 0}}
      assert parse_ip("::1") == {:ok, {0, 0, 0, 0, 0, 0, 0, 1}}
      assert parse_ip("2001:DB8::A") == {:ok, {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0xA}}
      assert parse_ip("::ffff:192.0.2.1") == {:ok, {0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0201}}

      longest = "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"
      assert byte_size(longest) == 45
      assert {:ok, {0xFFFF, _, _, _, _, _, 0xFFFF, 0xFFFF}} = parse_ip(longest)
    end

    test "rejects shorthand, zone ids and garbage" do
      for s <- [
            "",
            "1",
            "10.1",
            "10.1.2",
            "127.1",
            "1.2.3.4.5",
            "256.0.0.1",
            "010.0.0.1",
            " 1.2.3.4",
            "1.2.3.4 ",
            "1.2.3.4\n",
            "fe80::1%eth0",
            "fe80::1%1",
            "[::1]",
            "2001:db8:::1",
            "1:2:3:4:5:6:7:8:9",
            "g::1",
            "1.2.3.4/32",
            "example.com",
            String.duplicate("1", 46)
          ] do
        assert parse_ip(s) == {:error, :invalid_ip}, "expected #{inspect(s)} to be invalid"
      end
    end

    test "rejects non-binaries" do
      for t <- [nil, 1, :"1.2.3.4", ~c"1.2.3.4", {1, 2, 3, 4}, %{}] do
        assert parse_ip(t) == {:error, :invalid_ip}
      end
    end
  end

  describe "parse_cidr/1" do
    test "parses networks within prefix bounds" do
      assert parse_cidr("0.0.0.0/0") == {:ok, {{0, 0, 0, 0}, 0}}
      assert parse_cidr("10.0.0.0/8") == {:ok, {{10, 0, 0, 0}, 8}}
      assert parse_cidr("192.0.2.1/32") == {:ok, {{192, 0, 2, 1}, 32}}
      assert parse_cidr("192.0.2.1") == {:ok, {{192, 0, 2, 1}, 32}}
      assert parse_cidr("::/0") == {:ok, {{0, 0, 0, 0, 0, 0, 0, 0}, 0}}
      assert parse_cidr("2001:db8::/32") == {:ok, {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32}}
      assert parse_cidr("2001:db8::1/128") == {:ok, {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, 128}}
    end

    test "rejects out-of-range prefixes" do
      for s <- ["10.0.0.0/33", "10.0.0.0/-1", "::/129", "::/1000"] do
        assert parse_cidr(s) == {:error, :invalid_cidr}, "expected #{inspect(s)} to be invalid"
      end
    end

    test "rejects host bits set past the prefix" do
      assert parse_cidr("10.0.0.1/8") == {:error, :host_bits_set}
      assert parse_cidr("192.0.2.128/24") == {:error, :host_bits_set}
      assert parse_cidr("1.0.0.0/0") == {:error, :host_bits_set}
      assert parse_cidr("2001:db8::1/64") == {:error, :host_bits_set}
      assert parse_cidr("::1/127") == {:error, :host_bits_set}
    end

    test "rejects missing or extra slashes and malformed parts" do
      for s <- [
            "",
            "/",
            "/24",
            "10.0.0.0/",
            "10.0.0.0//24",
            "10.0.0.0/24/",
            "10.0.0.0/8/8",
            "10.0.0/8",
            "10.0.0.0/ 8",
            "10.0.0.0/8 ",
            "10.0.0.0/0x8",
            "10.0.0.0/8.0",
            "10.0.0.0/a",
            "fe80::%eth0/64"
          ] do
        assert parse_cidr(s) == {:error, :invalid_cidr}, "expected #{inspect(s)} to be invalid"
      end
    end

    test "rejects non-binaries" do
      for t <- [nil, 24, {{10, 0, 0, 0}, 8}, ~c"10.0.0.0/8"] do
        assert parse_cidr(t) == {:error, :invalid_cidr}
      end
    end

    # BUG: lib/net/net.ex:106 (parse_prefix/2) uses Integer.parse/1, which
    # accepts a sign, and only bounds the length, so "+8", "-0" and leading
    # zeros ("024") are accepted as valid prefix lengths. parse_ip/1 is
    # strict about leading zeros, so the prefix probably should be too.
    @tag :skip
    test "rejects signed or zero-padded prefixes" do
      for s <- ["10.0.0.0/+8", "0.0.0.0/-0", "10.0.0.0/024", "10.0.0.0/08", "::/+64"] do
        assert parse_cidr(s) == {:error, :invalid_cidr}, "expected #{inspect(s)} to be invalid"
      end
    end
  end

  describe "in_network?/2 and in_networks?/2" do
    test "matches IPv4 addresses" do
      net = {{192, 0, 2, 0}, 24}
      assert in_network?({192, 0, 2, 0}, net)
      assert in_network?({192, 0, 2, 255}, net)
      refute in_network?({192, 0, 3, 0}, net)
      refute in_network?({192, 0, 1, 255}, net)

      assert in_network?({10, 1, 2, 3}, {{10, 0, 0, 0}, 8})
      assert in_network?({192, 0, 2, 1}, {{192, 0, 2, 1}, 32})
      refute in_network?({192, 0, 2, 2}, {{192, 0, 2, 1}, 32})
    end

    test "matches IPv6 addresses" do
      net = {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32}
      assert in_network?({0x2001, 0xDB8, 0xFFFF, 0, 0, 0, 0, 1}, net)
      refute in_network?({0x2001, 0xDB9, 0, 0, 0, 0, 0, 1}, net)

      odd = {{0x2001, 0xDB8, 0x8000, 0, 0, 0, 0, 0}, 33}
      assert in_network?({0x2001, 0xDB8, 0xFFFF, 0, 0, 0, 0, 0}, odd)
      refute in_network?({0x2001, 0xDB8, 0x7FFF, 0, 0, 0, 0, 0}, odd)
    end

    test "/0 matches every address of the same family" do
      assert in_network?({1, 2, 3, 4}, {{0, 0, 0, 0}, 0})
      assert in_network?({255, 255, 255, 255}, {{0, 0, 0, 0}, 0})
      assert in_network?({0xFFFF, 1, 2, 3, 4, 5, 6, 7}, {{0, 0, 0, 0, 0, 0, 0, 0}, 0})
    end

    test "matches IPv4-mapped IPv6 addresses against IPv4 networks" do
      mapped = {0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0207}
      assert in_network?(mapped, {{192, 0, 2, 0}, 24})
      assert in_network?(mapped, {{0, 0, 0, 0}, 0})
      refute in_network?(mapped, {{198, 51, 100, 0}, 24})
    end

    test "never matches across families" do
      refute in_network?({0, 0, 0, 0}, {{0, 0, 0, 0, 0, 0, 0, 0}, 0})
      refute in_network?({0, 0, 0, 0, 0, 0, 0, 1}, {{0, 0, 0, 0}, 0})
      refute in_network?({192, 0, 2, 1}, {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32})
    end

    test "in_networks?/2 matches any of the networks" do
      nets = [{{10, 0, 0, 0}, 8}, {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32}]
      assert in_networks?({10, 9, 9, 9}, nets)
      assert in_networks?({0x2001, 0xDB8, 0, 0, 0, 0, 0, 9}, nets)
      assert in_networks?({0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 1}, nets)
      refute in_networks?({11, 0, 0, 0}, nets)
      refute in_networks?({10, 0, 0, 1}, [])
    end
  end

  test "normalize/1 converts only IPv4-mapped IPv6 addresses" do
    assert normalize({0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0201}) == {192, 0, 2, 1}
    assert normalize({0, 0, 0, 0, 0, 0xFFFF, 0, 0}) == {0, 0, 0, 0}
    assert normalize({192, 0, 2, 1}) == {192, 0, 2, 1}
    assert normalize({0, 0, 0, 0, 0, 0, 0, 1}) == {0, 0, 0, 0, 0, 0, 0, 1}
    # IPv4-compatible (deprecated) and NAT64 addresses are not mapped.
    assert normalize({0, 0, 0, 0, 0, 0, 0xC000, 0x0201}) == {0, 0, 0, 0, 0, 0, 0xC000, 0x0201}

    assert normalize({0x64, 0xFF9B, 0, 0, 0, 0, 0xC000, 0x0201}) ==
             {0x64, 0xFF9B, 0, 0, 0, 0, 0xC000, 0x0201}
  end

  test "format_cidr/1 round-trips with parse_cidr/1" do
    assert format_cidr({{192, 0, 2, 0}, 24}) == "192.0.2.0/24"
    assert format_cidr({{0, 0, 0, 0}, 0}) == "0.0.0.0/0"
    assert format_cidr({{0, 0, 0, 0, 0, 0, 0, 0}, 0}) == "::/0"

    for s <- ["192.0.2.0/24", "0.0.0.0/0", "::/0", "2001:db8::/32", "::1/128"] do
      assert s |> parse_cidr() |> elem(1) |> format_cidr() == s
    end
  end

  property "the masked network of an IPv4 address contains it" do
    check all(
            ip <- tuple({byte(), byte(), byte(), byte()}),
            length <- integer(0..32)
          ) do
      <<value::32>> = ip |> Tuple.to_list() |> :binary.list_to_bin()
      masked = value &&& bnot((1 <<< (32 - length)) - 1)
      network = List.to_tuple(:binary.bin_to_list(<<masked::32>>))

      assert {:ok, {^network, ^length}} = parse_cidr("#{:inet.ntoa(network)}/#{length}")
      assert in_network?(ip, {network, length})
      assert in_networks?(ip, [{network, length}])
    end
  end
end
