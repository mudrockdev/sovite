defmodule Sovite.ValidatorsTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Sovite.Validators

  doctest Sovite.Validators

  describe "domain?/1" do
    test "accepts valid domains" do
      for d <- ["example.com", "a", "a-b.c", "1.2.3.4", "xn--bcher-kva.example", "A.B.C"] do
        assert domain?(d), "expected #{inspect(d)} to be valid"
      end
    end

    test "rejects invalid domains" do
      for d <- [
            "",
            ".",
            "a.",
            ".a",
            "a..b",
            "-a.com",
            "a-.com",
            "a_b.com",
            "a b.com",
            "é.com",
            nil,
            123
          ] do
        refute domain?(d), "expected #{inspect(d)} to be invalid"
      end
    end

    test "enforces label and total length limits" do
      assert domain?(String.duplicate("a", 63) <> ".com")
      refute domain?(String.duplicate("a", 64) <> ".com")

      long = Enum.map_join(1..64, ".", fn _ -> "abc" end)
      assert byte_size(long) == 255
      assert domain?(long)
      refute domain?(long <> "a")
    end
  end

  describe "hostname?/1" do
    test "rejects numeric top-level labels" do
      assert hostname?("mail.example.com")
      assert hostname?("localhost")
      refute hostname?("192.0.2.1")
      refute hostname?("host.123")
    end
  end

  describe "parse_address_literal/1" do
    test "parses IPv4 literals" do
      assert parse_address_literal("[192.0.2.1]") == {:ok, {192, 0, 2, 1}}
      assert parse_address_literal("[0.0.0.0]") == {:ok, {0, 0, 0, 0}}
    end

    test "parses IPv6 literals with a case-insensitive tag" do
      assert parse_address_literal("[IPv6:2001:db8::1]") ==
               {:ok, {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}}

      assert parse_address_literal("[ipv6:::1]") == {:ok, {0, 0, 0, 0, 0, 0, 0, 1}}
      assert {:ok, _} = parse_address_literal("[IPv6:::ffff:192.0.2.1]")
    end

    test "rejects malformed literals" do
      for l <- [
            "[256.0.0.1]",
            "[1.2.3]",
            "[1.2.3.4.5]",
            "[1.2.3.a]",
            "[1.2.3.4",
            "1.2.3.4]",
            "[]",
            "[2001:db8::1]",
            "[IPv6:fe80::1%eth0]",
            "[IPv6:1.2.3.4]",
            "[IPv6:gggg::1]",
            "[tag:content]"
          ] do
        assert parse_address_literal(l) == {:error, :invalid_address_literal},
               "expected #{inspect(l)} to be invalid"
      end
    end
  end

  describe "helo?/1" do
    test "accepts domains and address literals" do
      assert helo?("client.example.com")
      assert helo?("[192.0.2.1]")
      refute helo?("192.0.2.1]")
      refute helo?("bad_name")
    end
  end

  describe "local_part?/1" do
    test "accepts dot-strings and quoted strings" do
      for l <- [
            "user",
            "first.last",
            "user+tag",
            "!#$%&'*+-/=?^_`{|}~",
            ~s("a b"),
            ~s("a\\"b"),
            ~s("")
          ] do
        assert local_part?(l), "expected #{inspect(l)} to be valid"
      end
    end

    test "rejects invalid local parts" do
      for l <- [
            ".a",
            "a.",
            "a..b",
            "a b",
            "a\"b",
            ~s("unterminated),
            ~s("a"b"),
            ~s("\x01"),
            "",
            "a@b"
          ] do
        refute local_part?(l), "expected #{inspect(l)} to be invalid"
      end

      refute local_part?(String.duplicate("a", 65))
    end
  end

  describe "split_mailbox/1" do
    test "splits valid mailboxes" do
      assert split_mailbox("user@example.com") == {:ok, {"user", "example.com"}}
      assert split_mailbox("user@[192.0.2.1]") == {:ok, {"user", "[192.0.2.1]"}}
      assert split_mailbox(~s("x@y"@example.com)) == {:ok, {~s("x@y"), "example.com"}}
    end

    test "reports why a mailbox is invalid" do
      assert split_mailbox("example.com") == {:error, :missing_at}
      assert split_mailbox("@example.com") == {:error, :invalid_local_part}
      assert split_mailbox("a..b@example.com") == {:error, :invalid_local_part}
      assert split_mailbox(~s("a"b@example.com)) == {:error, :invalid_local_part}
      assert split_mailbox("a@b@example.com") == {:error, :invalid_domain}
      assert split_mailbox("user@") == {:error, :invalid_domain}

      assert split_mailbox(String.duplicate("a", 65) <> "@x.com") ==
               {:error, :local_part_too_long}

      assert split_mailbox("a@" <> String.duplicate("b.", 126) <> "com") == {:error, :too_long}
      assert split_mailbox(nil) == {:error, :missing_at}
    end
  end

  describe "internationalized addresses (RFC 6531)" do
    test "are accepted with utf8: true" do
      for mailbox <- [
            "jürgen@bücher.example",
            "用户@例子.广告",
            ~s("ü ü"@example.com),
            "a@xn--bcher-kva.example",
            "δοκιμή@παράδειγμα.δοκιμή"
          ] do
        assert mailbox?(mailbox, utf8: true), mailbox
      end

      refute mailbox?("jürgen@example.com")
      refute mailbox?("a@bücher.example")
      refute local_part?("jürgen")
      assert local_part?("jürgen", utf8: true)
    end

    test "invalid UTF-8, controls, and invalid domains" do
      for mailbox <- [
            <<"a", 0xFF, "@example.com">>,
            "a\u0085@example.com",
            "a@☃.example",
            "a@-ü.example",
            "ü..ü@example.com"
          ] do
        refute mailbox?(mailbox, utf8: true), inspect(mailbox)
      end

      # Lengths count octets: 22 two-octet characters exceed 64.
      assert split_mailbox(String.duplicate("ü", 33) <> "@example.com", utf8: true) ==
               {:error, :local_part_too_long}
    end

    test "domains in A-labels" do
      assert ascii_domain("jürgen@Bücher.example") == {:ok, "jürgen@xn--bcher-kva.example"}
      assert ascii_domain("a@[192.0.2.1]") == {:ok, "a@[192.0.2.1]"}
      assert ascii_domain("a@☃.example") == {:error, :invalid_domain}
      assert international?("jürgen@example.com")
      refute international?("a@example.com")
    end
  end

  describe "properties" do
    property "generated domains are valid" do
      check all(domain <- domain_gen()) do
        assert domain?(domain)
        assert helo?(domain)
      end
    end

    property "generated IPv4 literals parse back to the same address" do
      check all(ip <- tuple({byte(), byte(), byte(), byte()})) do
        literal = "[" <> (ip |> :inet.ntoa() |> List.to_string()) <> "]"
        assert parse_address_literal(literal) == {:ok, ip}
      end
    end

    property "generated IPv6 literals parse back to the same address" do
      check all(ip <- tuple(List.to_tuple(List.duplicate(integer(0..0xFFFF), 8)))) do
        literal = "[IPv6:" <> (ip |> :inet.ntoa() |> List.to_string()) <> "]"
        assert parse_address_literal(literal) == {:ok, ip}
      end
    end

    property "generated mailboxes split back into their parts" do
      check all(local <- local_part_gen(), domain <- domain_gen()) do
        assert split_mailbox(local <> "@" <> domain) == {:ok, {local, domain}}
      end
    end

    property "validators never raise on arbitrary input" do
      check all(
              input <-
                one_of([
                  binary(),
                  string(:printable),
                  string(Enum.concat([?a..?z, ~c".-@[]:\"\\ "]))
                ]),
              max_runs: 1_000
            ) do
        assert is_boolean(domain?(input))
        assert is_boolean(hostname?(input))
        assert is_boolean(helo?(input))
        assert is_boolean(local_part?(input))
        assert match?({tag, _} when tag in [:ok, :error], split_mailbox(input))
        assert match?({tag, _} when tag in [:ok, :error], parse_address_literal(input))
      end
    end
  end

  defp label_gen do
    let_dig = Enum.concat([?a..?z, ?A..?Z, ?0..?9])

    gen all(
          first <- member_of(let_dig),
          middle <- string(Enum.concat(let_dig, [?-]), max_length: 20),
          last <- member_of(let_dig)
        ) do
      <<first>> <> middle <> <<last>>
    end
  end

  defp domain_gen do
    gen all(labels <- list_of(label_gen(), min_length: 1, max_length: 5)) do
      Enum.join(labels, ".")
    end
  end

  defp local_part_gen do
    atext = Enum.concat([?a..?z, ?A..?Z, ?0..?9, ~c"!#$%&'*+-/=?^_`{|}~"])
    atom = string(atext, min_length: 1, max_length: 10)

    dot_string =
      gen(all(atoms <- list_of(atom, min_length: 1, max_length: 4), do: Enum.join(atoms, ".")))

    quoted =
      gen all(s <- string(Enum.concat([32..33, 35..91, 93..126]), max_length: 20)) do
        ~s(") <> s <> ~s(")
      end

    one_of([dot_string, quoted])
  end
end
