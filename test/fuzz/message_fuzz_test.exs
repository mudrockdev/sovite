defmodule Sovite.MessageFuzzTest do
  # Fuzzing of what messages carry: the header section, address lists,
  # trace fields, DKIM and ARC signatures, Authentication-Results, and
  # the names and addresses in them.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.{ARC, AuthResults, DKIM, DMARC, IDNA, Net, SRS, Validators}
  alias Sovite.DKIM.{Body, Key, Signature, SigningKey, Tags}
  alias Sovite.IDNA.Punycode
  alias Sovite.Message.{AddressList, Headers, Trace}
  alias Sovite.Test.{FakeDNS, Fuzz}

  @moduletag :fuzz
  # `mix fuzz` runs each property many times.
  @moduletag timeout: :infinity

  @message """
           Received: from mx.example (mx.example [192.0.2.1])
           \tby mx.test with ESMTPS id 4F2; Sun, 18 Oct 2026 10:00:00 +0000
           From: "Doe, Jane" <jane@example.com>
           To: Team: a@example.net, "b (x)" <b@example.net>;, c@[192.0.2.1]
           Cc: =?utf-8?q?J=C3=B6rg?= <jörg@exämple.com>
           Subject: =?utf-8?b?SMOpbGxv?=
            folded
           Date: Sun, 18 Oct 2026 10:00:00 +0000
           Message-ID: <1@example.com>
           Authentication-Results: mx.test; spf=pass smtp.mailfrom=example.com;
            dkim=pass (2048-bit key) header.d=example.com header.s=s1;
            dmarc=pass (p=reject) header.from=example.com
           MIME-Version: 1.0
           Content-Type: multipart/alternative; boundary="b1"

           --b1
           Content-Type: text/plain; charset=utf-8

           Hello  there.\x20
           ..dot

           --b1--
           """
           |> String.replace("\n", "\r\n")

  @header_tokens ["\r\n", "\r\n ", "\r\n\t", ":", ";", ",", "<", ">", "\"", "(", ")", "\\", "@"]

  setup_all do
    {:ok, rsa} = SigningKey.from_pem(SigningKey.generate(:rsa, 1024), "example.com", "rsa")
    {:ok, ed} = SigningKey.from_pem(SigningKey.generate(:ed25519), "example.com", "ed")

    resolver =
      FakeDNS.resolver(
        Map.new([rsa, ed], &{{SigningKey.dns_name(&1), :txt}, [SigningKey.dns_record(&1)]})
      )

    %{keys: [rsa, ed], resolver: resolver}
  end

  describe "the header section" do
    property "splits and parses without losing a byte" do
      check all(data <- Fuzz.input([@message], @header_tokens), max_runs: Fuzz.runs()) do
        case Fuzz.quick(fn -> Headers.split(data) end) do
          {:ok, header, body} ->
            assert header <> "\r\n" <> body == data or "\r\n" <> body == data

            fields = Fuzz.quick(fn -> Headers.parse(header) end)
            assert IO.iodata_to_binary(Headers.encode(fields)) == header

            for {name, _raw} <- fields, name != nil do
              assert is_binary(Headers.get(fields, name))
            end

            assert Trace.hops(fields) >= 0

          :more ->
            refute data =~ "\r\n\r\n"
        end
      end
    end

    property "address lists parse, and rewrite only addresses" do
      seeds = [
        ~s|"Doe, Jane" <jane@example.com>|,
        "Team: a@example.net, \"b (x)\" <b@example.net>;, c@[192.0.2.1]",
        "=?utf-8?q?J=C3=B6rg?= <jörg@exämple.com> (comment (nested))",
        "<@route.example:a@example.com>, undisclosed-recipients:;",
        " a@example.com,\r\n\tb@example.com"
      ]

      check all(value <- Fuzz.input(seeds, @header_tokens), max_runs: Fuzz.runs()) do
        assert AddressList.rewrite(value, & &1) == value

        case Fuzz.quick(fn -> AddressList.addresses(value) end) do
          {:ok, addresses} -> assert Enum.all?(addresses, &is_binary/1)
          :error -> :ok
        end

        fields = Headers.parse("From:" <> value <> "\r\n")

        case DMARC.from_domain(fields) do
          {:ok, domain} -> assert is_binary(domain) and domain != ""
          {:error, reason} -> assert reason in [:missing, :multiple, :invalid]
        end
      end
    end

    property "Authentication-Results fields parse or are refused" do
      seeds = [
        "mx.test; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com",
        "mx.test 1; none",
        "\"quoted id\"; dmarc=fail (p=reject) header.from=example.com; arc=pass",
        "mx.test; auth=pass (cram) smtp.auth=alice; iprev=pass policy.iprev=192.0.2.1"
      ]

      check all(value <- Fuzz.input(seeds, [";", "=", "(", ")", "\""]), max_runs: Fuzz.runs()) do
        case Fuzz.quick(fn -> AuthResults.parse(value) end) do
          {:ok, id, results} -> assert is_binary(id) and is_list(results)
          :error -> :ok
        end

        assert AuthResults.authserv_id(value) |> elem_or_error()
      end
    end
  end

  describe "DKIM and ARC" do
    property "signatures, keys, and tag lists parse or are refused" do
      [signature] =
        DKIM.sign(@message, [
          elem(SigningKey.from_pem(SigningKey.generate(:ed25519), "a.example", "s"), 1)
        ])

      seeds = [
        signature |> :binary.split(":") |> List.last(),
        "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08",
        "v=DKIM1; k=ed25519; h=sha256; t=y:s; s=email; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
        "v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=; b=; l=10; z=From:a|To:b"
      ]

      check all(value <- Fuzz.input(seeds, [";", "=", " ", ":", "|"]), max_runs: Fuzz.runs()) do
        assert match?({:ok, _}, Tags.parse(value)) or Tags.parse(value) == :error
        assert {_, _} = Fuzz.quick(fn -> Signature.parse(value) end)
        assert {_, _} = Fuzz.quick(fn -> Key.parse(value) end)
      end
    end

    property "a signed message verifies, however it looks", %{keys: keys, resolver: resolver} do
      # (A message that starts with a folded line is refused.)
      message =
        Fuzz.input([@message], @header_tokens)
        |> filter(&(not String.starts_with?(&1, [" ", "\t"])))

      check all(message <- message, max_runs: Fuzz.runs()) do
        signed = Enum.join(DKIM.sign(message, keys)) <> message
        results = DKIM.verify(signed, resolver)
        assert Enum.map(results, & &1.result) == [:pass, :pass], inspect(results)
      end
    end

    property "any change to a signed message verifies or fails, never crashes", %{
      keys: keys,
      resolver: resolver
    } do
      signed = Enum.join(DKIM.sign(@message, keys)) <> @message
      sealed = seal(signed, hd(keys), resolver)

      check all(
              message <-
                Fuzz.mutated([signed, sealed], @header_tokens ++ ["DKIM-Signature:", "ARC-Seal:"]),
              max_runs: Fuzz.runs()
            ) do
        for result <- Fuzz.quick(fn -> DKIM.verify(message, resolver) end) do
          assert result.result in [:pass, :fail, :neutral, :temperror, :permerror, :policy]
        end

        case Headers.split(message) do
          {:ok, header, body} ->
            assert %ARC.Result{} =
                     Fuzz.quick(fn -> arc(Headers.parse(header), body, resolver) end)

          :more ->
            :ok
        end
      end
    end
  end

  describe "names and addresses" do
    property "domains convert between Unicode and A-labels consistently" do
      seeds = ["exämple.com", "xn--exmple-cua.com", "例え.テスト", "xn--r8jz45g.xn--zckzah", "a.b-c.d"]

      seeds =
        seeds ++ ["ß.de", "xn--zca.de", "١٢٣.com", "xn--", "a..b", String.duplicate("a", 64)]

      check all(name <- Fuzz.input(seeds, [".", "-", "xn--"]), max_runs: Fuzz.runs()) do
        case Fuzz.quick(fn -> IDNA.to_ascii(name) end) do
          {:ok, ascii} ->
            assert ascii =~ ~r/\A[\x21-\x7e]*\z/
            assert {:ok, unicode} = IDNA.to_unicode(ascii)
            assert IDNA.to_ascii(unicode) == {:ok, ascii}

          {:error, _reason} ->
            :ok
        end

        assert match?({:ok, _}, IDNA.to_unicode(name)) or
                 match?({:error, _}, IDNA.to_unicode(name))

        case Punycode.decode(name) do
          {:ok, decoded} -> assert Punycode.encode(decoded) |> elem_or_error()
          :error -> :ok
        end

        if String.valid?(name) do
          case Punycode.encode(name) do
            {:ok, encoded} -> assert Punycode.decode(encoded) == {:ok, name}
            :error -> :ok
          end
        end
      end
    end

    property "mailboxes, address literals, and networks parse or are refused" do
      seeds = [
        "alice@example.com",
        "\"j d\"@example.com",
        "pelé@exämple.com",
        "user@[192.0.2.1]",
        "user@[IPv6:2001:db8::1]",
        "[IPv6:::ffff:192.0.2.1]",
        "192.0.2.0/24",
        "2001:db8::/32",
        "a.b@xn--exmple-cua.com"
      ]

      check all(
              value <- Fuzz.input(seeds, ["@", ".", "\"", "\\", "[", "]", ":", "/"]),
              max_runs: Fuzz.runs()
            ) do
        for opts <- [[], [utf8: true]] do
          case Fuzz.quick(fn -> Validators.split_mailbox(value, opts) end) do
            {:ok, {local, domain}} -> assert is_binary(local) and is_binary(domain)
            {:error, reason} -> assert is_atom(reason)
          end
        end

        assert is_boolean(Validators.domain?(value))
        assert is_boolean(Validators.helo?(value))
        assert Validators.parse_address_literal(value) |> elem_or_error()
        assert Net.parse_ip(value) |> elem_or_error()
        assert Net.parse_cidr(value) |> elem_or_error()
      end
    end
  end

  describe "SRS" do
    property "addresses come back from SRS, and forged ones are refused" do
      opts = [secrets: ["new secret", "old secret"], now: ~U[2026-10-18 12:00:00Z]]

      senders = [
        "alice@example.com",
        "a=b+c@example.org",
        "\"j d\"@example.net",
        "pelé@exämple.com"
      ]

      once = Enum.map(senders, &elem(SRS.forward(&1, "fwd.example", opts), 1))
      twice = Enum.map(once, &elem(SRS.forward(&1, "fwd2.example", opts), 1))

      check all(
              address <-
                Fuzz.input(senders ++ once ++ twice, ["=", "+", "-", "@", "SRS0", "SRS1"]),
              max_runs: Fuzz.runs()
            ) do
        # Senders are checked before they are rewritten.
        case Validators.mailbox?(address, utf8: true) &&
               Fuzz.quick(fn -> SRS.forward(address, "fwd3.example", opts) end) do
          {:ok, forwarded} ->
            if SRS.srs?(address),
              do: assert(match?({:ok, _}, SRS.reverse(forwarded, opts))),
              else: assert(SRS.reverse(forwarded, opts) == {:ok, address})

          _invalid ->
            :ok
        end

        case Fuzz.quick(fn -> SRS.reverse(address, opts) end) do
          {:ok, original} -> assert is_binary(original)
          {:error, reason} -> assert reason in [:not_srs, :malformed, :bad_hash, :expired]
        end
      end
    end
  end

  defp elem_or_error({:ok, _value}), do: true
  defp elem_or_error({:error, _reason}), do: true
  defp elem_or_error(:error), do: true

  defp arc(fields, body, resolver) do
    verifier = ARC.new(fields)
    hashes = verifier |> ARC.body_specs() |> Body.new() |> Body.update(body) |> Body.finish()
    ARC.finish(verifier, hashes, resolver)
  end

  defp seal(message, key, resolver) do
    {:ok, header, body} = Headers.split(message)
    fields = Headers.parse(header)
    spec = DKIM.body_spec()
    {hash, _} = [spec] |> Body.new() |> Body.update(body) |> Body.finish() |> Map.fetch!(spec)
    result = arc(fields, body, resolver)

    Enum.join(ARC.seal(fields, hash, result, "example.com; spf=pass smtp.mailfrom=a@b", key)) <>
      message
  end
end
