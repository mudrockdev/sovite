defmodule Sovite.DKIMTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.DKIM
  alias Sovite.DKIM.{Body, Canon, Key, Signature, SigningKey, Tags, Verifier}
  alias Sovite.Message.Headers
  alias Sovite.Test.FakeDNS

  doctest Tags
  doctest Canon
  doctest Key

  # RFC 8463 Appendix A: one message signed with Ed25519 and RSA.
  @rfc8463 """
           DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;
            d=football.example.com; i=@football.example.com;
            q=dns/txt; s=brisbane; t=1528637909; h=from : to :
            subject : date : message-id : from : subject : date;
            bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
            b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus
            Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==
           DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
            d=football.example.com; i=@football.example.com;
            q=dns/txt; s=test; t=1528637909; h=from : to : subject :
            date : message-id : from : subject : date;
            bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
            b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3
            DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz
            dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=
           From: Joe SixPack <joe@football.example.com>
           To: Suzie Q <suzie@shopping.example.net>
           Subject: Is dinner ready?
           Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
           Message-ID: <20030712040037.46341.5F8J@football.example.com>

           Hi.

           We lost the game.  Are you hungry yet?

           Joe.
           """
           |> String.replace("\n", "\r\n")

  @rfc8463_keys %{
    {"brisbane._domainkey.football.example.com", :txt} => [
      "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
    ],
    {"test._domainkey.football.example.com", :txt} => [
      "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB"
    ]
  }

  @message "From: Alice <alice@example.com>\r\nTo: bob@example.net\r\nSubject: hi\r\n\r\nHello  there \r\n\r\n"

  setup_all do
    {:ok, rsa} = SigningKey.from_pem(SigningKey.generate(:rsa, 1024), "example.com", "rsa")
    {:ok, ed} = SigningKey.from_pem(SigningKey.generate(:ed25519), "example.com", "ed")
    %{rsa: rsa, ed: ed}
  end

  defp resolver(keys, extra \\ %{}) do
    keys
    |> Map.new(&{{SigningKey.dns_name(&1), :txt}, [SigningKey.dns_record(&1)]})
    |> Map.merge(extra)
    |> FakeDNS.resolver()
  end

  defp results(message, resolver, opts \\ []),
    do: message |> DKIM.verify(resolver, opts) |> Enum.map(&{&1.result, &1.reason})

  describe "verify/3" do
    test "passes the RFC 8463 example" do
      results = DKIM.verify(@rfc8463, FakeDNS.resolver(@rfc8463_keys))

      assert [
               %{result: :pass, algorithm: "ed25519-sha256", selector: "brisbane"},
               %{result: :pass, algorithm: "rsa-sha256", selector: "test"} = rsa
             ] = results

      assert rsa.domain == "football.example.com"
      assert rsa.identity == "@football.example.com"
      assert rsa.b == "F45dVWDf"
    end

    test "fails a changed body or header" do
      resolver = FakeDNS.resolver(@rfc8463_keys)
      changed_body = String.replace(@rfc8463, "hungry", "thirsty")

      assert results(changed_body, resolver) == [
               {:fail, "body hash did not verify"},
               {:fail, "body hash did not verify"}
             ]

      changed_header = String.replace(@rfc8463, "dinner ready", "lunch ready")

      assert results(changed_header, resolver) == [
               {:fail, "signature did not verify"},
               {:fail, "signature did not verify"}
             ]

      # Relaxed canonicalization ignores whitespace changes.
      respaced = String.replace(@rfc8463, "Subject: Is dinner", "Subject:  Is   dinner")
      assert [{:pass, nil}, {:pass, nil}] = results(respaced, resolver)
    end

    test "reports key problems", %{rsa: rsa, ed: ed} do
      [signature] = DKIM.sign(@message, [rsa])
      message = signature <> @message
      name = SigningKey.dns_name(rsa)
      [record] = [SigningKey.dns_record(rsa)]

      cases = [
        {%{}, {:permerror, "no key for #{name}"}},
        {%{{name, :txt} => {:error, :servfail}},
         {:temperror, "key lookup for #{name} failed: servfail"}},
        {%{{name, :txt} => ["v=DKIM1; k=rsa; p="]}, {:permerror, "key revoked"}},
        {%{{name, :txt} => [SigningKey.dns_record(ed)]},
         {:permerror, "key type does not match the algorithm"}},
        {%{{name, :txt} => ["k=rsa; v=DKIM1; p=abc"]}, {:permerror, "v= is not the first tag"}},
        {%{{name, :txt} => [record <> "; s=other"]}, {:permerror, "key is not for email"}},
        {%{{name, :txt} => [record <> "; h=sha1"]}, {:permerror, "key does not allow sha256"}},
        {%{{name, :txt} => ["junk", record]}, {:pass, nil}}
      ]

      for {records, expected} <- cases do
        assert results(message, FakeDNS.resolver(Map.put_new(records, {"x", :a}, []))) ==
                 [expected],
               inspect(records)
      end
    end

    test "refuses short RSA keys (RFC 8301)" do
      short = :public_key.generate_key({:rsa, 512, 65_537})
      {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} = short
      {_, der, _} = :public_key.pem_entry_encode(:SubjectPublicKeyInfo, {:RSAPublicKey, n, e})

      assert Key.parse("v=DKIM1; p=" <> Base.encode64(der)) ==
               {:error, "RSA key of 512 bits is too short"}

      assert {:error, "RSA keys must have at least 1024 bits"} =
               SigningKey.from_pem(
                 :public_key.pem_encode([:public_key.pem_entry_encode(:RSAPrivateKey, short)]),
                 "example.com",
                 "s"
               )
    end

    test "refuses RSA-SHA1 and unusable signatures", %{rsa: rsa} do
      [signature] = DKIM.sign(@message, [rsa])
      resolver = resolver([rsa])

      sha1 = String.replace(signature, "a=rsa-sha256", "a=rsa-sha1")

      assert [%{result: :permerror, reason: "rsa-sha1 is not accepted (RFC 8301)", b: b}] =
               DKIM.verify(sha1 <> @message, resolver)

      assert byte_size(b) == 8

      for {change, reason} <- [
            {&String.replace(&1, "v=1", "v=2"), "unsupported version"},
            {&String.replace(&1, "a=rsa-sha256", "a=rsa-md5"), "unknown algorithm rsa-md5"},
            {&String.replace(&1, "h=from:to:subject:from", "h=to:subject"), "From is not signed"},
            {&String.replace(&1, "d=example.com", "d=example.com; i=a@other.com"),
             "i= is not in the signing domain"},
            {&String.replace(&1, "s=rsa", "s=rsa; q=http"), "unsupported query method"},
            {&String.replace(&1, "c=relaxed/relaxed", "c=fancy"), "unknown canonicalization"},
            {&String.replace(&1, ~r/t=(\d+)/, "t=\\1; x=1"), "x= is before t="},
            {&String.replace(&1, "s=rsa;", "s=;"), "missing s= tag"}
          ] do
        result = DKIM.verify(change.(signature) <> @message, resolver)
        assert [%{result: :permerror, reason: ^reason, domain: "example.com"}] = result
      end

      duplicate = String.replace(signature, "d=example.com", "d=example.com; d=x")

      assert [%{result: :permerror, reason: "malformed tag list", domain: nil}] =
               DKIM.verify(duplicate <> @message, resolver)
    end

    test "checks expiration and the i= domain", %{rsa: rsa} do
      [signature] = DKIM.sign(@message, [rsa], expiration: 60, identity: "alice@mail.example.com")
      resolver = resolver([rsa])

      assert [%{result: :pass, identity: "alice@mail.example.com"}] =
               DKIM.verify(signature <> @message, resolver)

      assert results(signature <> @message, resolver, now: System.os_time(:second) + 120) ==
               [{:permerror, "signature expired"}]

      strict =
        resolver([], %{
          {SigningKey.dns_name(rsa), :txt} => [SigningKey.dns_record(rsa) <> "; t=s"]
        })

      assert results(signature <> @message, strict) ==
               [{:permerror, "key requires i= to be in d= exactly"}]
    end

    test "honours l= and refuses one longer than the body", %{rsa: rsa} do
      {fields, body} = split(@message)
      {hash, _} = body_hash(body, {:relaxed, :sha256, 5})

      signature =
        fields
        |> DKIM.sign_fields(hash, rsa)
        |> String.replace("c=relaxed/relaxed;", "c=relaxed/relaxed; l=5;")

      # The signature now covers its l= tag, so sign again by hand.
      [_name, value] = :binary.split(signature, ":")
      {:ok, tags} = Tags.parse(value)
      tags = Map.drop(tags, ["b"])
      raw = resign(fields, rsa, tags)

      assert results(raw <> @message <> "appended\r\n", resolver([rsa])) == [{:pass, nil}]

      long = resign(fields, rsa, Map.put(tags, "l", "5000"))

      assert results(long <> @message, resolver([rsa])) == [
               {:permerror, "l= is longer than the body"}
             ]
    end

    test "stops at :max_signatures", %{rsa: rsa} do
      signatures = DKIM.sign(@message, [rsa, rsa, rsa])
      message = Enum.join(signatures) <> @message
      assert length(DKIM.verify(message, resolver([rsa]), max_signatures: 2)) == 2
      assert DKIM.verify(@message, resolver([rsa])) == []
    end
  end

  # Builds and signs a DKIM-Signature field from tags, keeping their order
  # fixed.
  defp resign(fields, key, tags) do
    names = String.split(tags["h"], ":")
    text = Enum.map_join(Enum.sort(tags), "; ", fn {k, v} -> "#{k}=#{v}" end)
    DKIM.signed_field("DKIM-Signature", [text], Canon.select(fields, names), key)
  end

  defp split(message) do
    {:ok, header, body} = Headers.split(message)
    {Headers.parse(header), body}
  end

  defp body_hash(body, spec),
    do: [spec] |> Body.new() |> Body.update(body) |> Body.finish() |> Map.fetch!(spec)

  describe "sign/3" do
    test "dual signs with RSA and Ed25519", %{rsa: rsa, ed: ed} do
      signatures = DKIM.sign(@message, [rsa, ed], timestamp: 1_700_000_000)

      assert [
               "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=rsa;" <> _,
               "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=ed;" <>
                 _
             ] = signatures

      assert Enum.all?(signatures, &(&1 =~ "t=1700000000;" and &1 =~ "h=from:to:subject:from;"))
      assert Enum.all?(signatures, &String.ends_with?(&1, "\r\n"))

      message = Enum.join(signatures) <> @message
      assert [{:pass, nil}, {:pass, nil}] = results(message, resolver([rsa, ed]))

      # From is oversigned: adding another one breaks the signatures.
      assert [{:fail, _}, {:fail, _}] =
               results(
                 Enum.join(signatures) <> "From: mallory@evil.example\r\n" <> @message,
                 resolver([rsa, ed])
               )
    end

    test "signs only the default fields that are present", %{ed: ed} do
      message = "Received: x\r\nFrom: a@example.com\r\nX-Spam: no\r\nDate: today\r\n\r\nbody\r\n"
      [signature] = DKIM.sign(message, [ed], headers: ["from", "date", "x-spam"], oversign: [])
      assert signature =~ "h=from:x-spam:date;"

      [signature] = DKIM.sign(message, [ed])
      assert signature =~ "h=from:date:from;"
    end

    test "folds long fields", %{rsa: rsa} do
      headers = for i <- 1..20, do: "X-H#{i}: v\r\n"
      message = Enum.join(headers) <> @message
      [signature] = DKIM.sign(message, [rsa], headers: Enum.map(1..20, &"x-h#{&1}") ++ ["from"])

      assert signature |> String.split("\r\n") |> Enum.all?(&(byte_size(&1) <= 100))
      assert [{:pass, nil}] = results(signature <> message, resolver([rsa]))
    end
  end

  describe "keys" do
    test "load PKCS#1 and PKCS#8 PEM and refuse others" do
      rsa = :public_key.generate_key({:rsa, 1024, 65_537})
      pkcs1 = :public_key.pem_encode([:public_key.pem_entry_encode(:RSAPrivateKey, rsa)])

      assert {:ok, %SigningKey{algorithm: :rsa_sha256, domain: "example.com"}} =
               SigningKey.from_pem(pkcs1, "Example.COM", "s")

      ec = :public_key.generate_key({:namedCurve, :secp256r1})
      p256 = :public_key.pem_encode([:public_key.pem_entry_encode(:ECPrivateKey, ec)])

      assert SigningKey.from_pem(p256, "example.com", "s") ==
               {:error, "only RSA and Ed25519 keys are supported"}

      assert SigningKey.from_pem("nonsense", "example.com", "s") ==
               {:error, "no private key found"}
    end

    test "print the DNS record", %{ed: ed, rsa: rsa} do
      assert SigningKey.dns_name(ed) == "ed._domainkey.example.com"
      assert "v=DKIM1; k=ed25519; p=" <> _ = SigningKey.dns_record(ed)
      assert {:ok, %Key{type: :rsa, bits: 1024}} = Key.parse(SigningKey.dns_record(rsa))
      assert {:ok, %Key{type: :ed25519}} = Key.parse(SigningKey.dns_record(ed))
    end

    test "parse bare RSAPublicKey records and refuse junk" do
      {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} =
        :public_key.generate_key({:rsa, 1024, 65_537})

      der = :public_key.der_encode(:RSAPublicKey, {:RSAPublicKey, n, e})
      assert {:ok, %Key{bits: 1024}} = Key.parse("p=" <> Base.encode64(der))

      assert Key.parse("p=" <> Base.encode64("junk")) == {:error, "malformed RSA key"}

      assert Key.parse("k=ed25519; p=" <> Base.encode64("short")) ==
               {:error, "malformed ed25519 key"}

      assert Key.parse("k=dsa; p=AAAA") == {:error, "unknown key type dsa"}
      assert Key.parse("v=DKIM2; p=AAAA") == {:error, "unsupported key version"}
      assert Key.parse("p=!!") == {:error, "malformed p= tag"}
      assert Key.parse("k=rsa") == {:error, "key record has no p= tag"}
      assert Key.parse("p") == {:error, "malformed key record"}
    end
  end

  describe "canonicalization" do
    # RFC 6376 §3.4.5.
    @example "A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n"

    test "matches the RFC 6376 example" do
      {fields, body} = split(@example)

      assert Enum.map(fields, &Canon.header(elem(&1, 1), :relaxed)) == ["a:X\r\n", "b:Y Z\r\n"]

      assert Enum.map(fields, &Canon.header(elem(&1, 1), :simple)) == [
               "A: X\r\n",
               "B : Y\t\r\n\tZ  \r\n"
             ]

      assert canonical_body(body, :relaxed) == " C\r\nD E\r\n"
      assert canonical_body(body, :simple) == " C \r\nD \t E\r\n"
    end

    test "handles empty bodies and missing final line breaks" do
      assert canonical_body("", :simple) == "\r\n"
      assert canonical_body("", :relaxed) == ""
      assert canonical_body("\r\n\r\n", :simple) == "\r\n"
      assert canonical_body("\r\n \r\n", :relaxed) == ""
      assert canonical_body("abc", :simple) == "abc\r\n"
      assert canonical_body("abc  ", :relaxed) == "abc\r\n"
      assert canonical_body("a\r\n\r\nb\r\n\r\n", :simple) == "a\r\n\r\nb\r\n"
    end

    test "selects fields from the bottom" do
      fields = Headers.parse("A: 1\r\nB: 2\r\nA: 3\r\n")

      assert Canon.select(fields, ["a", "a", "a", "B", "c"]) == [
               "A: 3\r\n",
               "A: 1\r\n",
               "B: 2\r\n"
             ]
    end

    @tag timeout: :infinity
    property "hashes the same however the body is split" do
      check all(
              lines <- list_of(string([?a, ?\s, ?\t, ?\r, ?\n], max_length: 8), max_length: 20),
              cuts <- list_of(integer(0..200), max_length: 6)
            ) do
        body = Enum.join(lines, "\r\n")
        whole = canonical_body(body, :relaxed)

        chunks = split_at(body, Enum.sort(cuts))
        specs = [{:relaxed, :sha256, nil}, {:simple, :sha256, nil}, {:relaxed, :sha256, 7}]
        streamed = Enum.reduce(chunks, Body.new(specs), &Body.update(&2, &1)) |> Body.finish()
        once = specs |> Body.new() |> Body.update(body) |> Body.finish()

        assert streamed == once

        assert streamed[{:relaxed, :sha256, nil}] ==
                 {:crypto.hash(:sha256, whole), byte_size(whole)}

        limited = binary_part(whole, 0, min(7, byte_size(whole)))
        assert elem(streamed[{:relaxed, :sha256, 7}], 0) == :crypto.hash(:sha256, limited)
      end
    end

    test "canonicalizes very long lines in pieces" do
      long = String.duplicate("ab  ", 40_000)

      for {canon, expected} <- [
            {:relaxed, String.trim_trailing(String.replace(long, "  ", " ")) <> "\r\n"},
            {:simple, long <> "\r\n\r\nx\r\n"}
          ] do
        body = if canon == :simple, do: long <> "\r\n\r\nx\r\n\r\n", else: long <> "\r\n"
        chunks = for <<chunk::binary-size(1000) <- body>>, do: chunk
        rest = binary_part(body, length(chunks) * 1000, byte_size(body) - length(chunks) * 1000)
        spec = {canon, :sha256, nil}

        state = Enum.reduce(chunks ++ [rest], Body.new([spec]), &Body.update(&2, &1))
        assert Body.finish(state)[spec] == {:crypto.hash(:sha256, expected), byte_size(expected)}
      end
    end
  end

  defp canonical_body(body, canon) do
    # The hash of the canonical body equals the hash of the expected text.
    spec = {canon, :sha256, nil}
    {hash, length} = body_hash(body, spec)

    candidates = for text <- candidates(body, canon), do: text

    Enum.find(candidates, &(:crypto.hash(:sha256, &1) == hash and byte_size(&1) == length)) ||
      flunk("no candidate matches")
  end

  # Reference canonicalization, line by line, for the tests.
  defp candidates(body, canon) do
    lines = String.split(body, "\r\n")
    {lines, last} = Enum.split(lines, -1)
    lines = if last == [""], do: lines, else: lines ++ last

    lines =
      if canon == :relaxed,
        do:
          Enum.map(lines, &(&1 |> String.replace(~r/[ \t]+/, " ") |> String.trim_trailing(" "))),
        else: lines

    lines = lines |> Enum.reverse() |> Enum.drop_while(&(&1 == "")) |> Enum.reverse()

    case {lines, canon} do
      {[], :simple} -> ["\r\n"]
      {[], :relaxed} -> [""]
      {lines, _} -> [Enum.map_join(lines, &(&1 <> "\r\n"))]
    end
  end

  defp split_at(body, cuts) do
    {chunks, rest, _} =
      Enum.reduce(cuts, {[], body, 0}, fn cut, {acc, rest, done} ->
        take = min(max(cut - done, 0), byte_size(rest))
        <<chunk::binary-size(^take), rest::binary>> = rest
        {[chunk | acc], rest, done + take}
      end)

    Enum.reverse([rest | chunks])
  end

  describe "Verifier" do
    test "streams the body and lists the hashes it needs", %{rsa: rsa, ed: ed} do
      message = Enum.join(DKIM.sign(@message, [rsa, ed])) <> @message
      {fields, body} = split(message)
      verifier = Verifier.new(fields)
      assert Verifier.body_specs(verifier) == [{:relaxed, :sha256, nil}]

      body_state = Body.new(Verifier.body_specs(verifier))
      body_state = body |> String.codepoints() |> Enum.reduce(body_state, &Body.update(&2, &1))

      assert [%{result: :pass}, %{result: :pass}] =
               Verifier.finish(verifier, Body.finish(body_state), resolver([rsa, ed]))
    end

    test "reports a signature whose body was not hashed", %{rsa: rsa} do
      {fields, _body} = split(Enum.join(DKIM.sign(@message, [rsa])) <> @message)

      assert [%{result: :permerror, reason: "body was not hashed"}] =
               Verifier.finish(Verifier.new(fields), %{}, resolver([rsa]))
    end
  end

  test "Signature.parse/2 reads every tag", %{rsa: rsa} do
    [raw] = DKIM.sign(@message, [rsa], expiration: 10, timestamp: 100)
    assert {:ok, %Signature{} = signature} = Signature.parse(raw, now: 105)
    assert signature.timestamp == 100
    assert signature.expiration == 110
    assert signature.headers == ~w(from to subject from)
    assert {signature.header_canon, signature.body_canon} == {:relaxed, :relaxed}

    simple = String.replace(raw, "c=relaxed/relaxed", "c=relaxed")
    assert {:ok, %Signature{body_canon: :simple}} = Signature.parse(simple, now: 105)

    assert {:error, "malformed c= tag"} =
             Signature.parse(String.replace(raw, "c=relaxed/relaxed", "c=a/b/c"))

    assert {:error, "malformed b= tag"} = Signature.parse(String.replace(raw, "b=", "b=!"))

    assert {:error, "malformed l= tag"} =
             Signature.parse(String.replace(raw, "s=rsa", "s=rsa; l=x"))

    assert {:error, "malformed h= tag"} =
             Signature.parse(String.replace(raw, "h=from", "h=:from"))

    assert {:error, "missing v= tag"} = Signature.parse(String.replace(raw, "v=1; ", ""))
    assert {:error, "missing b= tag"} = Signature.parse(String.replace(raw, ~r/b=[^;]*$/s, "z=1"))
  end
end
