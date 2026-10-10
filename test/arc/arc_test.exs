defmodule Sovite.ARCTest do
  use ExUnit.Case, async: true

  alias Sovite.ARC
  alias Sovite.DKIM
  alias Sovite.DKIM.{Body, SigningKey}
  alias Sovite.Message.Headers
  alias Sovite.Test.FakeDNS

  @message "From: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n"

  setup_all do
    {:ok, first} = SigningKey.from_pem(SigningKey.generate(:rsa, 1024), "list.example", "arc")
    {:ok, second} = SigningKey.from_pem(SigningKey.generate(:ed25519), "fwd.example", "arc")

    resolver =
      FakeDNS.resolver(
        Map.new([first, second], &{{SigningKey.dns_name(&1), :txt}, [SigningKey.dns_record(&1)]})
      )

    %{first: first, second: second, resolver: resolver}
  end

  defp parse(message) do
    {:ok, header, body} = Headers.split(message)
    {Headers.parse(header), body}
  end

  defp validate(message, resolver) do
    {fields, body} = parse(message)
    verifier = ARC.new(fields)
    hashes = verifier |> ARC.body_specs() |> Body.new() |> Body.update(body) |> Body.finish()
    ARC.finish(verifier, hashes, resolver)
  end

  defp seal(message, key, resolver) do
    {fields, body} = parse(message)
    spec = DKIM.body_spec()
    {hash, _} = [spec] |> Body.new() |> Body.update(body) |> Body.finish() |> Map.fetch!(spec)
    result = validate(message, resolver)

    Enum.join(ARC.seal(fields, hash, result, "#{key.domain}; spf=pass smtp.mailfrom=a@b", key)) <>
      message
  end

  test "a message without ARC sets has cv=none", %{resolver: resolver} do
    assert validate(@message, resolver) == %ARC.Result{cv: :none, instance: 0}
  end

  test "seals and validates a chain over two hops", %{
    first: first,
    second: second,
    resolver: resolver
  } do
    once = seal(@message, first, resolver)

    assert "ARC-Authentication-Results: i=1; list.example; spf=pass smtp.mailfrom=a@b\r\n" <>
             "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=list.example;" <> _ =
             once

    assert once =~ "ARC-Seal: i=1; a=rsa-sha256; t="
    assert once =~ "cv=none; d=list.example; s=arc;"

    assert %ARC.Result{cv: :pass, instance: 1, sealers: ["list.example"]} =
             validate(once, resolver)

    # A forwarder adds a field and seals again.
    twice = seal("Received: from list\r\n" <> once, second, resolver)
    assert twice =~ "ARC-Seal: i=2; a=ed25519-sha256;"
    assert twice =~ "cv=pass;"

    assert %ARC.Result{cv: :pass, instance: 2, sealers: ["list.example", "fwd.example"]} =
             validate(twice, resolver)
  end

  test "a changed message or chain fails", %{first: first, second: second, resolver: resolver} do
    twice = seal(seal(@message, first, resolver), second, resolver)

    assert %{cv: :fail, reason: "ARC-Message-Signature 2: body hash did not verify"} =
             validate(twice <> "more\r\n", resolver)

    changed = String.replace(twice, "i=1; list.example", "i=1; list.example.net")

    assert %{cv: :fail, reason: "ARC-Seal 2: signature did not verify"} =
             validate(changed, resolver)

    # The newest message signature covers the header; older ones may break.
    assert %{cv: :fail, reason: "ARC-Message-Signature 2: signature did not verify"} =
             validate(String.replace(twice, "Subject: hi", "Subject: ho"), resolver)

    unknown = FakeDNS.resolver(%{})

    assert %{cv: :fail, reason: "ARC-Message-Signature 2: no key for " <> _} =
             validate(twice, unknown)
  end

  test "a broken chain is sealed once with cv=fail, then never again",
       %{first: first, second: second, resolver: resolver} do
    broken = String.replace(seal(@message, first, resolver), "body", "changed body")
    assert %{cv: :fail} = validate(broken, resolver)

    failed = seal(broken, second, resolver)
    assert failed =~ "ARC-Seal: i=2; a=ed25519-sha256;"
    assert failed =~ "cv=fail;"
    assert %{cv: :fail, reason: "the chain was already broken"} = validate(failed, resolver)

    assert seal(failed, first, resolver) == failed
  end

  test "checks the structure of the chain", %{first: first, resolver: resolver} do
    once = seal(@message, first, resolver)
    [aar, ams, as | _] = once |> parse() |> elem(0) |> Enum.map(&elem(&1, 1))

    cases = [
      {aar <> as <> @message, "ARC set 1 is incomplete or has duplicates"},
      {aar <> aar <> ams <> as <> @message, "ARC set 1 is incomplete or has duplicates"},
      {String.replace(once, "i=1", "i=2"), "ARC instances are not 1..N"},
      {String.replace(once, "ARC-Seal: i=1", "ARC-Seal: i=x"),
       "an ARC field has no valid instance"},
      {String.replace(once, "cv=none", "cv=pass"), "ARC-Seal 1 has cv=pass"},
      {String.replace(once, "cv=none", "cv=maybe"), "ARC-Seal 1: malformed cv= tag"},
      {String.replace(once, ~r/ARC-Seal: i=1; a=rsa-sha256/, "ARC-Seal: i=1; a=rsa-sha1"),
       "ARC-Seal 1: unsupported algorithm"},
      {String.replace(
         once,
         "ARC-Message-Signature: i=1; a=rsa-sha256",
         "ARC-Message-Signature: i=1; a=x"
       ), "ARC-Message-Signature: unknown algorithm x"}
    ]

    for {message, reason} <- cases do
      assert %{cv: :fail, reason: ^reason} = validate(message, resolver)
    end

    # A broken structure is never sealed.
    {fields, _} = parse(String.replace(once, "i=1", "i=2"))
    assert ARC.seal(fields, "hash", %ARC.Result{cv: :fail}, "x; none", first) == []
  end

  test "does not seal beyond 50 instances", %{first: first} do
    {fields, _} = parse(@message)
    assert ARC.seal(fields, "hash", %ARC.Result{cv: :pass, instance: 50}, "x; none", first) == []
  end
end
