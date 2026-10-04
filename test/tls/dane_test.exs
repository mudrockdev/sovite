defmodule Sovite.TLS.DANETest do
  use ExUnit.Case, async: true

  alias Sovite.Test.Certs
  alias Sovite.TLS.DANE

  setup_all do
    ca = Certs.ca()
    leaf = Certs.issue(ca, names: ["mx.example.com"])
    %{ca: ca, leaf: leaf}
  end

  defp spki_sha256(der) do
    {:Certificate, tbs, _, _} = :public_key.pkix_decode_cert(der, :plain)
    :crypto.hash(:sha256, :public_key.der_encode(:SubjectPublicKeyInfo, elem(tbs, 7)))
  end

  # Serves `cert` (with its chain) on a TLS port and connects with DANE.
  defp handshake(cert, records, hostname) do
    {:ok, listen} =
      :ssl.listen(
        0,
        Sovite.TLS.server_options(certs_keys: [Certs.certs_keys(cert)]) ++
          [reuseaddr: true, ip: {127, 0, 0, 1}]
      )

    {:ok, {_, port}} = :ssl.sockname(listen)

    spawn_link(fn ->
      {:ok, socket} = :ssl.transport_accept(listen)
      _ = :ssl.handshake(socket, 5_000)
      Process.sleep(500)
    end)

    result = :ssl.connect({127, 0, 0, 1}, port, DANE.client_options(records, hostname), 5_000)
    :ssl.close(listen)

    case result do
      {:ok, socket} ->
        :ssl.close(socket)
        :ok

      {:error, reason} ->
        {:error, reason}
    end
  end

  test "keeps only records usable for SMTP" do
    good = [{3, 1, 1, :binary.copy("a", 32)}, {2, 0, 2, :binary.copy("b", 64)}, {3, 0, 0, "der"}]

    bad = [
      {1, 1, 1, :binary.copy("a", 32)},
      {0, 0, 1, :binary.copy("a", 32)},
      {3, 2, 1, :binary.copy("a", 32)},
      {3, 1, 1, "short"},
      {3, 1, 3, "x"},
      {3, 0, 0, ""}
    ]

    assert DANE.usable(good ++ bad) == good
  end

  test "matches certificates and keys with every matching type", %{leaf: leaf} do
    der = leaf.cert
    assert DANE.matches?(der, {3, 0, 0, der})
    assert DANE.matches?(der, {3, 0, 1, :crypto.hash(:sha256, der)})
    assert DANE.matches?(der, {3, 0, 2, :crypto.hash(:sha512, der)})
    assert DANE.matches?(der, {3, 1, 1, spki_sha256(der)})
    refute DANE.matches?(der, {3, 1, 1, :crypto.hash(:sha256, "other")})
    refute DANE.matches?("not a certificate", {3, 1, 1, spki_sha256(der)})
  end

  test "DANE-EE accepts the key regardless of name, issuer, and dates", %{ca: ca, leaf: leaf} do
    assert handshake(leaf, [{3, 1, 1, spki_sha256(leaf.cert)}], "other.example") == :ok

    expired =
      Certs.issue(ca,
        names: ["mx.example.com"],
        not_before: ~U[2020-01-01 00:00:00Z],
        not_after: ~U[2020-02-01 00:00:00Z]
      )

    assert handshake(expired, [{3, 1, 1, spki_sha256(expired.cert)}], "mx.example.com") == :ok
  end

  test "DANE-EE rejects another key", %{leaf: leaf} do
    assert {:error, _} =
             handshake(leaf, [{3, 1, 1, :crypto.hash(:sha256, "nope")}], "mx.example.com")
  end

  test "DANE-TA needs the chain to be valid for the host name", %{ca: ca, leaf: leaf} do
    record = {2, 0, 1, :crypto.hash(:sha256, ca.cert)}
    assert handshake(leaf, [record], "mx.example.com") == :ok
    assert {:error, _} = handshake(leaf, [record], "other.example")

    expired =
      Certs.issue(ca,
        names: ["mx.example.com"],
        not_before: ~U[2020-01-01 00:00:00Z],
        not_after: ~U[2020-02-01 00:00:00Z]
      )

    assert {:error, _} = handshake(expired, [record], "mx.example.com")

    other_ca = Certs.ca()

    assert {:error, _} =
             handshake(leaf, [{2, 0, 1, :crypto.hash(:sha256, other_ca.cert)}], "mx.example.com")
  end

  test "either record type may match", %{ca: ca, leaf: leaf} do
    records = [{3, 1, 1, :crypto.hash(:sha256, "stale")}, {2, 1, 1, spki_sha256(ca.cert)}]
    assert handshake(leaf, records, "mx.example.com") == :ok
  end
end
