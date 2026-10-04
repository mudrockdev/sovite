defmodule Sovite.TLS.ACMETest do
  use ExUnit.Case, async: true

  alias Sovite.Test.FakeACME
  alias Sovite.TLS.{ACME, Certificate}
  alias Sovite.TLS.ACME.CSR

  @p256 {1, 2, 840, 10_045, 3, 1, 7}

  defp new_key, do: :public_key.generate_key({:namedCurve, @p256})

  # A challenge responder on a random port, like Sovite.Core.ACME runs.
  defp responder do
    table = :ets.new(:challenges, [:public])

    listener =
      start_supervised!(
        {Sovite.Listener,
         ip: {127, 0, 0, 1},
         port: 0,
         handler: Sovite.TLS.ACME.HTTPChallenge,
         handler_opts: [table: table]},
        id: make_ref()
      )

    {:ok, {_, port}} = Sovite.Listener.sockname(listener)

    publish = fn
      {:put, token, auth} -> :ets.insert(table, {token, auth})
      {:delete, token} -> :ets.delete(table, token)
    end

    {port, table, publish}
  end

  test "registers and obtains a certificate with HTTP-01" do
    {port, table, publish} = responder()
    ca = FakeACME.start!(challenge_port: port)

    {:ok, acme} = ACME.connect(FakeACME.directory_url(ca), new_key(), poll_interval: 10)
    {:ok, acme} = ACME.register(acme, "admin@example.com")

    key = new_key()

    assert {:ok, pem, _acme} =
             ACME.obtain(acme, ["mx.example.com", "mail.example.com"], key, publish)

    key_pem =
      :public_key.pem_encode([
        {:ECPrivateKey, :public_key.der_encode(:ECPrivateKey, key), :not_encrypted}
      ])

    assert {:ok, cert} = Certificate.decode(pem, key_pem)
    assert cert.names == ["mx.example.com", "mail.example.com"]
    assert length(cert.chain) == 2
    # Challenges are withdrawn afterwards.
    assert :ets.tab2list(table) == []
  end

  test "retries once after a bad nonce" do
    {port, _table, publish} = responder()
    ca = FakeACME.start!(challenge_port: port, bad_nonce_once: true)
    {:ok, acme} = ACME.connect(FakeACME.directory_url(ca), new_key(), poll_interval: 10)
    {:ok, acme} = ACME.register(acme, "admin@example.com")
    assert {:ok, _pem, _} = ACME.obtain(acme, ["mx.example.com"], new_key(), publish)
  end

  test "reports a failed challenge" do
    {port, _table, _publish} = responder()
    ca = FakeACME.start!(challenge_port: port)
    {:ok, acme} = ACME.connect(FakeACME.directory_url(ca), new_key(), poll_interval: 10)
    {:ok, acme} = ACME.register(acme, "admin@example.com")

    # Publishes nothing, so the CA gets 404.
    assert {:error, {:challenge_failed, "mx.example.com", "got 404" <> _}} =
             ACME.obtain(acme, ["mx.example.com"], new_key(), fn _ -> :ok end)
  end

  test "reports problems and unreachable servers" do
    assert {:error, _} = ACME.connect("http://127.0.0.1:1/directory", new_key(), timeout: 1000)

    {port, _table, _publish} = responder()
    ca = FakeACME.start!(challenge_port: port)
    {:ok, acme} = ACME.connect(FakeACME.directory_url(ca), new_key())

    # An order without an account is refused with a problem document.
    assert {:error, {:acme, "urn:ietf:params:acme:error:malformed", _}} =
             ACME.obtain(acme, ["mx.example.com"], new_key(), fn _ -> :ok end)
  end

  test "key authorizations use the RFC 7638 thumbprint" do
    {port, _table, _publish} = responder()
    ca = FakeACME.start!(challenge_port: port)
    {:ok, acme} = ACME.connect(FakeACME.directory_url(ca), new_key())
    assert [token, thumbprint] = acme |> ACME.key_authorization("tok") |> String.split(".")
    assert token == "tok"
    assert byte_size(Base.url_decode64!(thumbprint, padding: false)) == 32
  end

  test "builds CSRs that verify" do
    key = new_key()
    der = CSR.build(["mx.example.com", "alt.example.com"], key)

    {:CertificationRequest, info, _alg, signature} =
      :public_key.der_decode(:CertificationRequest, der)

    {:ECPrivateKey, _, _, params, point, _} = key
    info_der = :public_key.der_encode(:CertificationRequestInfo, info)
    assert :public_key.verify(info_der, :sha256, signature, {{:ECPoint, point}, params})
  end

  test "the challenge responder answers only known tokens" do
    {port, table, _publish} = responder()
    :ets.insert(table, {"tok", "tok.thumb"})

    get = fn path ->
      {:ok, {{_, status, _}, _, body}} =
        :httpc.request(:get, {~c"http://127.0.0.1:#{port}#{path}", []}, [], body_format: :binary)

      {status, body}
    end

    assert get.("/.well-known/acme-challenge/tok") == {200, "tok.thumb"}
    assert {404, _} = get.("/.well-known/acme-challenge/other")
    assert {404, _} = get.("/.well-known/acme-challenge/../../etc")
    assert {404, _} = get.("/")
  end
end
