defmodule Sovite.TLSTest do
  use ExUnit.Case, async: true

  alias Sovite.Test.Certs

  alias Sovite.TLS
  alias Sovite.TLS.DANE

  doctest TLS

  test "allows only strong cipher suites" do
    assert {:ok, [_, _]} = TLS.ciphers(["ECDHE-RSA-AES128-GCM-SHA256", "TLS_AES_128_GCM_SHA256"])
    assert TLS.ciphers(["AES128-SHA"]) == {:error, {:weak_cipher, "AES128-SHA"}}

    assert TLS.ciphers(["DHE-RSA-AES128-GCM-SHA256"]) ==
             {:error, {:weak_cipher, "DHE-RSA-AES128-GCM-SHA256"}}

    assert TLS.ciphers(["ECDHE-RSA-AES128-SHA256"]) ==
             {:error, {:weak_cipher, "ECDHE-RSA-AES128-SHA256"}}

    assert TLS.ciphers(["NOPE"]) == {:error, {:unknown_cipher, "NOPE"}}
  end

  test "the defaults are all accepted" do
    for version <- [:"tlsv1.2", :"tlsv1.3"] do
      assert {:ok, suites} = TLS.ciphers(TLS.default_ciphers(version))
      assert length(suites) == length(TLS.default_ciphers(version))
    end

    assert Enum.all?(TLS.default_ciphers(:"tlsv1.3"), &String.starts_with?(&1, "TLS_"))
  end

  test "server options pin versions and refuse client renegotiation" do
    opts = TLS.server_options(certs_keys: [], min_version: :"tlsv1.3")
    assert opts[:versions] == [:"tlsv1.3"]
    assert opts[:client_renegotiation] == false
    assert opts[:honor_cipher_order] == true
    assert opts[:log_level] == :none
    refute Keyword.has_key?(opts, :sni_fun)
    assert_raise ArgumentError, fn -> TLS.server_options(certs_keys: [], ciphers: ["RC4-SHA"]) end
  end

  test "client options verify only when asked" do
    assert TLS.client_options([])[:verify] == :verify_none
    assert TLS.client_options([])[:server_name_indication] == :disable
    opts = TLS.client_options(verify: :peer, hostname: "mx.example.com", cacerts: [])
    assert opts[:verify] == :verify_peer
    assert opts[:server_name_indication] == ~c"mx.example.com"
  end

  test "formats errors" do
    assert TLS.format_error({:tls_alert, {:handshake_failure, ~c"oops"}}) == "oops"
    assert TLS.format_error(:timeout) == "timeout"
    assert TLS.format_error(:closed) == "connection closed"
    assert TLS.format_error({:options, :x}) == "invalid TLS option :x"
    assert TLS.format_error({:weird, 1}) == "{:weird, 1}"
  end

  describe "report_verify/3" do
    setup do
      ca = Certs.ca()
      %{ca: ca, leaf: Certs.issue(ca, names: ["mx.example.com"])}
    end

    defp connect(cert, ssl) do
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

      result = :ssl.connect({127, 0, 0, 1}, port, ssl, 5_000)
      :ssl.close(listen)
      with {:ok, socket} <- result, do: :ssl.close(socket)
    end

    defp verifying(ca, hostname),
      do: Sovite.TLS.client_options(verify: :peer, hostname: hostname, cacerts: [ca.cert])

    test "reports problems and fails the handshake", %{ca: ca, leaf: leaf} do
      ref = make_ref()
      ssl = Sovite.TLS.report_verify(verifying(ca, "other.example.com"), {self(), ref})
      assert {:error, _} = connect(leaf, ssl)
      assert_received {:tls_verify, ^ref, :hostname_check_failed}

      ssl = Sovite.TLS.report_verify(verifying(Certs.ca(), "mx.example.com"), {self(), ref})
      assert {:error, _} = connect(leaf, ssl)
      assert_received {:tls_verify, ^ref, :unknown_ca}

      ssl = Sovite.TLS.report_verify(verifying(ca, "mx.example.com"), {self(), ref})
      assert :ok = connect(leaf, ssl)
      refute_received {:tls_verify, ^ref, _}
    end

    test "only reports without enforce", %{ca: ca, leaf: leaf} do
      ref = make_ref()

      ssl =
        Sovite.TLS.report_verify(verifying(ca, "other.example.com"), {self(), ref},
          enforce: false
        )

      assert :ok = connect(leaf, ssl)
      assert_received {:tls_verify, ^ref, :hostname_check_failed}
    end

    test "wraps DANE verification and leaves unverified options alone", %{leaf: leaf} do
      ref = make_ref()
      ssl = DANE.client_options([{3, 0, 1, :binary.copy(<<0>>, 32)}], "mx.example.com")
      assert {:error, _} = connect(leaf, Sovite.TLS.report_verify(ssl, {self(), ref}))
      assert_received {:tls_verify, ^ref, :dane_mismatch}

      plain = Sovite.TLS.client_options([])
      assert Sovite.TLS.report_verify(plain, {self(), ref}) == plain
    end
  end
end
