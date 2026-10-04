defmodule Sovite.TLS.CertificateTest do
  use ExUnit.Case, async: true

  alias Sovite.Test.Certs
  alias Sovite.TLS.Certificate

  @moduletag :tmp_dir

  setup_all do
    %{ca: Certs.ca()}
  end

  test "loads a chain and key, with names and expiry", %{ca: ca, tmp_dir: dir} do
    for key <- [:ec, :rsa] do
      cert =
        Certs.issue(ca,
          names: ["MX.example.com", "*.example.org"],
          key: key,
          not_after: ~U[2030-01-02 03:04:05Z]
        )

      {cert_file, key_file} = Certs.write!(dir, "mx-#{key}", cert)

      assert {:ok, loaded} = Certificate.load(cert_file, key_file)
      assert loaded.names == ["mx.example.com", "*.example.org"]
      assert loaded.not_after == ~U[2030-01-02 03:04:05Z]
      assert length(loaded.chain) == 2
      assert loaded.cert_file == cert_file
      assert %{cert: [_, _], key: {_, _}} = Certificate.certs_keys(loaded)
    end
  end

  test "falls back to the common name without subjectAltName", %{ca: ca} do
    cert = Certs.issue(ca, names: [], common_name: "Legacy.Example.com")

    assert {:ok, %{names: ["legacy.example.com"]}} =
             Certificate.decode(Certs.pem_chain(cert.chain), Certs.pem_key(cert.key))
  end

  test "matches names and single-label wildcards", %{ca: ca} do
    cert = Certs.issue(ca, names: ["mx.example.com", "*.example.org"])
    {:ok, loaded} = Certificate.decode(Certs.pem_chain(cert.chain), Certs.pem_key(cert.key))

    assert Certificate.matches?(loaded, "MX.example.com.")
    assert Certificate.matches?(loaded, "a.example.org")
    refute Certificate.matches?(loaded, "example.org")
    refute Certificate.matches?(loaded, "a.b.example.org")
    refute Certificate.matches?(loaded, ".example.org")
    refute Certificate.matches?(loaded, "other.example.com")
  end

  test "refuses mismatched, missing, and broken input", %{ca: ca, tmp_dir: dir} do
    a = Certs.issue(ca, names: ["a.test"])
    b = Certs.issue(ca, names: ["b.test"])

    assert Certificate.decode(Certs.pem_chain(a.chain), Certs.pem_key(b.key)) ==
             {:error, :key_mismatch}

    assert Certificate.decode("", Certs.pem_key(a.key)) == {:error, :no_certificate}

    assert Certificate.decode(Certs.pem_chain(a.chain), Certs.pem_chain(a.chain)) ==
             {:error, :no_key}

    assert Certificate.decode(Certs.pem_chain(a.chain), "garbage") == {:error, :no_key}

    broken = :public_key.pem_encode([{:Certificate, "not der", :not_encrypted}])
    assert Certificate.decode(broken, Certs.pem_key(a.key)) == {:error, :invalid_certificate}

    cipher = {{~c"DES-EDE3-CBC", :crypto.strong_rand_bytes(8)}, ~c"pw"}

    encrypted =
      :public_key.pem_encode([:public_key.pem_entry_encode(:ECPrivateKey, a.key, cipher)])

    assert Certificate.decode(Certs.pem_chain(a.chain), encrypted) == {:error, :encrypted_key}

    assert Certificate.load(Path.join(dir, "missing.crt"), Path.join(dir, "missing.key")) ==
             {:error, {:cert_file, :enoent}}
  end
end
