defmodule Sovite.Test.Certs do
  @moduledoc """
  Builds X.509 certificates for tests, without the `openssl` command.

      ca = Certs.ca()
      server = Certs.issue(ca, names: ["mx.example.com"])
      {cert_file, key_file} = Certs.write!(dir, "mx", server)

  Keys are ECDSA P-256 unless `key: :rsa` is given. `issue/2` can also
  sign a given public key (`public_key: ...`), as a CA signs a CSR.
  """

  require Record

  @hrl "public_key/include/public_key.hrl"
  Record.defrecordp(:tbs, :OTPTBSCertificate, Record.extract(:OTPTBSCertificate, from_lib: @hrl))

  @ec_public_key {1, 2, 840, 10_045, 2, 1}
  @p256 {1, 2, 840, 10_045, 3, 1, 7}
  @rsa_encryption {1, 2, 840, 113_549, 1, 1, 1}
  @ecdsa_sha256 {1, 2, 840, 10_045, 4, 3, 2}
  @rsa_sha256 {1, 2, 840, 113_549, 1, 1, 11}

  @doc "A self-signed CA."
  def ca(opts \\ []) do
    key = new_key(Keyword.get(opts, :key, :ec))

    subject =
      name(Keyword.get(opts, :name, "Sovite Test CA #{System.unique_integer([:positive])}"))

    extensions = [
      {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, true, :asn1_NOVALUE}},
      {:Extension, {2, 5, 29, 15}, true, [:keyCertSign, :cRLSign]}
    ]

    der = sign(subject, subject, public(key), key, extensions, opts)
    %{cert: der, key: key, subject: subject, chain: [der]}
  end

  @doc """
  A certificate signed by `issuer` (a `ca/1` or another `issue/2` result
  with `ca: true`).

  ## Options

    * `:names` - DNS names for subjectAltName.
    * `:key` - `:ec`, `:rsa`, or a private key record.
    * `:public_key` - sign this public key (`{point, params}` or an
      `RSAPublicKey`) instead of a new key. The result has no `:key`.
    * `:not_before` / `:not_after` - `DateTime`s. Default: yesterday and in
      90 days.
    * `:ca` - issue an intermediate CA.
    * `:common_name` - subject CN. Defaults to the first name.
  """
  def issue(issuer, opts) do
    names = Keyword.get(opts, :names, [])

    {key, public} =
      case Keyword.fetch(opts, :public_key) do
        {:ok, public} ->
          {nil, public}

        :error ->
          key = new_key(Keyword.get(opts, :key, :ec))
          {key, public(key)}
      end

    extensions =
      if(names != [],
        do: [{:Extension, {2, 5, 29, 17}, false, Enum.map(names, &{:dNSName, to_charlist(&1)})}],
        else: []
      ) ++
        if(opts[:ca],
          do: [
            {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, true, :asn1_NOVALUE}},
            {:Extension, {2, 5, 29, 15}, true, [:keyCertSign, :cRLSign]}
          ],
          else: []
        )

    cn = Keyword.get(opts, :common_name) || List.first(names) || "test"
    subject = name(cn)
    der = sign(subject, issuer.subject, public, issuer.key, extensions, opts)
    %{cert: der, key: key, subject: subject, chain: [der | issuer.chain]}
  end

  @doc "Writes the chain and key as PEM files. Returns `{cert_file, key_file}`."
  def write!(dir, name, %{chain: chain, key: key}) do
    cert_file = Path.join(dir, name <> ".crt")
    key_file = Path.join(dir, name <> ".key")
    File.write!(cert_file, pem_chain(chain))
    File.write!(key_file, pem_key(key))
    {cert_file, key_file}
  end

  def pem_chain(chain),
    do: :public_key.pem_encode(Enum.map(chain, &{:Certificate, &1, :not_encrypted}))

  def pem_key(key) do
    type = elem(key, 0)
    :public_key.pem_encode([{type, :public_key.der_encode(type, key), :not_encrypted}])
  end

  @doc "The `certs_keys` entry for `:ssl`."
  def certs_keys(%{chain: chain, key: key}) do
    type = elem(key, 0)
    %{cert: chain, key: {type, :public_key.der_encode(type, key)}}
  end

  @doc "The public key of a private key, as `issue/2` takes it."
  def public({:ECPrivateKey, _, _, params, point, _}), do: {{:ECPoint, point}, params}
  def public({:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _}), do: {:RSAPublicKey, n, e}

  def new_key(:ec), do: :public_key.generate_key({:namedCurve, @p256})
  def new_key(:rsa), do: :public_key.generate_key({:rsa, 2048, 65_537})
  def new_key(key) when is_tuple(key), do: key

  defp sign(subject, issuer, public, issuer_key, extensions, opts) do
    now = DateTime.utc_now()
    not_before = Keyword.get(opts, :not_before, DateTime.add(now, -1, :day))
    not_after = Keyword.get(opts, :not_after, DateTime.add(now, 90, :day))

    tbs =
      tbs(
        version: :v3,
        serialNumber: :rand.uniform(Bitwise.bsl(1, 62)),
        signature: signature_algorithm(issuer_key),
        issuer: issuer,
        validity: {:Validity, time(not_before), time(not_after)},
        subject: subject,
        subjectPublicKeyInfo: spki(public),
        issuerUniqueID: :asn1_NOVALUE,
        subjectUniqueID: :asn1_NOVALUE,
        extensions: extensions
      )

    :public_key.pkix_sign(tbs, issuer_key)
  end

  defp spki({{:ECPoint, _} = point, params}),
    do: {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, @ec_public_key, params}, point}

  defp spki({:RSAPublicKey, _, _} = key),
    do: {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, @rsa_encryption, :NULL}, key}

  defp signature_algorithm({:ECPrivateKey, _, _, _, _, _}),
    do: {:SignatureAlgorithm, @ecdsa_sha256, :asn1_NOVALUE}

  defp signature_algorithm(_rsa), do: {:SignatureAlgorithm, @rsa_sha256, :NULL}

  defp name(cn),
    do: {:rdnSequence, [[{:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, cn}}]]}

  defp time(%DateTime{} = dt) do
    {:generalTime, dt |> Calendar.strftime("%Y%m%d%H%M%SZ") |> to_charlist()}
  end
end
