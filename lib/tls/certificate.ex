defmodule Sovite.TLS.Certificate do
  @moduledoc """
  A certificate chain and its private key, loaded from PEM files.

  The certificate file holds the server certificate first, then any
  intermediate certificates, as most CAs (and ACME clients) write it. The
  key file holds one unencrypted private key: RSA, EC, or PKCS #8.

  The key is checked against the certificate, so a mismatched pair is
  rejected at load time instead of failing every handshake.
  """

  @enforce_keys [:chain, :key, :names, :not_after]
  defstruct [:chain, :key, :names, :not_after, :cert_file, :key_file]

  @type t :: %__MODULE__{
          chain: [binary(), ...],
          key: {atom(), binary()},
          names: [String.t()],
          not_after: DateTime.t(),
          cert_file: Path.t() | nil,
          key_file: Path.t() | nil
        }

  @typedoc """
  Why a certificate could not be loaded:

    * `{:cert_file | :key_file, File.posix()}` - the file cannot be read.
    * `:no_certificate` / `:no_key` - the PEM data has none.
    * `:encrypted_key` - the key is protected by a passphrase.
    * `:invalid_certificate` / `:invalid_key` - the data does not decode.
    * `:key_mismatch` - the key does not belong to the certificate.
  """
  @type error ::
          {:cert_file | :key_file, File.posix()}
          | :no_certificate
          | :no_key
          | :encrypted_key
          | :invalid_certificate
          | :invalid_key
          | :key_mismatch

  @doc "Loads a certificate chain and key from PEM files."
  @spec load(Path.t(), Path.t()) :: {:ok, t()} | {:error, error()}
  def load(cert_file, key_file) do
    with {:ok, cert_pem} <- read(cert_file, :cert_file),
         {:ok, key_pem} <- read(key_file, :key_file),
         {:ok, cert} <- decode(cert_pem, key_pem) do
      {:ok, %{cert | cert_file: cert_file, key_file: key_file}}
    end
  end

  defp read(path, kind) do
    case File.read(path) do
      {:ok, data} -> {:ok, data}
      {:error, reason} -> {:error, {kind, reason}}
    end
  end

  @doc "Decodes a certificate chain and key from PEM data."
  @spec decode(binary(), binary()) :: {:ok, t()} | {:error, error()}
  def decode(cert_pem, key_pem) do
    with {:ok, chain} <- decode_chain(cert_pem),
         {:ok, key} <- decode_key(key_pem),
         {:ok, otp} <- decode_cert(hd(chain)),
         :ok <- check_pair(otp, key) do
      {:ok,
       %__MODULE__{
         chain: chain,
         key: key,
         names: names(otp),
         not_after: not_after(otp)
       }}
    end
  end

  @doc """
  Returns whether the certificate is valid for `hostname`. A wildcard
  name matches exactly one label (`*.example.com` matches
  `mx.example.com`, not `example.com` or `a.b.example.com`).
  """
  @spec matches?(t(), String.t()) :: boolean()
  def matches?(%__MODULE__{names: names}, hostname) do
    hostname = hostname |> String.trim_trailing(".") |> String.downcase(:ascii)
    Enum.any?(names, &name_matches?(&1, hostname))
  end

  defp name_matches?("*." <> suffix, hostname) do
    case :binary.split(hostname, ".") do
      [label, rest] -> label != "" and rest == suffix
      _ -> false
    end
  end

  defp name_matches?(name, hostname), do: name == hostname

  @doc "Returns the certificate as an `:ssl` `certs_keys` entry."
  @spec certs_keys(t()) :: map()
  def certs_keys(%__MODULE__{chain: chain, key: key}), do: %{cert: chain, key: key}

  ## Decoding

  defp decode_chain(pem) do
    case pem_entries(pem) do
      {:ok, entries} ->
        case for({:Certificate, der, :not_encrypted} <- entries, do: der) do
          [] -> {:error, :no_certificate}
          chain -> {:ok, chain}
        end

      :error ->
        {:error, :invalid_certificate}
    end
  end

  @key_types [:RSAPrivateKey, :ECPrivateKey, :PrivateKeyInfo]

  defp decode_key(pem) do
    with {:ok, entries} <- pem_entries(pem) do
      case Enum.find(entries, fn {type, _der, _} ->
             type in [:EncryptedPrivateKeyInfo | @key_types]
           end) do
        nil -> {:error, :no_key}
        {_type, _der, encryption} when encryption != :not_encrypted -> {:error, :encrypted_key}
        {:EncryptedPrivateKeyInfo, _der, _} -> {:error, :encrypted_key}
        {type, der, :not_encrypted} -> {:ok, {type, der}}
      end
    else
      :error -> {:error, :invalid_key}
    end
  end

  defp pem_entries(pem) do
    {:ok, :public_key.pem_decode(pem)}
  rescue
    _ -> :error
  end

  defp decode_cert(der) do
    {:ok, :public_key.pkix_decode_cert(der, :otp)}
  rescue
    _ -> {:error, :invalid_certificate}
  end

  # Signs a test message with the key and verifies it with the
  # certificate's public key.
  defp check_pair(otp, {type, der}) do
    private = :public_key.der_decode(type, der) |> unwrap_pkcs8()
    public = otp |> tbs() |> elem(7) |> public_key()
    digest = if eddsa?(private), do: :none, else: :sha256
    message = "sovite key check"

    if :public_key.verify(message, digest, :public_key.sign(message, digest, private), public),
      do: :ok,
      else: {:error, :key_mismatch}
  rescue
    _ -> {:error, :invalid_key}
  end

  # PKCS #8 keys decode to the inner key record already on current OTP;
  # older versions return the PrivateKeyInfo record.
  defp unwrap_pkcs8(key) when elem(key, 0) == :PrivateKeyInfo,
    do:
      :public_key.pem_entry_decode(
        {:PrivateKeyInfo, :public_key.der_encode(:PrivateKeyInfo, key), :not_encrypted}
      )

  defp unwrap_pkcs8(key), do: key

  defp eddsa?({:ECPrivateKey, _, _, {:namedCurve, curve}, _, _}),
    do: curve in [{1, 3, 101, 112}, {1, 3, 101, 113}, :ed25519, :ed448]

  defp eddsa?(_), do: false

  # OTPSubjectPublicKeyInfo: {_, {_, algorithm, params}, key}
  defp public_key({:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, _alg, params}, key}) do
    case {key, params} do
      {{:ECPoint, _} = point, {:namedCurve, _} = curve} -> {point, curve}
      {key, _} -> key
    end
  end

  defp tbs({:OTPCertificate, tbs, _alg, _sig}), do: tbs

  # OTPTBSCertificate fields: version, serialNumber, signature, issuer,
  # validity, subject, subjectPublicKeyInfo, ..., extensions (last).
  defp names(otp) do
    tbs = tbs(otp)
    extensions = elem(tbs, tuple_size(tbs) - 1)

    san =
      for {:Extension, {2, 5, 29, 17}, _critical, names} <- List.wrap(extensions),
          {:dNSName, name} <- names,
          do: name |> to_string() |> String.downcase(:ascii)

    if san != [], do: Enum.uniq(san), else: common_names(elem(tbs, 6))
  end

  defp common_names({:rdnSequence, rdns}) do
    for rdn <- rdns,
        {:AttributeTypeAndValue, {2, 5, 4, 3}, value} <- rdn,
        name = directory_string(value),
        do: String.downcase(name, :ascii)
  end

  defp directory_string({_type, value}) when is_list(value), do: List.to_string(value)
  defp directory_string({_type, value}) when is_binary(value), do: value
  defp directory_string(value) when is_list(value), do: List.to_string(value)
  defp directory_string(_value), do: nil

  defp not_after(otp) do
    {:Validity, _not_before, not_after} = otp |> tbs() |> elem(5)
    parse_time(not_after)
  end

  defp parse_time({:utcTime, time}) do
    <<yy::binary-size(2), rest::binary>> = to_string(time)
    year = String.to_integer(yy)
    parse_time({:generalTime, "#{if year >= 50, do: 19, else: 20}#{yy}#{rest}"})
  end

  defp parse_time({:generalTime, time}) do
    <<y::binary-size(4), mo::binary-size(2), d::binary-size(2), h::binary-size(2),
      mi::binary-size(2), s::binary-size(2), "Z">> = to_string(time)

    [y, mo, d, h, mi, s] = Enum.map([y, mo, d, h, mi, s], &String.to_integer/1)
    DateTime.new!(Date.new!(y, mo, d), Time.new!(h, mi, s))
  end
end
