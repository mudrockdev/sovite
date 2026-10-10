defmodule Sovite.DKIM.SigningKey do
  @moduledoc """
  A private key to sign with, for one domain and selector, and the key
  record to publish for it.

      {:ok, key} = Sovite.DKIM.SigningKey.from_pem(File.read!(path), "example.com", "s2026")
      Sovite.DKIM.SigningKey.dns_name(key)    #=> "s2026._domainkey.example.com"
      Sovite.DKIM.SigningKey.dns_record(key)  #=> "v=DKIM1; k=rsa; p=MIIBIjANBg..."

  Keys are PEM files, as `openssl genpkey` writes them or `generate/2`
  returns: PKCS#8 (`PRIVATE KEY`), or for RSA also PKCS#1
  (`RSA PRIVATE KEY`). RSA keys must have at least 1024 bits; 2048 is
  the usual size (RFC 8301 §3.2).
  """

  @enforce_keys [:domain, :selector, :algorithm, :private, :public]
  defstruct [:domain, :selector, :algorithm, :private, :public]

  @type t :: %__MODULE__{
          domain: String.t(),
          selector: String.t(),
          algorithm: :rsa_sha256 | :ed25519_sha256,
          private: tuple() | binary(),
          public: tuple() | binary()
        }

  @ed25519 {1, 3, 101, 112}

  @doc "Loads a private key from PEM data."
  @spec from_pem(binary(), String.t(), String.t()) :: {:ok, t()} | {:error, String.t()}
  def from_pem(pem, domain, selector) do
    entries =
      try do
        :public_key.pem_decode(pem)
      rescue
        _ -> []
      end

    case Enum.find(entries, &(elem(&1, 0) in [:PrivateKeyInfo, :RSAPrivateKey, :ECPrivateKey])) do
      nil -> {:error, "no private key found"}
      {_type, _der, :not_encrypted} = entry -> decode(entry, domain, selector)
      _encrypted -> {:error, "the private key is encrypted"}
    end
  end

  defp decode(entry, domain, selector) do
    case :public_key.pem_entry_decode(entry) do
      {:RSAPrivateKey, _, modulus, exponent, _, _, _, _, _, _, _} = private ->
        if bit_size(:binary.encode_unsigned(modulus)) < 1024,
          do: {:error, "RSA keys must have at least 1024 bits"},
          else:
            {:ok, new(domain, selector, :rsa_sha256, private, {:RSAPublicKey, modulus, exponent})}

      {:ECPrivateKey, _, private, {:namedCurve, @ed25519}, _, _} ->
        {public, _} = :crypto.generate_key(:eddsa, :ed25519, private)
        {:ok, new(domain, selector, :ed25519_sha256, private, public)}

      _other ->
        {:error, "only RSA and Ed25519 keys are supported"}
    end
  rescue
    _ -> {:error, "malformed private key"}
  end

  defp new(domain, selector, algorithm, private, public) do
    %__MODULE__{
      domain: String.downcase(domain, :ascii),
      selector: selector,
      algorithm: algorithm,
      private: private,
      public: public
    }
  end

  @doc """
  Generates a new private key as PKCS#8 PEM: `:rsa` with `bits` (2048 by
  default) or `:ed25519`.
  """
  @spec generate(:rsa | :ed25519, pos_integer()) :: binary()
  def generate(type, bits \\ 2048)

  def generate(:rsa, bits) when bits >= 1024,
    do: pem(:public_key.generate_key({:rsa, bits, 65_537}))

  def generate(:ed25519, _bits), do: pem(:public_key.generate_key({:namedCurve, :ed25519}))

  defp pem(key), do: :public_key.pem_encode([:public_key.pem_entry_encode(:PrivateKeyInfo, key)])

  @doc "The DNS name the key record goes at."
  @spec dns_name(t()) :: String.t()
  def dns_name(key), do: "#{key.selector}._domainkey.#{key.domain}"

  @doc "The key record (RFC 6376 §3.6.1) to publish at `dns_name/1`."
  @spec dns_record(t()) :: String.t()
  def dns_record(%__MODULE__{algorithm: :rsa_sha256, public: public}) do
    {:SubjectPublicKeyInfo, der, _} = :public_key.pem_entry_encode(:SubjectPublicKeyInfo, public)
    "v=DKIM1; k=rsa; p=" <> Base.encode64(der)
  end

  def dns_record(%__MODULE__{algorithm: :ed25519_sha256, public: public}),
    do: "v=DKIM1; k=ed25519; p=" <> Base.encode64(public)

  @doc "The `a=` tag value."
  @spec algorithm_name(t()) :: String.t()
  def algorithm_name(%__MODULE__{algorithm: :rsa_sha256}), do: "rsa-sha256"
  def algorithm_name(%__MODULE__{algorithm: :ed25519_sha256}), do: "ed25519-sha256"

  @doc "Signs `data`. For Ed25519 the SHA-256 hash of the data is signed (RFC 8463 §3)."
  @spec sign(t(), iodata()) :: binary()
  def sign(%__MODULE__{algorithm: :rsa_sha256, private: private}, data),
    do: :public_key.sign(IO.iodata_to_binary(data), :sha256, private)

  def sign(%__MODULE__{algorithm: :ed25519_sha256, private: private}, data),
    do: :crypto.sign(:eddsa, :none, :crypto.hash(:sha256, data), [private, :ed25519])
end
