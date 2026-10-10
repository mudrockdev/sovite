defmodule Sovite.DKIM.Key do
  @moduledoc """
  DKIM public keys: the key records published at
  `<selector>._domainkey.<domain>` (RFC 6376 §3.6.1), and the signature
  algorithms that use them.

  RSA keys shorter than 1024 bits are refused (RFC 8301 §3.2). Ed25519
  keys are the raw 32 bytes (RFC 8463 §4.2).
  """

  alias Sovite.DKIM.Tags
  alias Sovite.DNS

  @min_rsa_bits 1024

  @enforce_keys [:type, :key]
  defstruct [:type, :key, bits: nil, strict: false]

  @typedoc """
  A public key. `key` is an `RSAPublicKey` record or the raw Ed25519
  key; `strict` is `t=s`: the `i=` domain must equal `d=`.
  """
  @type t :: %__MODULE__{
          type: :rsa | :ed25519,
          key: tuple() | binary(),
          bits: pos_integer() | nil,
          strict: boolean()
        }

  @typedoc "Why no key could be used: permanent, or a DNS failure."
  @type error :: {:permerror, String.t()} | {:temperror, String.t()}

  @doc """
  Looks up the key for `selector` and `domain`. When several records
  are published, the first usable one counts.
  """
  @spec fetch(DNS.resolver(), String.t(), String.t()) :: {:ok, t()} | {:error, error()}
  def fetch(resolver, selector, domain) do
    name = selector <> "._domainkey." <> domain

    case DNS.lookup(resolver, name, :txt) do
      {:ok, []} ->
        {:error, {:permerror, "no key for #{name}"}}

      {:ok, records} ->
        parsed = Enum.map(records, &parse/1)

        case Enum.find(parsed, &match?({:ok, _}, &1)) || hd(parsed) do
          {:ok, key} -> {:ok, key}
          {:error, reason} -> {:error, {:permerror, reason}}
        end

      {:error, :nxdomain} ->
        {:error, {:permerror, "no key for #{name}"}}

      {:error, reason} ->
        {:error, {:temperror, "key lookup for #{name} failed: #{reason}"}}
    end
  end

  @doc """
  Parses a key record.

      iex> {:ok, key} = Sovite.DKIM.Key.parse("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
      iex> key.type
      :ed25519
  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, String.t()}
  def parse(record) do
    with {:ok, tags} <- tags(record),
         :ok <- version(record, tags),
         :ok <- hashes(tags["h"]),
         :ok <- service(tags["s"]),
         {:ok, type} <- type(Map.get(tags, "k", "rsa")),
         {:ok, data} <- public_data(tags["p"]),
         {:ok, key, bits} <- decode(type, data) do
      flags = (tags["t"] || "") |> String.split(":") |> Enum.map(&Tags.trim/1)
      {:ok, %__MODULE__{type: type, key: key, bits: bits, strict: "s" in flags}}
    end
  end

  defp tags(record) do
    case Tags.parse(record) do
      {:ok, tags} -> {:ok, tags}
      :error -> {:error, "malformed key record"}
    end
  end

  # v= is optional, but must come first when present.
  defp version(record, %{"v" => "DKIM1"}) do
    if record |> Tags.trim() |> String.starts_with?("v="),
      do: :ok,
      else: {:error, "v= is not the first tag"}
  end

  defp version(_record, %{"v" => _}), do: {:error, "unsupported key version"}
  defp version(_record, _tags), do: :ok

  defp hashes(nil), do: :ok

  defp hashes(value) do
    if "sha256" in Enum.map(String.split(value, ":"), &Tags.trim/1),
      do: :ok,
      else: {:error, "key does not allow sha256"}
  end

  defp service(nil), do: :ok

  defp service(value) do
    services = Enum.map(String.split(value, ":"), &Tags.trim/1)
    if "*" in services or "email" in services, do: :ok, else: {:error, "key is not for email"}
  end

  defp type("rsa"), do: {:ok, :rsa}
  defp type("ed25519"), do: {:ok, :ed25519}
  defp type(other), do: {:error, "unknown key type #{other}"}

  defp public_data(nil), do: {:error, "key record has no p= tag"}

  defp public_data(value) do
    case Tags.strip_whitespace(value) do
      "" ->
        {:error, "key revoked"}

      data ->
        case Base.decode64(data) do
          {:ok, data} -> {:ok, data}
          :error -> {:error, "malformed p= tag"}
        end
    end
  end

  defp decode(:ed25519, <<key::binary-32>>), do: {:ok, key, 256}
  defp decode(:ed25519, _data), do: {:error, "malformed ed25519 key"}

  # Usually a SubjectPublicKeyInfo; some publish the bare RSAPublicKey.
  defp decode(:rsa, der) do
    key =
      try do
        case :public_key.der_decode(:SubjectPublicKeyInfo, der) do
          {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, {1, 2, 840, 113_549, 1, 1, 1}, _}, bits} ->
            :public_key.der_decode(:RSAPublicKey, bits)

          _other ->
            nil
        end
      rescue
        _ -> rsa_public_key(der)
      end

    case key do
      {:RSAPublicKey, modulus, _exponent} = key ->
        bits = modulus |> :binary.encode_unsigned() |> bit_size()

        if bits >= @min_rsa_bits,
          do: {:ok, key, bits},
          else: {:error, "RSA key of #{bits} bits is too short"}

      _ ->
        {:error, "malformed RSA key"}
    end
  end

  defp rsa_public_key(der) do
    :public_key.der_decode(:RSAPublicKey, der)
  rescue
    _ -> nil
  end

  @doc """
  Checks `signature` over `data` with `key`, for `algorithm`. For
  Ed25519 the SHA-256 hash of the data is what is signed (RFC 8463 §3).
  """
  @spec verify(t(), Sovite.DKIM.Signature.algorithm(), iodata(), binary()) :: boolean()
  def verify(%__MODULE__{type: :rsa, key: key}, :rsa_sha256, data, signature),
    do: :public_key.verify(IO.iodata_to_binary(data), :sha256, signature, key)

  def verify(%__MODULE__{type: :ed25519, key: key}, :ed25519_sha256, data, signature) do
    :crypto.verify(:eddsa, :none, :crypto.hash(:sha256, data), signature, [key, :ed25519])
  rescue
    ErlangError -> false
  end

  def verify(_key, _algorithm, _data, _signature), do: false
end
