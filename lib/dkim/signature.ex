defmodule Sovite.DKIM.Signature do
  @moduledoc """
  A parsed `DKIM-Signature:` field (RFC 6376 §3.5), or the
  `ARC-Message-Signature:` field that uses the same tags (RFC 8617 §4.1.2).
  """

  alias Sovite.DKIM.Tags

  @typedoc """
  The signing algorithm. `:rsa_sha1` is parsed so it can be refused by
  name (RFC 8301 §3.1).
  """
  @type algorithm :: :rsa_sha256 | :ed25519_sha256 | :rsa_sha1

  @enforce_keys [:algorithm, :signature, :body_hash, :domain, :selector, :headers, :raw]
  defstruct [
    :algorithm,
    :signature,
    :body_hash,
    :domain,
    :selector,
    :headers,
    :identity,
    :length,
    :timestamp,
    :expiration,
    :instance,
    :raw,
    header_canon: :simple,
    body_canon: :simple
  ]

  @type t :: %__MODULE__{
          algorithm: algorithm(),
          signature: binary(),
          body_hash: binary(),
          domain: String.t(),
          selector: String.t(),
          headers: [String.t()],
          identity: String.t() | nil,
          length: non_neg_integer() | nil,
          timestamp: non_neg_integer() | nil,
          expiration: non_neg_integer() | nil,
          instance: pos_integer() | nil,
          raw: String.t(),
          header_canon: Sovite.DKIM.Canon.algorithm(),
          body_canon: Sovite.DKIM.Canon.algorithm()
        }

  @doc """
  Parses a raw `DKIM-Signature:` field (`kind: :dkim`, the default) or
  `ARC-Message-Signature:` field (`kind: :arc`). Returns a description of
  the problem for a field that cannot be used.

  The checks are those of RFC 6376 §6.1.1 that need no DNS: the
  required tags, the `i=` domain, `From` among the signed fields, and the
  expiration time against `:now` (Unix seconds).
  """
  @spec parse(String.t(), keyword()) :: {:ok, t()} | {:error, String.t()}
  def parse(raw, opts \\ []) do
    kind = Keyword.get(opts, :kind, :dkim)
    [_name, value] = :binary.split(raw, ":")

    with {:ok, tags} <- tags(value),
         :ok <- version(kind, tags),
         {:ok, required} <- required(tags, kind),
         {:ok, algorithm} <- algorithm(tags["a"]),
         {:ok, signature} <- base64(tags["b"], "b"),
         {:ok, body_hash} <- base64(tags["bh"], "bh"),
         {:ok, header_canon, body_canon} <- canonicalization(tags["c"]),
         {:ok, headers} <- signed_headers(kind, tags["h"]),
         {:ok, length} <- optional_integer(tags["l"], "l"),
         {:ok, timestamp} <- optional_integer(tags["t"], "t"),
         {:ok, expiration} <- optional_integer(tags["x"], "x"),
         {:ok, instance} <- instance(kind, tags["i"]),
         :ok <- query_method(tags["q"]),
         domain = String.downcase(required.d, :ascii),
         {:ok, identity} <- identity(kind, tags["i"], domain),
         :ok <- times(timestamp, expiration, Keyword.get_lazy(opts, :now, &now/0)) do
      {:ok,
       %__MODULE__{
         algorithm: algorithm,
         signature: signature,
         body_hash: body_hash,
         domain: domain,
         selector: required.s,
         headers: headers,
         identity: identity,
         length: length,
         timestamp: timestamp,
         expiration: expiration,
         instance: instance,
         raw: raw,
         header_canon: header_canon,
         body_canon: body_canon
       }}
    end
  end

  defp now, do: System.os_time(:second)

  defp tags(value) do
    case Tags.parse(value) do
      {:ok, tags} -> {:ok, tags}
      :error -> {:error, "malformed tag list"}
    end
  end

  defp version(:dkim, %{"v" => "1"}), do: :ok
  defp version(:dkim, %{"v" => _}), do: {:error, "unsupported version"}
  defp version(:dkim, _tags), do: {:error, "missing v= tag"}
  defp version(:arc, _tags), do: :ok

  defp required(tags, kind) do
    names = if kind == :arc, do: ~w(a b bh d h s i), else: ~w(a b bh d h s)

    case Enum.find(names, &(Map.get(tags, &1, "") == "" and &1 != "b")) do
      nil when is_map_key(tags, "b") -> {:ok, %{d: tags["d"], s: tags["s"]}}
      nil -> {:error, "missing b= tag"}
      name -> {:error, "missing #{name}= tag"}
    end
  end

  # Fixed table: never create atoms from message data.
  defp algorithm("rsa-sha256"), do: {:ok, :rsa_sha256}
  defp algorithm("ed25519-sha256"), do: {:ok, :ed25519_sha256}
  defp algorithm("rsa-sha1"), do: {:ok, :rsa_sha1}
  defp algorithm(other), do: {:error, "unknown algorithm #{other}"}

  defp base64(value, tag) do
    case Base.decode64(Tags.strip_whitespace(value)) do
      {:ok, data} -> {:ok, data}
      :error -> {:error, "malformed #{tag}= tag"}
    end
  end

  defp canonicalization(nil), do: {:ok, :simple, :simple}

  defp canonicalization(value) do
    case String.split(String.downcase(value, :ascii), "/") do
      [header] -> with {:ok, h} <- canon(header), do: {:ok, h, :simple}
      [header, body] -> with {:ok, h} <- canon(header), {:ok, b} <- canon(body), do: {:ok, h, b}
      _ -> {:error, "malformed c= tag"}
    end
  end

  defp canon("simple"), do: {:ok, :simple}
  defp canon("relaxed"), do: {:ok, :relaxed}
  defp canon(_other), do: {:error, "unknown canonicalization"}

  defp signed_headers(kind, value) do
    headers =
      value
      |> String.split(":")
      |> Enum.map(&(&1 |> Tags.trim() |> String.downcase(:ascii)))

    cond do
      Enum.any?(headers, &(&1 == "")) -> {:error, "malformed h= tag"}
      kind == :dkim and "from" not in headers -> {:error, "From is not signed"}
      kind == :arc and "arc-seal" in headers -> {:error, "ARC-Seal is signed"}
      true -> {:ok, headers}
    end
  end

  defp optional_integer(nil, _tag), do: {:ok, nil}

  defp optional_integer(value, tag) do
    if Regex.match?(~r/\A[0-9]{1,76}\z/, value),
      do: {:ok, String.to_integer(value)},
      else: {:error, "malformed #{tag}= tag"}
  end

  defp instance(:dkim, _value), do: {:ok, nil}

  defp instance(:arc, value) do
    case Integer.parse(value) do
      {i, ""} when i in 1..50 -> {:ok, i}
      _ -> {:error, "malformed i= tag"}
    end
  end

  defp query_method(nil), do: :ok

  defp query_method(value) do
    methods = value |> String.split(":") |> Enum.map(&String.downcase(Tags.trim(&1), :ascii))
    if "dns/txt" in methods, do: :ok, else: {:error, "unsupported query method"}
  end

  # The identity must be in the signing domain or one of its subdomains.
  defp identity(:arc, _value, _domain), do: {:ok, nil}
  defp identity(:dkim, nil, domain), do: {:ok, "@" <> domain}

  defp identity(:dkim, value, domain) do
    with [_local, id_domain] <- String.split(value, "@", parts: 2),
         id_domain = String.downcase(id_domain, :ascii),
         true <- id_domain == domain or String.ends_with?(id_domain, "." <> domain) do
      {:ok, value}
    else
      _ -> {:error, "i= is not in the signing domain"}
    end
  end

  defp times(timestamp, expiration, now) do
    cond do
      expiration != nil and timestamp != nil and expiration < timestamp ->
        {:error, "x= is before t="}

      expiration != nil and expiration < now ->
        {:error, "signature expired"}

      true ->
        :ok
    end
  end
end
