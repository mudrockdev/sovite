defmodule Sovite.DKIM.Verifier do
  @moduledoc """
  Verifies the `DKIM-Signature:` fields of a message whose body is
  hashed as it streams by (RFC 6376 §6).

      verifier = Sovite.DKIM.Verifier.new(fields)
      body = Sovite.DKIM.Body.new(Sovite.DKIM.Verifier.body_specs(verifier))
      body = Sovite.DKIM.Body.update(body, chunk)   # for each body chunk
      results = Sovite.DKIM.Verifier.finish(verifier, Sovite.DKIM.Body.finish(body), resolver)

  Results are in the order of the signatures in the header, top first.
  """

  alias Sovite.DKIM.{Body, Canon, Key, Result, Signature, Tags}

  @enforce_keys [:fields, :signatures]
  defstruct [:fields, :signatures]

  @type t :: %__MODULE__{
          fields: [Sovite.Message.Headers.field()],
          signatures: [{:ok, Signature.t()} | {:error, String.t(), String.t()}]
        }

  @doc """
  Reads the signatures of header `fields`.

  ## Options

    * `:max_signatures` - signatures beyond this many are ignored, so a
      message cannot make the verifier do unbounded work. Defaults to 10.
    * `:now` - Unix seconds, for expired signatures. Defaults to now.
  """
  @spec new([Sovite.Message.Headers.field()], keyword()) :: t()
  def new(fields, opts \\ []) do
    signatures =
      fields
      |> Enum.filter(&match?({"dkim-signature", _}, &1))
      |> Enum.take(Keyword.get(opts, :max_signatures, 10))
      |> Enum.map(fn {_name, raw} ->
        case Signature.parse(raw, Keyword.take(opts, [:now])) do
          {:ok, signature} -> {:ok, signature}
          {:error, reason} -> {:error, raw, reason}
        end
      end)

    %__MODULE__{fields: fields, signatures: signatures}
  end

  @doc "The body hashes the signatures need."
  @spec body_specs(t()) :: [Body.spec()]
  def body_specs(%__MODULE__{signatures: signatures}) do
    for {:ok, %Signature{algorithm: algorithm} = signature} <- signatures,
        algorithm != :rsa_sha1,
        uniq: true,
        do: body_spec(signature)
  end

  @doc false
  @spec body_spec(Signature.t()) :: Body.spec()
  def body_spec(signature), do: {signature.body_canon, :sha256, signature.length}

  @doc "Checks each signature, looking up keys with `resolver`."
  @spec finish(t(), %{Body.spec() => {binary(), non_neg_integer()}}, Sovite.DNS.resolver()) ::
          [Result.t()]
  def finish(%__MODULE__{} = verifier, hashes, resolver) do
    results =
      Enum.map(verifier.signatures, fn
        {:ok, signature} -> check(signature, verifier.fields, hashes, resolver)
        {:error, raw, reason} -> unusable(raw, reason)
      end)

    :telemetry.execute([:sovite, :dkim, :verify], %{count: length(results)}, %{results: results})
    results
  end

  defp check(signature, fields, hashes, resolver) do
    result = %Result{
      domain: signature.domain,
      selector: signature.selector,
      identity: signature.identity,
      algorithm: algorithm_name(signature.algorithm),
      b: b_prefix(Base.encode64(signature.signature))
    }

    case verify(signature, fields, hashes, resolver) do
      :pass -> %{result | result: :pass}
      {status, reason} -> %{result | result: status, reason: reason}
    end
  end

  @doc false
  # Checks one parsed signature (also used for ARC-Message-Signature).
  @spec verify(Signature.t(), list(), map(), Sovite.DNS.resolver()) ::
          :pass | {:fail | :permerror | :temperror, String.t()}
  def verify(%Signature{algorithm: :rsa_sha1}, _fields, _hashes, _resolver),
    do: {:permerror, "rsa-sha1 is not accepted (RFC 8301)"}

  def verify(signature, fields, hashes, resolver) do
    with :ok <- body_hash(signature, hashes),
         {:ok, key} <- key(signature, resolver) do
      data =
        Canon.signed_data(
          Canon.select(fields, signature.headers),
          signature.raw,
          signature.header_canon
        )

      if Key.verify(key, signature.algorithm, data, signature.signature),
        do: :pass,
        else: {:fail, "signature did not verify"}
    end
  end

  defp body_hash(signature, hashes) do
    case Map.fetch(hashes, body_spec(signature)) do
      {:ok, {_hash, length}} when signature.length != nil and signature.length > length ->
        {:permerror, "l= is longer than the body"}

      {:ok, {hash, _length}} ->
        if hash == signature.body_hash, do: :ok, else: {:fail, "body hash did not verify"}

      :error ->
        {:permerror, "body was not hashed"}
    end
  end

  defp key(signature, resolver) do
    case Key.fetch(resolver, signature.selector, signature.domain) do
      {:ok, key} ->
        cond do
          key_type(signature.algorithm) != key.type ->
            {:permerror, "key type does not match the algorithm"}

          key.strict and identity_domain(signature) != signature.domain ->
            {:permerror, "key requires i= to be in d= exactly"}

          true ->
            {:ok, key}
        end

      {:error, {status, reason}} ->
        {status, reason}
    end
  end

  defp key_type(:rsa_sha256), do: :rsa
  defp key_type(:ed25519_sha256), do: :ed25519

  defp identity_domain(%Signature{identity: nil, domain: domain}), do: domain

  defp identity_domain(%Signature{identity: identity}),
    do: identity |> String.split("@") |> List.last() |> String.downcase(:ascii)

  # A signature that cannot be parsed: report what can be read of it.
  defp unusable(raw, reason) do
    [_name, value] = :binary.split(raw, ":")

    tags =
      case Tags.parse(value) do
        {:ok, tags} -> tags
        :error -> %{}
      end

    %Result{
      result: :permerror,
      domain: tags["d"] && String.downcase(tags["d"], :ascii),
      selector: tags["s"],
      identity: tags["i"],
      algorithm: tags["a"],
      b: tags["b"] && b_prefix(Tags.strip_whitespace(tags["b"])),
      reason: reason
    }
  end

  defp algorithm_name(:rsa_sha256), do: "rsa-sha256"
  defp algorithm_name(:ed25519_sha256), do: "ed25519-sha256"
  defp algorithm_name(:rsa_sha1), do: "rsa-sha1"

  # header.b (RFC 6008): enough of the signature to tell it apart.
  defp b_prefix(""), do: nil
  defp b_prefix(encoded), do: binary_part(encoded, 0, min(8, byte_size(encoded)))
end
