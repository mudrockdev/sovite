defmodule Sovite.ARC do
  @moduledoc """
  Authenticated Received Chain (RFC 8617): verifying the chain of ARC
  sets a message carries, and sealing it with one more, so the
  authentication results of earlier hops survive forwarding and mailing
  lists.

      verifier = Sovite.ARC.new(fields)
      body = Sovite.DKIM.Body.new(Sovite.ARC.body_specs(verifier))
      ...
      %Sovite.ARC.Result{cv: :pass} = Sovite.ARC.finish(verifier, hashes, resolver)

      Sovite.ARC.seal(fields, body_hash, result, auth_results, key)
      #=> [arc_authentication_results, arc_message_signature, arc_seal]

  An ARC set is three fields with the same instance `i=`:
  `ARC-Authentication-Results:` (the results the sealer saw),
  `ARC-Message-Signature:` (a DKIM-like signature of the message), and
  `ARC-Seal:` (a signature over all ARC sets so far).

  Header fields are as returned by `Sovite.Message.Headers.parse/1`; keys
  are `Sovite.DKIM.SigningKey`s. Body hashes come from
  `Sovite.DKIM.Body`.
  """

  alias Sovite.DKIM
  alias Sovite.DKIM.{Body, Canon, Key, Signature, SigningKey, Tags, Verifier}

  @max_instances 50

  @typedoc "The chain validation status (`cv=`)."
  @type cv :: :none | :pass | :fail

  defmodule Result do
    @moduledoc """
    The chain validation result. `instance` is the highest instance
    (0 without a chain), `sealers` the `d=` of each `ARC-Seal:`, oldest
    first.
    """

    defstruct cv: :none, instance: 0, sealers: [], reason: nil

    @type t :: %__MODULE__{
            cv: Sovite.ARC.cv(),
            instance: non_neg_integer(),
            sealers: [String.t()],
            reason: String.t() | nil
          }
  end

  @enforce_keys [:fields, :sets, :problem]
  defstruct [:fields, :sets, :problem, :signature]

  @opaque t :: %__MODULE__{}

  @doc """
  Reads the ARC sets of header `fields` and checks their structure.

  ## Options

    * `:now` - Unix seconds, for expired signatures. Defaults to now.
  """
  @spec new([Sovite.Message.Headers.field()], keyword()) :: t()
  def new(fields, opts \\ []) do
    case collect(fields) do
      {:ok, []} ->
        %__MODULE__{fields: fields, sets: [], problem: nil}

      {:ok, sets} ->
        %{ams: ams} = List.last(sets)

        {problem, signature} =
          with nil <- structure_problem(sets),
               {:ok, signature} <-
                 Signature.parse(ams, Keyword.put(Keyword.take(opts, [:now]), :kind, :arc)) do
            {nil, signature}
          else
            {:error, reason} -> {"ARC-Message-Signature: " <> reason, nil}
            reason -> {reason, nil}
          end

        %__MODULE__{fields: fields, sets: sets, problem: problem, signature: signature}

      {:error, reason} ->
        %__MODULE__{fields: fields, sets: [], problem: reason}
    end
  end

  # The sets by instance, oldest first. Each instance must have exactly
  # one of each field, and the instances must be 1..N.
  defp collect(fields) do
    entries =
      for {name, raw} <- fields,
          name in ~w(arc-seal arc-message-signature arc-authentication-results) do
        {kind(name), instance(name, raw), raw}
      end

    grouped = Enum.group_by(entries, &elem(&1, 1))
    count = map_size(grouped)

    cond do
      entries == [] ->
        {:ok, []}

      Map.has_key?(grouped, :error) ->
        {:error, "an ARC field has no valid instance"}

      count > @max_instances or Enum.sort(Map.keys(grouped)) != Enum.to_list(1..count) ->
        {:error, "ARC instances are not 1..N"}

      true ->
        sets(grouped, count)
    end
  end

  defp sets(grouped, count) do
    Enum.reduce_while(1..count, {:ok, []}, fn i, {:ok, acc} ->
      case set(i, grouped[i]) do
        {:ok, set} -> {:cont, {:ok, acc ++ [set]}}
        error -> {:halt, error}
      end
    end)
  end

  defp set(i, entries) do
    case Enum.sort(Enum.map(entries, &{elem(&1, 0), elem(&1, 2)})) do
      [{:aar, aar}, {:ams, ams}, {:as, as}] -> {:ok, %{instance: i, aar: aar, ams: ams, as: as}}
      _ -> {:error, "ARC set #{i} is incomplete or has duplicates"}
    end
  end

  defp kind("arc-seal"), do: :as
  defp kind("arc-message-signature"), do: :ams
  defp kind("arc-authentication-results"), do: :aar

  defp instance(name, raw) do
    [_name, value] = :binary.split(raw, ":")

    text =
      case name do
        # i= is the first part of an ARC-Authentication-Results value.
        "arc-authentication-results" -> value |> String.split(";") |> hd()
        _ -> value
      end

    with {:ok, tags} <- Tags.parse(text),
         {i, ""} when i in 1..@max_instances <- Integer.parse(tags["i"] || "") do
      i
    else
      _ -> :error
    end
  end

  defp structure_problem(sets) do
    Enum.find_value(sets, fn %{instance: i, as: as} ->
      case {i, seal_tags(as)} do
        {_, {:ok, %{cv: :fail}}} -> nil
        {1, {:ok, %{cv: :none}}} -> nil
        {i, {:ok, %{cv: :pass}}} when i > 1 -> nil
        {_, {:ok, %{cv: cv}}} -> "ARC-Seal #{i} has cv=#{cv}"
        {_, {:error, reason}} -> "ARC-Seal #{i}: #{reason}"
      end
    end)
  end

  defp seal_tags(raw) do
    [_name, value] = :binary.split(raw, ":")

    with {:ok, tags} <- tags(value),
         {:ok, cv} <- cv(tags["cv"]),
         {:ok, algorithm} <- algorithm(tags["a"]),
         {:ok, signature} <- decode64(tags["b"]),
         {:ok, domain, selector} <- signer(tags) do
      {:ok,
       %{cv: cv, algorithm: algorithm, signature: signature, domain: domain, selector: selector}}
    end
  end

  defp signer(%{"d" => domain, "s" => selector}) when domain != "" and selector != "",
    do: {:ok, String.downcase(domain, :ascii), selector}

  defp signer(_tags), do: {:error, "missing d= or s= tag"}

  defp tags(value) do
    case Tags.parse(value) do
      {:ok, tags} -> {:ok, tags}
      :error -> {:error, "malformed tag list"}
    end
  end

  # Fixed tables: never create atoms from message data.
  defp cv("none"), do: {:ok, :none}
  defp cv("pass"), do: {:ok, :pass}
  defp cv("fail"), do: {:ok, :fail}
  defp cv(_other), do: {:error, "malformed cv= tag"}

  defp algorithm("rsa-sha256"), do: {:ok, :rsa_sha256}
  defp algorithm("ed25519-sha256"), do: {:ok, :ed25519_sha256}
  defp algorithm(_other), do: {:error, "unsupported algorithm"}

  defp decode64(nil), do: {:error, "missing b="}

  defp decode64(value) do
    case Base.decode64(Tags.strip_whitespace(value)) do
      {:ok, data} -> {:ok, data}
      :error -> {:error, "malformed b= tag"}
    end
  end

  @doc "The body hashes the newest `ARC-Message-Signature:` needs."
  @spec body_specs(t()) :: [Body.spec()]
  def body_specs(%__MODULE__{signature: nil}), do: []
  def body_specs(%__MODULE__{signature: signature}), do: [Verifier.body_spec(signature)]

  @doc """
  Validates the chain (RFC 8617 §5.2): the newest message signature and
  every seal must verify.
  """
  @spec finish(t(), %{Body.spec() => {binary(), non_neg_integer()}}, Sovite.DNS.resolver()) ::
          Result.t()
  def finish(%__MODULE__{sets: [], problem: nil}, _hashes, _resolver), do: %Result{}

  def finish(%__MODULE__{} = verifier, hashes, resolver) do
    sets = verifier.sets
    sealers = Enum.map(sets, &seal_domain/1)
    result = %Result{instance: length(sets), sealers: sealers}

    case chain_problem(verifier, hashes, resolver) do
      nil -> %{result | cv: :pass}
      reason -> %{result | cv: :fail, reason: reason}
    end
  end

  defp seal_domain(%{as: as}) do
    case seal_tags(as) do
      {:ok, %{domain: domain}} -> domain
      {:error, _} -> nil
    end
  end

  defp chain_problem(%__MODULE__{problem: problem}, _hashes, _resolver) when problem != nil,
    do: problem

  defp chain_problem(verifier, hashes, resolver) do
    sets = verifier.sets

    with :pass <- newest_cv(sets),
         :pass <- message_signature(verifier, hashes, resolver) do
      sets |> Enum.reverse() |> Enum.find_value(&seal_problem(sets, &1, resolver))
    else
      {_status, reason} -> reason
    end
  end

  defp seal_problem(sets, set, resolver) do
    case seal(sets, set, resolver) do
      :pass -> nil
      {_status, reason} -> "ARC-Seal #{set.instance}: #{reason}"
    end
  end

  defp newest_cv(sets) do
    case seal_tags(List.last(sets).as) do
      {:ok, %{cv: :fail}} -> {:fail, "the chain was already broken"}
      _ -> :pass
    end
  end

  defp message_signature(verifier, hashes, resolver) do
    case Verifier.verify(verifier.signature, verifier.fields, hashes, resolver) do
      :pass -> :pass
      {status, reason} -> {status, "ARC-Message-Signature #{length(verifier.sets)}: #{reason}"}
    end
  end

  defp seal(sets, set, resolver) do
    {:ok, seal} = seal_tags(set.as)
    selected = seal_input(Enum.take(sets, set.instance - 1)) ++ [set.aar, set.ams]
    data = Canon.signed_data(selected, set.as, :relaxed)

    case Key.fetch(resolver, seal.selector, seal.domain) do
      {:ok, key} ->
        if Key.verify(key, seal.algorithm, data, seal.signature),
          do: :pass,
          else: {:fail, "signature did not verify"}

      {:error, {status, reason}} ->
        {status, reason}
    end
  end

  defp seal_input(sets), do: Enum.flat_map(sets, &[&1.aar, &1.ams, &1.as])

  @doc """
  Adds an ARC set to a message (RFC 8617 §5.1), recording `result`, the
  chain status `finish/3` returned, and `auth_results`, the
  `Authentication-Results:` value this server computed (from
  `Sovite.AuthResults.value/2`, authserv-id first).

  Returns the three fields to put at the top of the message, or `[]`
  when the chain must not be sealed: it already failed, or is at the
  limit of 50 instances. `body_hash` is for `Sovite.DKIM.body_spec/0`.

  ## Options

    * `:headers` - names of the fields the message signature covers when
      present. Defaults to `Sovite.DKIM.default_headers/0` and
      `DKIM-Signature`.
    * `:timestamp` - Unix seconds for `t=`. Defaults to now.
  """
  @spec seal(
          [Sovite.Message.Headers.field()],
          binary(),
          Result.t(),
          String.t(),
          SigningKey.t(),
          keyword()
        ) ::
          [String.t()]
  def seal(fields, body_hash, %Result{} = result, auth_results, %SigningKey{} = key, opts \\ []) do
    sets =
      case collect(fields) do
        {:ok, sets} -> sets
        {:error, _} -> nil
      end

    cond do
      sets == nil or result.instance >= @max_instances -> []
      sets != [] and newest_cv(sets) != :pass -> []
      true -> new_set(fields, sets, body_hash, result, auth_results, key, opts)
    end
  end

  defp new_set(fields, sets, body_hash, result, auth_results, key, opts) do
    i = result.instance + 1
    timestamp = Keyword.get_lazy(opts, :timestamp, fn -> System.os_time(:second) end)
    cv = if result.instance == 0, do: "none", else: Atom.to_string(result.cv)

    aar = "ARC-Authentication-Results: i=#{i}; " <> auth_results <> "\r\n"

    headers = Keyword.get(opts, :headers, DKIM.default_headers() ++ ["dkim-signature"])
    wanted = MapSet.new(headers, &String.downcase/1)
    names = for {name, _raw} <- fields, name != nil, MapSet.member?(wanted, name), do: name

    ams =
      DKIM.signed_field(
        "ARC-Message-Signature",
        [
          "i=#{i}",
          "a=" <> SigningKey.algorithm_name(key),
          "c=relaxed/relaxed",
          "d=" <> key.domain,
          "s=" <> key.selector,
          "t=#{timestamp}",
          "h=" <> Enum.join(names, ":"),
          "bh=" <> Base.encode64(body_hash)
        ],
        Canon.select(fields, names),
        key
      )

    seal =
      DKIM.signed_field(
        "ARC-Seal",
        [
          "i=#{i}",
          "a=" <> SigningKey.algorithm_name(key),
          "t=#{timestamp}",
          "cv=" <> cv,
          "d=" <> key.domain,
          "s=" <> key.selector
        ],
        seal_input(Enum.take(sets, result.instance)) ++ [aar, ams],
        key
      )

    [aar, ams, seal]
  end
end
