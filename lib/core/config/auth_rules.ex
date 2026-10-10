defmodule Sovite.Core.Config.AuthRules do
  @moduledoc false
  # Defaults, key loading, and cross-key checks for [spf], [dkim], [arc],
  # [dmarc], and [srs].

  alias Sovite.Core.Config.Error
  alias Sovite.DKIM.SigningKey

  # Shorter secrets are too easy to guess from SRS addresses.
  @min_secret 16

  @spec defaults(map()) :: map()
  def defaults(values) do
    hostname = values.server.hostname

    values
    |> update_in([:server, :authserv_id], &(&1 || hostname))
    |> update_in([:srs, :domain], &(&1 || hostname))
    |> update_in([:dmarc, :report_org], &(&1 || hostname))
    |> update_in([:dmarc, :report_from], &(&1 || "postmaster@" <> hostname))
  end

  # Reads every [[dkim.key]] file, so a broken key is a config error
  # rather than a surprise at the first message.
  @spec load_keys(map()) :: {map(), [Error.t()]}
  def load_keys(values) do
    {keys, errors} =
      values.dkim.key
      |> Enum.with_index()
      |> Enum.map_reduce([], fn {key, index}, errors ->
        case load(key) do
          {:ok, signing_key} ->
            {Map.put(key, :signing_key, signing_key), errors}

          {:error, reason} ->
            error = %Error{path: ["dkim", "key", "[#{index}]", "file"], reason: reason}
            {Map.put(key, :signing_key, nil), [error | errors]}
        end
      end)

    {put_in(values.dkim.key, keys), Enum.reverse(errors)}
  end

  defp load(key) do
    case File.read(key.file) do
      {:ok, pem} -> SigningKey.from_pem(pem, key.domain, key.selector)
      {:error, reason} -> {:error, "cannot read #{key.file}: #{:file.format_error(reason)}"}
    end
  end

  @spec errors(map()) :: [Error.t()]
  def errors(values) do
    duplicate_key_errors(values.dkim.key) ++ arc_errors(values) ++ srs_errors(values.srs)
  end

  defp duplicate_key_errors(keys) do
    keys
    |> Enum.with_index()
    |> Enum.group_by(fn {key, _} -> {key.domain, String.downcase(key.selector)} end)
    |> Enum.flat_map(fn
      {_, [_]} ->
        []

      {{domain, selector}, [_ | duplicates]} ->
        for {_, index} <- duplicates,
            do: %Error{
              path: ["dkim", "key", "[#{index}]"],
              reason: "selector #{selector} of #{domain} is already defined"
            }
    end)
  end

  defp arc_errors(%{arc: %{seal: false}}), do: []

  defp arc_errors(%{arc: arc, dkim: dkim}) do
    if Enum.any?(dkim.key, &(&1.domain == arc.domain and &1.selector == arc.selector)),
      do: [],
      else: [
        %Error{
          path: ["arc", "seal"],
          reason: "needs arc.domain and arc.selector to name a [[dkim.key]]"
        }
      ]
  end

  defp srs_errors(%{enabled: false}), do: []

  defp srs_errors(%{secrets: []}),
    do: [%Error{path: ["srs", "secrets"], reason: "is required when SRS is enabled"}]

  defp srs_errors(%{secrets: secrets}) do
    for {secret, index} <- Enum.with_index(secrets),
        byte_size(secret) < @min_secret,
        do: %Error{
          path: ["srs", "secrets", "[#{index}]"],
          reason: "must be at least #{@min_secret} characters"
        }
  end
end
