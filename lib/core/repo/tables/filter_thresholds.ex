defmodule Sovite.Core.Repo.Tables.FilterThresholds do
  @moduledoc """
  Filter thresholds for addresses and domains, managed with `sovitectl
  filter threshold` (see `Sovite.Core.Filter.Actions`).
  """

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Data
  alias Sovite.Core.Repo.Schemas.FilterThreshold

  @doc "Sets the threshold of `action` for `pattern` (an address or `@domain`); `nil` turns it off."
  @spec set(Repo.t(), String.t(), atom(), float() | nil) ::
          {:ok, FilterThreshold.t()} | {:error, Ecto.Changeset.t()}
  def set(repo, pattern, action, score) do
    Data.upsert(
      repo,
      FilterThreshold,
      [pattern: Data.fold(pattern), action: action],
      &FilterThreshold.changeset(&1, %{pattern: pattern, action: action, score: score})
    )
  end

  @doc "Deletes the threshold of `action` for `pattern`, or all of its thresholds with `nil`."
  @spec delete(Repo.t(), String.t(), atom() | nil) :: :ok | {:error, :not_found}
  def delete(repo, pattern, nil),
    do: Data.delete(repo, from(t in FilterThreshold, where: t.pattern == ^Data.fold(pattern)))

  def delete(repo, pattern, action) do
    Data.delete(
      repo,
      from(t in FilterThreshold, where: t.pattern == ^Data.fold(pattern) and t.action == ^action)
    )
  end

  @doc "Lists all thresholds, by pattern and action."
  @spec list(Repo.t()) :: [FilterThreshold.t()]
  def list(repo),
    do: Repo.run(repo, & &1.all(from(t in FilterThreshold, order_by: [t.pattern, t.action])))

  @doc "The thresholds of `patterns` (folded), as `{pattern, action, score}`."
  @spec lookup(Repo.t(), [String.t()]) :: [{String.t(), atom(), float() | nil}]
  def lookup(repo, patterns) do
    patterns = Enum.map(patterns, &Data.fold/1)

    query =
      from(t in FilterThreshold,
        where: t.pattern in ^patterns,
        select: {t.pattern, t.action, t.score}
      )

    Repo.run(repo, & &1.all(query))
  end
end
