defmodule Sovite.Core.Repo.Tables.AddressRewrites do
  @moduledoc """
  Address rewrites stored in Sovite's database, managed with `sovitectl
  rewrite` (see `Sovite.Core.Rewrite`).

  As a `Sovite.Core.Lookup` table, the handle names the kind of rewrite
  to find (`:sender`, `:recipient`, or `:both`) and a lookup returns the
  replacement.
  """

  @behaviour Sovite.Core.Lookup

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Data
  alias Sovite.Core.Repo.Schemas.AddressRewrite

  @doc "Sets the rewrite of `kind` for `pattern`, replacing any earlier one."
  @spec set(Repo.t(), atom() | String.t(), String.t(), String.t()) ::
          {:ok, AddressRewrite.t()} | {:error, Ecto.Changeset.t()}
  def set(repo, kind, pattern, replacement) do
    attrs = %{kind: kind, pattern: pattern, replacement: replacement}

    with {:ok, rewrite} <-
           Ecto.Changeset.apply_action(
             AddressRewrite.changeset(%AddressRewrite{}, attrs),
             :insert
           ) do
      Data.upsert(
        repo,
        AddressRewrite,
        [kind: rewrite.kind, pattern: rewrite.pattern],
        &AddressRewrite.changeset(&1, attrs)
      )
    end
  end

  @doc "Deletes the rewrite of `kind` for `pattern`."
  @spec delete(Repo.t(), atom(), String.t()) :: :ok | {:error, :not_found}
  def delete(repo, kind, pattern) do
    Data.delete(
      repo,
      from(r in AddressRewrite, where: r.kind == ^kind and r.pattern == ^Data.fold(pattern))
    )
  end

  @doc "Lists all rewrites, by kind and pattern."
  @spec list(Repo.t()) :: [AddressRewrite.t()]
  def list(repo),
    do: Repo.run(repo, & &1.all(from(r in AddressRewrite, order_by: [r.kind, r.pattern])))

  @impl Sovite.Core.Lookup
  def lookup(%{repo: repo, kind: kind}, key) do
    query =
      from(r in AddressRewrite,
        where: r.kind == ^kind and r.pattern == ^Data.fold(key),
        select: r.replacement
      )

    Data.lookup(repo, & &1.one(query))
  end
end
