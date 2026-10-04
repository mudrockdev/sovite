defmodule Sovite.Core.Repo.Tables.AccessRules do
  @moduledoc """
  Access rules for the restriction chains, stored in Sovite's database
  and managed with `sovitectl access`.

  As a `Sovite.Core.Lookup` table, the handle names the kind of rule:
  `:client`, `:helo`, `:sender`, or `:recipient`.
  A lookup returns the action and its text, as an `access(5)` table
  would.
  """

  @behaviour Sovite.Core.Lookup

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Data
  alias Sovite.Core.Repo.Schemas.AccessRule

  @doc "Sets the rule for `kind` and `pattern`, replacing any earlier one."
  @spec set(Repo.t(), atom() | String.t(), String.t(), String.t(), String.t() | nil) ::
          {:ok, AccessRule.t()} | {:error, Ecto.Changeset.t()}
  def set(repo, kind, pattern, action, text \\ nil) do
    attrs = %{kind: kind, pattern: pattern, action: action, text: text}
    changeset = AccessRule.changeset(%AccessRule{}, attrs)

    case Ecto.Changeset.apply_action(changeset, :insert) do
      {:ok, rule} ->
        Data.upsert(
          repo,
          AccessRule,
          [kind: rule.kind, pattern: rule.pattern],
          &AccessRule.changeset(&1, attrs)
        )

      {:error, _changeset} = error ->
        error
    end
  end

  @doc "Deletes the rule for `kind` and `pattern`."
  @spec delete(Repo.t(), atom(), String.t()) :: :ok | {:error, :not_found}
  def delete(repo, kind, pattern) do
    Data.delete(
      repo,
      from(r in AccessRule, where: r.kind == ^kind and r.pattern == ^Data.fold(pattern))
    )
  end

  @doc "Lists all rules, by kind and pattern."
  @spec list(Repo.t()) :: [AccessRule.t()]
  def list(repo),
    do: Repo.run(repo, & &1.all(from(r in AccessRule, order_by: [r.kind, r.pattern])))

  @impl Sovite.Core.Lookup
  def lookup(%{repo: repo, kind: kind}, key) do
    query =
      from(r in AccessRule,
        where: r.kind == ^kind and r.pattern == ^Data.fold(key),
        select: {r.action, r.text}
      )

    Data.lookup(repo, fn module ->
      case module.one(query) do
        nil -> nil
        {action, nil} -> action
        {action, text} -> "#{action} #{text}"
      end
    end)
  end
end
