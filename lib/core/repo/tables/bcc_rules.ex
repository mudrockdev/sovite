defmodule Sovite.Core.Repo.Tables.BccRules do
  @moduledoc """
  BCC rules stored in Sovite's database, managed with `sovitectl bcc`
  (see `Sovite.Core.Recipients.bcc/3`).

  As a `Sovite.Core.Lookup` table, the handle names the kind (`:sender`
  or `:recipient`) and a lookup returns every copy address for a
  pattern, joined with `", "`.
  """

  @behaviour Sovite.Core.Lookup

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Data
  alias Sovite.Core.Repo.Schemas.BccRule

  @doc "Adds a rule: mail of `kind` matching `pattern` is also sent to `address`."
  @spec add(Repo.t(), atom() | String.t(), String.t(), String.t()) ::
          {:ok, BccRule.t()} | {:error, Ecto.Changeset.t()}
  def add(repo, kind, pattern, address) do
    Repo.run(repo, fn module ->
      %BccRule{}
      |> BccRule.changeset(%{kind: kind, pattern: pattern, address: address})
      |> module.insert()
    end)
  end

  @doc "Deletes a rule."
  @spec delete(Repo.t(), atom(), String.t(), String.t()) :: :ok | {:error, :not_found}
  def delete(repo, kind, pattern, address) do
    Data.delete(
      repo,
      from(r in BccRule,
        where:
          r.kind == ^kind and r.pattern == ^Data.fold(pattern) and
            r.address == ^String.trim(address)
      )
    )
  end

  @doc "Lists all rules, by kind and pattern."
  @spec list(Repo.t()) :: [BccRule.t()]
  def list(repo),
    do: Repo.run(repo, & &1.all(from(r in BccRule, order_by: [r.kind, r.pattern, r.address])))

  @impl Sovite.Core.Lookup
  def lookup(%{repo: repo, kind: kind}, key) do
    query =
      from(r in BccRule,
        where: r.kind == ^kind and r.pattern == ^Data.fold(key),
        order_by: r.id,
        select: r.address
      )

    Data.lookup(repo, fn module ->
      case module.all(query) do
        [] -> nil
        addresses -> Enum.join(addresses, ", ")
      end
    end)
  end
end
