defmodule Sovite.Core.Repo.Tables.Aliases do
  @moduledoc """
  Aliases stored in Sovite's database, managed with `sovitectl alias`.

  As a `Sovite.Core.Lookup` table, a lookup returns the
  destinations of an enabled alias, joined with `", "`.
  """

  @behaviour Sovite.Core.Lookup

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Data
  alias Sovite.Core.Repo.Schemas.{Alias, AliasDestination}

  @doc """
  Adds destinations to the alias for `address`, creating the alias if
  needed. Returns the alias with its destinations.
  """
  @spec add(Repo.t(), String.t(), [String.t(), ...]) ::
          {:ok, Alias.t()} | {:error, Ecto.Changeset.t()}
  def add(repo, address, destinations) do
    Repo.run(repo, fn module ->
      module.transaction(fn ->
        entry = find_or_create(module, address)
        add_destinations(module, entry, destinations)
        module.preload(entry, :destinations, force: true)
      end)
    end)
  end

  defp find_or_create(module, address) do
    case module.get_by(Alias, address: Data.fold(address)) do
      nil -> %Alias{} |> Alias.changeset(%{address: address}) |> insert!(module)
      entry -> entry
    end
  end

  # Adds the destinations the alias does not have yet.
  defp add_destinations(module, entry, destinations) do
    existing =
      module.all(from(d in AliasDestination, where: d.alias_id == ^entry.id, select: d.address))

    for destination <- Enum.uniq(destinations), String.trim(destination) not in existing do
      %AliasDestination{alias_id: entry.id}
      |> AliasDestination.changeset(%{address: destination})
      |> insert!(module)
    end
  end

  defp insert!(changeset, module) do
    case module.insert(changeset) do
      {:ok, row} -> row
      {:error, changeset} -> module.rollback(changeset)
    end
  end

  @doc "Deletes the alias for `address` and its destinations."
  @spec delete(Repo.t(), String.t()) :: :ok | {:error, :not_found}
  def delete(repo, address),
    do: Data.delete(repo, from(a in Alias, where: a.address == ^Data.fold(address)))

  @doc "Removes one destination from the alias for `address`."
  @spec remove_destination(Repo.t(), String.t(), String.t()) :: :ok | {:error, :not_found}
  def remove_destination(repo, address, destination) do
    # SQLite cannot DELETE with a JOIN.
    ids = from(a in Alias, where: a.address == ^Data.fold(address), select: a.id)

    Data.delete(
      repo,
      from(d in AliasDestination,
        where: d.alias_id in subquery(ids) and d.address == ^String.trim(destination)
      )
    )
  end

  @doc "Enables or disables an alias."
  @spec set_enabled(Repo.t(), String.t(), boolean()) ::
          {:ok, Alias.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def set_enabled(repo, address, enabled),
    do: Data.set_enabled(repo, Alias, [address: Data.fold(address)], enabled)

  @doc "Lists all aliases, by address, with their destinations."
  @spec list(Repo.t()) :: [Alias.t()]
  def list(repo) do
    Repo.run(repo, fn module ->
      from(a in Alias, order_by: a.address)
      |> module.all()
      |> module.preload(destinations: from(d in AliasDestination, order_by: d.id))
    end)
  end

  @impl Sovite.Core.Lookup
  def lookup(%{repo: repo}, key) do
    query =
      from(d in AliasDestination,
        join: a in Alias,
        on: a.id == d.alias_id,
        where: a.address == ^Data.fold(key) and a.enabled,
        order_by: d.id,
        select: d.address
      )

    Data.lookup(repo, fn module ->
      case module.all(query) do
        [] -> nil
        destinations -> Enum.join(destinations, ", ")
      end
    end)
  end
end
