defmodule Sovite.Core.Repo.Tables.Domains do
  @moduledoc """
  Domains stored in Sovite's database, managed with `sovitectl domain`.
  They add to the domains in the `[domains]` config section; a domain in
  the config file wins over the same domain in the database.

  The SMTP server and the queue manager read them from a cache
  (`Sovite.Core.Repo.Tables.DomainCache`), refreshed every few seconds, so a change
  applies without a restart and a database outage does not make hosted
  domains look foreign.
  """

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Data
  alias Sovite.Core.Repo.Schemas.Domain

  @doc "Adds a domain of class `kind`."
  @spec add(Repo.t(), String.t(), Domain.kind() | String.t()) ::
          {:ok, Domain.t()} | {:error, Ecto.Changeset.t()}
  def add(repo, name, kind) do
    Repo.run(repo, fn module ->
      %Domain{} |> Domain.changeset(%{name: name, kind: kind}) |> module.insert()
    end)
  end

  @doc "Deletes a domain."
  @spec delete(Repo.t(), String.t()) :: :ok | {:error, :not_found}
  def delete(repo, name),
    do: Data.delete(repo, from(d in Domain, where: d.name == ^Data.fold(name)))

  @doc "Enables or disables a domain. Disabled domains are ignored."
  @spec set_enabled(Repo.t(), String.t(), boolean()) ::
          {:ok, Domain.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def set_enabled(repo, name, enabled),
    do: Data.set_enabled(repo, Domain, [name: Data.fold(name)], enabled)

  @doc "Lists all domains, by name."
  @spec list(Repo.t()) :: [Domain.t()]
  def list(repo), do: Repo.run(repo, & &1.all(from(d in Domain, order_by: d.name)))

  @doc "The enabled domains and their classes."
  @spec classes(Repo.t()) :: %{String.t() => Domain.kind()}
  def classes(repo) do
    query = from(d in Domain, where: d.enabled, select: {d.name, d.kind})
    repo |> Repo.run(& &1.all(query)) |> Map.new()
  end
end
