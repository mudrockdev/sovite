defmodule Sovite.Core.Repo.Tables.RelocatedUsers do
  @moduledoc """
  Users who moved, stored in Sovite's database and managed with
  `sovitectl moved`. Mail for them is rejected with `5.1.6` and
  their new location.

  As a `Sovite.Core.Lookup` table, a lookup returns the new
  location.
  """

  @behaviour Sovite.Core.Lookup

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Data
  alias Sovite.Core.Repo.Schemas.RelocatedUser

  @doc "Records that `address` moved to `new_location`, replacing any earlier entry."
  @spec set(Repo.t(), String.t(), String.t()) ::
          {:ok, RelocatedUser.t()} | {:error, Ecto.Changeset.t()}
  def set(repo, address, new_location) do
    Data.upsert(
      repo,
      RelocatedUser,
      [address: Data.fold(address)],
      &RelocatedUser.changeset(&1, %{address: address, new_location: new_location})
    )
  end

  @doc "Deletes the entry for `address`."
  @spec delete(Repo.t(), String.t()) :: :ok | {:error, :not_found}
  def delete(repo, address),
    do: Data.delete(repo, from(r in RelocatedUser, where: r.address == ^Data.fold(address)))

  @doc "Lists all entries, by address."
  @spec list(Repo.t()) :: [RelocatedUser.t()]
  def list(repo), do: Repo.run(repo, & &1.all(from(r in RelocatedUser, order_by: r.address)))

  @impl Sovite.Core.Lookup
  def lookup(%{repo: repo}, key) do
    query =
      from(r in RelocatedUser, where: r.address == ^Data.fold(key), select: r.new_location)

    Data.lookup(repo, & &1.one(query))
  end
end
