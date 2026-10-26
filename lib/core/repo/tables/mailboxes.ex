defmodule Sovite.Core.Repo.Tables.Mailboxes do
  @moduledoc """
  Mailboxes of virtual mailbox domains, stored in Sovite's database and
  managed with `sovitectl mailbox`.

  As a `Sovite.Core.MTA.Lookup` table, a lookup finds enabled mailboxes and
  returns their address.
  """

  @behaviour Sovite.Core.MTA.Lookup

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Data
  alias Sovite.Core.Repo.Schemas.Mailbox

  @doc "Adds a mailbox."
  @spec add(Repo.t(), String.t()) :: {:ok, Mailbox.t()} | {:error, Ecto.Changeset.t()}
  def add(repo, address) do
    Repo.run(repo, fn module ->
      %Mailbox{} |> Mailbox.changeset(%{address: address}) |> module.insert()
    end)
  end

  @doc "Deletes a mailbox."
  @spec delete(Repo.t(), String.t()) :: :ok | {:error, :not_found}
  def delete(repo, address),
    do: Data.delete(repo, from(m in Mailbox, where: m.address == ^Data.fold(address)))

  @doc "Enables or disables a mailbox. Mail for a disabled one is rejected."
  @spec set_enabled(Repo.t(), String.t(), boolean()) ::
          {:ok, Mailbox.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def set_enabled(repo, address, enabled),
    do: Data.set_enabled(repo, Mailbox, [address: Data.fold(address)], enabled)

  @doc "Lists all mailboxes, by address."
  @spec list(Repo.t()) :: [Mailbox.t()]
  def list(repo), do: Repo.run(repo, & &1.all(from(m in Mailbox, order_by: m.address)))

  @doc """
  When the mailbox at exactly `address` was added, for `RRVS` (RFC
  7293), or `:error` if there is none.
  """
  @spec added_at(Repo.t(), String.t()) :: {:ok, DateTime.t()} | :error
  def added_at(repo, address) do
    query =
      from(m in Mailbox, where: m.address == ^Data.fold(address), select: m.inserted_at)

    case Repo.run(repo, & &1.one(query)) do
      %DateTime{} = time -> {:ok, time}
      nil -> :error
    end
  end

  @impl Sovite.Core.MTA.Lookup
  def lookup(%{repo: repo}, key) do
    query =
      from(m in Mailbox, where: m.address == ^Data.fold(key) and m.enabled, select: m.address)

    Data.lookup(repo, & &1.one(query))
  end
end
