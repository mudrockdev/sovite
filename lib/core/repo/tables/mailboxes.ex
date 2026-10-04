defmodule Sovite.Core.Repo.Tables.Mailboxes do
  @moduledoc """
  Mailboxes of virtual mailbox domains, stored in Sovite's database and
  managed with `sovitectl mailbox`.

  As a `Sovite.Core.Lookup` table, a lookup finds enabled mailboxes and
  returns their address.
  """

  @behaviour Sovite.Core.Lookup

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

  @impl Sovite.Core.Lookup
  def lookup(%{repo: repo}, key) do
    query =
      from(m in Mailbox, where: m.address == ^Data.fold(key) and m.enabled, select: m.address)

    Data.lookup(repo, & &1.one(query))
  end
end
