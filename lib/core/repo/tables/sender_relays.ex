defmodule Sovite.Core.Repo.Tables.SenderRelays do
  @moduledoc """
  Sender-dependent relaying, stored in Sovite's database and managed
  with `sovitectl sender-relay`: for a sender address or `@domain`, the
  relay host, the source address to connect from, and the credentials
  for the relay host.

  As a `Sovite.Core.Lookup` table, the handle names the field a lookup
  returns: `:relayhost`, `:source_address`, or `:credentials`
  (`username:password`).

  A field that is not set is "not found".
  """

  @behaviour Sovite.Core.Lookup

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Data
  alias Sovite.Core.Repo.Schemas.SenderRelay

  @fields [:relayhost, :source_address, :username, :password]

  @doc """
  Sets fields (`:relayhost`, `:source_address`, `:username`,
  `:password`) for `sender`, creating its entry if needed. A `nil` value
  clears the field.
  """
  @spec set(Repo.t(), String.t(), map()) :: {:ok, SenderRelay.t()} | {:error, Ecto.Changeset.t()}
  def set(repo, sender, fields) do
    attrs = fields |> Map.take(@fields) |> Map.put(:sender, sender)

    Data.upsert(repo, SenderRelay, [sender: Data.fold(sender)], &SenderRelay.changeset(&1, attrs))
  end

  @doc "Deletes the entry for `sender`."
  @spec delete(Repo.t(), String.t()) :: :ok | {:error, :not_found}
  def delete(repo, sender),
    do: Data.delete(repo, from(s in SenderRelay, where: s.sender == ^Data.fold(sender)))

  @doc "Lists all entries, by sender."
  @spec list(Repo.t()) :: [SenderRelay.t()]
  def list(repo), do: Repo.run(repo, & &1.all(from(s in SenderRelay, order_by: s.sender)))

  @impl Sovite.Core.Lookup
  def lookup(%{repo: repo, field: field}, key) do
    Data.lookup(repo, fn module ->
      case module.get_by(SenderRelay, sender: Data.fold(key)) do
        nil -> nil
        relay -> value(relay, field)
      end
    end)
  end

  defp value(%{username: nil}, :credentials), do: nil
  defp value(relay, :credentials), do: "#{relay.username}:#{relay.password || ""}"
  defp value(relay, field), do: Map.fetch!(relay, field)
end
