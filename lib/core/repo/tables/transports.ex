defmodule Sovite.Core.Repo.Tables.Transports do
  @moduledoc """
  Transports stored in Sovite's database, managed with
  `sovitectl transport`.

  As a `Sovite.Core.Lookup` table, a lookup returns the transport
  for a pattern; `Sovite.Core.Router` tries the patterns in order.
  """

  @behaviour Sovite.Core.Lookup

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Data
  alias Sovite.Core.Repo.Schemas.Transport

  @doc "Sets the transport for `pattern`, replacing any earlier one."
  @spec set(Repo.t(), String.t(), String.t()) ::
          {:ok, Transport.t()} | {:error, Ecto.Changeset.t()}
  def set(repo, pattern, transport) do
    Data.upsert(
      repo,
      Transport,
      [pattern: Data.fold(pattern)],
      &Transport.changeset(&1, %{pattern: pattern, transport: transport})
    )
  end

  @doc "Deletes the entry for `pattern`."
  @spec delete(Repo.t(), String.t()) :: :ok | {:error, :not_found}
  def delete(repo, pattern),
    do: Data.delete(repo, from(t in Transport, where: t.pattern == ^Data.fold(pattern)))

  @doc "Lists all entries, by pattern."
  @spec list(Repo.t()) :: [Transport.t()]
  def list(repo), do: Repo.run(repo, & &1.all(from(t in Transport, order_by: t.pattern)))

  @impl Sovite.Core.Lookup
  def lookup(%{repo: repo}, key) do
    query = from(t in Transport, where: t.pattern == ^Data.fold(key), select: t.transport)
    Data.lookup(repo, & &1.one(query))
  end
end
