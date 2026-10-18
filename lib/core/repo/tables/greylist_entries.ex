defmodule Sovite.Core.Repo.Tables.GreylistEntries do
  @moduledoc """
  The greylisting triplets seen by `Sovite.Core.Greylist`: one per
  client network, sender, and recipient.
  """

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Schemas.GreylistEntry

  @doc "The entry with key `triplet`, if any."
  @spec get(Repo.t(), String.t()) :: GreylistEntry.t() | nil
  def get(repo, triplet), do: Repo.run(repo, & &1.get_by(GreylistEntry, triplet: triplet))

  @doc "Stores the entry of `attrs.triplet`, replacing an earlier one."
  @spec put(Repo.t(), map()) :: {:ok, GreylistEntry.t()} | {:error, Ecto.Changeset.t()}
  def put(repo, attrs) do
    Repo.run(repo, fn module ->
      (module.get_by(GreylistEntry, triplet: attrs.triplet) || %GreylistEntry{})
      |> GreylistEntry.changeset(attrs)
      |> module.insert_or_update()
    end)
  end

  @doc """
  Merges an entry from another node (see `Sovite.Core.Cluster.Sync`):
  stored if new, otherwise combined with the stored one, keeping the
  earliest first sighting and pass, and the latest use and expiry.
  """
  @spec merge(Repo.t(), map()) :: {:ok, GreylistEntry.t()} | {:error, Ecto.Changeset.t()}
  def merge(repo, attrs) do
    Repo.run(repo, fn module ->
      case module.get_by(GreylistEntry, triplet: attrs.triplet) do
        nil ->
          %GreylistEntry{} |> GreylistEntry.changeset(attrs) |> module.insert()

        stored ->
          merged = %{
            first_seen: earliest(stored.first_seen, attrs.first_seen),
            last_seen: latest(stored.last_seen, attrs.last_seen),
            passed_at: earliest(stored.passed_at, attrs.passed_at),
            expires_at: latest(stored.expires_at, attrs.expires_at)
          }

          stored |> GreylistEntry.changeset(merged) |> module.update()
      end
    end)
  end

  defp earliest(nil, b), do: b
  defp earliest(a, nil), do: a
  defp earliest(a, b), do: if(DateTime.before?(a, b), do: a, else: b)

  defp latest(a, b), do: if(DateTime.after?(a, b), do: a, else: b)

  @doc "Deletes the entries that expired before `now`. Returns how many."
  @spec delete_expired(Repo.t(), DateTime.t()) :: non_neg_integer()
  def delete_expired(repo, now) do
    now = DateTime.truncate(now, :second)
    query = from(e in GreylistEntry, where: e.expires_at < ^now)
    Repo.run(repo, fn module -> elem(module.delete_all(query), 0) end)
  end

  @doc "Deletes every entry. Returns how many."
  @spec delete_all(Repo.t()) :: non_neg_integer()
  def delete_all(repo),
    do: Repo.run(repo, fn module -> elem(module.delete_all(GreylistEntry), 0) end)

  @doc "The entries, most recently seen first."
  @spec list(Repo.t()) :: [GreylistEntry.t()]
  def list(repo),
    do:
      Repo.run(repo, & &1.all(from(e in GreylistEntry, order_by: [desc: e.last_seen, asc: e.id])))

  @doc "How many entries there are, and how many of them passed."
  @spec counts(Repo.t()) :: %{total: non_neg_integer(), passed: non_neg_integer()}
  def counts(repo) do
    query =
      from(e in GreylistEntry,
        select: %{total: count(e.id), passed: count(e.passed_at)}
      )

    Repo.run(repo, & &1.one(query))
  end
end
