defmodule Sovite.Core.Repo.Tables.IPAddressCounts do
  @moduledoc """
  Messages sent per source address and day, for the warm-up schedules
  and daily limits of `Sovite.Core.MTA.IPPools`.
  """

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Schemas.IPAddressCount

  @doc "The counts of `day`, by address."
  @spec day(Repo.t(), Date.t()) :: %{String.t() => non_neg_integer()}
  def day(repo, day) do
    query = from(c in IPAddressCount, where: c.day == ^day, select: {c.address, c.messages})
    Repo.run(repo, &Map.new(&1.all(query)))
  end

  @doc "Adds `messages` to the count of `address` on `day`."
  @spec add(Repo.t(), String.t(), Date.t(), pos_integer()) ::
          {:ok, IPAddressCount.t()} | {:error, Ecto.Changeset.t()}
  def add(repo, address, day, messages) do
    Repo.run(repo, fn module ->
      module.transaction(fn -> increment(module, address, day, messages) end)
    end)
  end

  defp increment(module, address, day, messages) do
    count = module.get_by(IPAddressCount, address: address, day: day) || %IPAddressCount{}
    attrs = %{address: address, day: day, messages: (count.messages || 0) + messages}

    case count |> IPAddressCount.changeset(attrs) |> module.insert_or_update() do
      {:ok, count} -> count
      {:error, changeset} -> module.rollback(changeset)
    end
  end

  @doc "Deletes the counts of days before `day`. Returns how many."
  @spec delete_before(Repo.t(), Date.t()) :: non_neg_integer()
  def delete_before(repo, day) do
    query = from(c in IPAddressCount, where: c.day < ^day)
    Repo.run(repo, fn module -> elem(module.delete_all(query), 0) end)
  end

  @doc "Every count, newest day first."
  @spec list(Repo.t()) :: [IPAddressCount.t()]
  def list(repo),
    do:
      Repo.run(
        repo,
        & &1.all(from(c in IPAddressCount, order_by: [desc: c.day, asc: c.address]))
      )
end
