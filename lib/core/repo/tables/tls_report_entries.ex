defmodule Sovite.Core.Repo.Tables.TLSReportEntries do
  @moduledoc """
  TLS outcomes of outgoing sessions waiting to be reported, one per
  session, written by `Sovite.Core.Delivery` and read and removed by
  `Sovite.Core.TLSReports` when it sends the TLS-RPT reports.
  """

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Schemas.TLSReportEntry

  @doc "Stores a session outcome."
  @spec add(Repo.t(), map()) :: {:ok, TLSReportEntry.t()} | {:error, Ecto.Changeset.t()}
  def add(repo, attrs) do
    Repo.run(repo, fn module ->
      %TLSReportEntry{}
      |> TLSReportEntry.changeset(attrs)
      |> module.insert()
    end)
  end

  @doc "The policy domains with outcomes stored before `until`."
  @spec domains(Repo.t(), DateTime.t()) :: [String.t()]
  def domains(repo, until) do
    until = seconds(until)

    query =
      from(e in TLSReportEntry,
        where: e.inserted_at < ^until,
        distinct: true,
        order_by: e.policy_domain,
        select: e.policy_domain
      )

    Repo.run(repo, & &1.all(query))
  end

  @doc "The outcomes for `domain` stored before `until`, oldest first."
  @spec list(Repo.t(), String.t(), DateTime.t()) :: [TLSReportEntry.t()]
  def list(repo, domain, until) do
    until = seconds(until)

    query =
      from(e in TLSReportEntry,
        where: e.policy_domain == ^domain and e.inserted_at < ^until,
        order_by: e.id
      )

    Repo.run(repo, & &1.all(query))
  end

  @doc "Deletes the outcomes for `domain` stored before `until`, once reported."
  @spec delete(Repo.t(), String.t(), DateTime.t()) :: non_neg_integer()
  def delete(repo, domain, until) do
    until = seconds(until)

    query =
      from(e in TLSReportEntry, where: e.policy_domain == ^domain and e.inserted_at < ^until)

    Repo.run(repo, fn module -> elem(module.delete_all(query), 0) end)
  end

  # The column has whole seconds, and SQLite compares the times as text,
  # where "12:00:00Z" sorts after "12:00:00.5Z".
  defp seconds(time), do: DateTime.truncate(time, :second)
end
