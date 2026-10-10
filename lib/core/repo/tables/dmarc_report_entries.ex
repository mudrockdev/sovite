defmodule Sovite.Core.Repo.Tables.DMARCReportEntries do
  @moduledoc """
  DMARC evaluations waiting to be reported, one per message, written by
  `Sovite.Core.SMTPHandler` and read and removed by
  `Sovite.Core.DMARCReports` when it sends the aggregate reports.
  """

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Schemas.DMARCReportEntry

  @doc "Stores an evaluation."
  @spec add(Repo.t(), map()) :: {:ok, DMARCReportEntry.t()} | {:error, Ecto.Changeset.t()}
  def add(repo, attrs) do
    Repo.run(repo, fn module ->
      %DMARCReportEntry{}
      |> DMARCReportEntry.changeset(attrs)
      |> module.insert()
    end)
  end

  @doc "The policy domains with evaluations stored before `until`."
  @spec domains(Repo.t(), DateTime.t()) :: [String.t()]
  def domains(repo, until) do
    query =
      from(e in DMARCReportEntry,
        where: e.inserted_at < ^until,
        distinct: true,
        order_by: e.policy_domain,
        select: e.policy_domain
      )

    Repo.run(repo, & &1.all(query))
  end

  @doc "The evaluations for `domain` stored before `until`, oldest first."
  @spec list(Repo.t(), String.t(), DateTime.t()) :: [DMARCReportEntry.t()]
  def list(repo, domain, until) do
    query =
      from(e in DMARCReportEntry,
        where: e.policy_domain == ^domain and e.inserted_at < ^until,
        order_by: e.id
      )

    Repo.run(repo, & &1.all(query))
  end

  @doc "Deletes the evaluations for `domain` stored before `until`, once reported."
  @spec delete(Repo.t(), String.t(), DateTime.t()) :: non_neg_integer()
  def delete(repo, domain, until) do
    query =
      from(e in DMARCReportEntry, where: e.policy_domain == ^domain and e.inserted_at < ^until)

    Repo.run(repo, fn module -> elem(module.delete_all(query), 0) end)
  end
end
