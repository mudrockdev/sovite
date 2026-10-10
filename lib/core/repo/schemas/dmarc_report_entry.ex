defmodule Sovite.Core.Repo.Schemas.DMARCReportEntry do
  @moduledoc """
  The DMARC evaluation of one received message, kept until the next
  aggregate report for its policy domain (`Sovite.Core.DMARCReports`).
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Sovite.Core.Repo.Schemas.DMARCSignature

  @type t :: %__MODULE__{}

  @policies [:none, :quarantine, :reject]
  @spf_results [:pass, :fail, :softfail, :neutral, :none, :temperror, :permerror]

  @overrides [
    :forwarded,
    :sampled_out,
    :trusted_forwarder,
    :mailing_list,
    :local_policy,
    :other
  ]

  schema "dmarc_report_entries" do
    field(:policy_domain, :string)
    field(:rua, :string)
    field(:adkim, Ecto.Enum, values: [:relaxed, :strict])
    field(:aspf, Ecto.Enum, values: [:relaxed, :strict])
    field(:p, Ecto.Enum, values: @policies)
    field(:sp, Ecto.Enum, values: @policies)
    field(:np, Ecto.Enum, values: @policies)
    field(:pct, :integer)
    field(:source_ip, :string)
    field(:header_from, :string)
    field(:envelope_from, :string)
    field(:envelope_to, :string)
    field(:disposition, Ecto.Enum, values: @policies)
    field(:dkim, Ecto.Enum, values: [:pass, :fail])
    field(:spf, Ecto.Enum, values: [:pass, :fail])
    field(:override, Ecto.Enum, values: @overrides)
    field(:spf_domain, :string)
    field(:spf_scope, Ecto.Enum, values: [:mfrom, :helo])
    field(:spf_result, Ecto.Enum, values: @spf_results)
    embeds_many(:signatures, DMARCSignature, on_replace: :delete)
    timestamps(type: :utc_datetime, updated_at: false)
  end

  @fields [
    :policy_domain,
    :rua,
    :adkim,
    :aspf,
    :p,
    :sp,
    :np,
    :pct,
    :source_ip,
    :header_from,
    :envelope_from,
    :envelope_to,
    :disposition,
    :dkim,
    :spf,
    :override,
    :spf_domain,
    :spf_scope,
    :spf_result
  ]

  @required [
    :policy_domain,
    :rua,
    :adkim,
    :aspf,
    :p,
    :sp,
    :pct,
    :source_ip,
    :header_from,
    :disposition,
    :dkim,
    :spf
  ]

  @doc false
  def changeset(entry, attrs) do
    entry
    |> cast(attrs, @fields)
    |> cast_embed(:signatures, with: &DMARCSignature.changeset/2)
    |> validate_required(@required)
    |> validate_number(:pct, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> validate_length(:rua, max: 2048)
    |> truncate([:policy_domain, :header_from, :envelope_from, :envelope_to, :spf_domain], 253)
  end

  # Domains come from messages: keep them within the columns.
  defp truncate(changeset, fields, max) do
    Enum.reduce(fields, changeset, fn field, changeset ->
      update_change(changeset, field, &String.slice(&1, 0, max))
    end)
  end
end
