defmodule Sovite.Core.Repo.Migrations.CreateDMARCReportEntries do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:dmarc_report_entries) do
      # The domain whose policy applied, and what it published.
      add(:policy_domain, :string, size: 253, null: false)
      # The rua= URIs, comma-separated as in the record.
      add(:rua, :string, size: 2048, null: false)
      add(:adkim, :string, size: 8, null: false)
      add(:aspf, :string, size: 8, null: false)
      add(:p, :string, size: 16, null: false)
      add(:sp, :string, size: 16, null: false)
      add(:np, :string, size: 16)
      add(:pct, :integer, null: false)
      # The message.
      add(:source_ip, :string, size: 45, null: false)
      add(:header_from, :string, size: 253, null: false)
      add(:envelope_from, :string, size: 253)
      add(:envelope_to, :string, size: 253)
      # What was decided: the disposition, the aligned results, and why a
      # disposition differs from the policy.
      add(:disposition, :string, size: 16, null: false)
      add(:dkim, :string, size: 8, null: false)
      add(:spf, :string, size: 8, null: false)
      add(:override, :string, size: 32)
      # The SPF check behind the aligned result.
      add(:spf_domain, :string, size: 253)
      add(:spf_scope, :string, size: 8)
      add(:spf_result, :string, size: 16)
      # Every DKIM signature checked: a JSON list of domain, selector, result.
      add(:signatures, :map, null: false)
      timestamps(type: :utc_datetime, updated_at: false)
    end

    create(index(:dmarc_report_entries, [:policy_domain, :inserted_at]))
  end
end
