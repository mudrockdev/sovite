defmodule Sovite.Core.Repo.Migrations.CreateTLSReportEntries do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:tls_report_entries) do
      # The recipient domain, and the policy that applied to the session:
      # its type, and the policy itself (the MTA-STS policy body, or the
      # TLSA records, one per line).
      add(:policy_domain, :string, size: 253, null: false)
      add(:policy_type, :string, size: 16, null: false)
      add(:policy, :text)
      # The session.
      add(:mx_host, :string, size: 253, null: false)
      add(:receiving_ip, :string, size: 45, null: false)
      add(:receiving_helo, :string, size: 253)
      add(:sending_ip, :string, size: 45)
      # Empty for a successful session; otherwise why it failed.
      add(:result_type, :string, size: 32)
      add(:failure_reason, :string, size: 255)
      timestamps(type: :utc_datetime, updated_at: false)
    end

    create(index(:tls_report_entries, [:policy_domain, :inserted_at]))
  end
end
