defmodule Sovite.Core.Repo.Migrations.CreateMTASTSPolicies do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:mta_sts_policies) do
      # The policy domain, and the id= of its _mta-sts TXT record when the
      # policy was fetched.
      add(:domain, :string, size: 253, null: false)
      add(:policy_id, :string, size: 32, null: false)
      add(:mode, :string, size: 8, null: false)
      add(:max_age, :integer, null: false)
      # The policy body as fetched, parsed again when read.
      add(:policy, :text, null: false)
      add(:fetched_at, :utc_datetime, null: false)
      add(:expires_at, :utc_datetime, null: false)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:mta_sts_policies, [:domain]))
  end
end
