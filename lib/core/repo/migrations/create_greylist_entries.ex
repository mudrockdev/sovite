defmodule Sovite.Core.Repo.Migrations.CreateGreylistEntries do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:greylist_entries) do
      # SHA-256 of the triplet (Sovite.Abuse.Greylist.key/1): a fixed-size
      # unique key, as the three fields together are too long to index on
      # every database.
      add(:triplet, :string, size: 64, null: false)
      add(:client_network, :string, size: 43, null: false)
      add(:sender, :string, size: 320, null: false)
      add(:recipient, :string, size: 320, null: false)
      add(:first_seen, :utc_datetime, null: false)
      add(:last_seen, :utc_datetime, null: false)
      add(:passed_at, :utc_datetime)
      add(:expires_at, :utc_datetime, null: false)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:greylist_entries, [:triplet]))
    create(index(:greylist_entries, [:expires_at]))
  end
end
