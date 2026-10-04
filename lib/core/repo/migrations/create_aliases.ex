defmodule Sovite.Core.Repo.Migrations.CreateAliases do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:aliases) do
      # A full address, "@domain" (catch-all), or a local part.
      add(:address, :string, size: 320, null: false)
      add(:enabled, :boolean, null: false, default: true)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:aliases, [:address]))

    create table(:alias_destinations) do
      add(:alias_id, references(:aliases, on_delete: :delete_all), null: false)
      add(:address, :string, size: 320, null: false)
      timestamps(type: :utc_datetime, updated_at: false)
    end

    create(unique_index(:alias_destinations, [:alias_id, :address]))
  end
end
