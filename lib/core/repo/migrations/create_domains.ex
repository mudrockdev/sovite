defmodule Sovite.Core.Repo.Migrations.CreateDomains do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:domains) do
      add(:name, :string, size: 253, null: false)
      # local, aliased, hosted, or relay
      add(:kind, :string, size: 32, null: false)
      add(:enabled, :boolean, null: false, default: true)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:domains, [:name]))
  end
end
