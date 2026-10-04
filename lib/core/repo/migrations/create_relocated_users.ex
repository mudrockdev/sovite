defmodule Sovite.Core.Repo.Migrations.CreateRelocatedUsers do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:relocated_users) do
      add(:address, :string, size: 320, null: false)
      add(:new_location, :string, size: 512, null: false)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:relocated_users, [:address]))
  end
end
