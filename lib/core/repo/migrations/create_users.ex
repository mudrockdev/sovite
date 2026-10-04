defmodule Sovite.Core.Repo.Migrations.CreateUsers do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:users) do
      # 320 characters: the longest valid email address.
      add(:username, :string, size: 320, null: false)
      add(:password_hash, :string, size: 512, null: false)
      add(:enabled, :boolean, null: false, default: true)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:users, [:username]))

    create table(:sender_logins) do
      add(:user_id, references(:users, on_delete: :delete_all), null: false)
      add(:address, :string, size: 320, null: false)
      timestamps(type: :utc_datetime, updated_at: false)
    end

    create(unique_index(:sender_logins, [:user_id, :address]))
  end
end
