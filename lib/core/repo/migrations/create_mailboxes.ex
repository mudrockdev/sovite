defmodule Sovite.Core.Repo.Migrations.CreateMailboxes do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:mailboxes) do
      # A full address, or "@domain" to accept every address of a domain.
      add(:address, :string, size: 320, null: false)
      add(:enabled, :boolean, null: false, default: true)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:mailboxes, [:address]))
  end
end
