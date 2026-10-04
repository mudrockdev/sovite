defmodule Sovite.Core.Repo.Migrations.CreateAccessRules do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:access_rules) do
      # client, helo, sender, or recipient
      add(:kind, :string, size: 32, null: false)
      add(:pattern, :string, size: 320, null: false)
      # ACCEPT, CONTINUE, REJECT, DEFER, DISCARD, HOLD, WARN, or a reply code
      add(:action, :string, size: 16, null: false)
      add(:text, :string, size: 512)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:access_rules, [:kind, :pattern]))
  end
end
