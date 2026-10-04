defmodule Sovite.Core.Repo.Migrations.CreateBccRules do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:bcc_rules) do
      # sender or recipient
      add(:kind, :string, size: 16, null: false)
      # A full address, or "@domain".
      add(:pattern, :string, size: 320, null: false)
      # Where the copy goes.
      add(:address, :string, size: 320, null: false)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:bcc_rules, [:kind, :pattern, :address]))
  end
end
