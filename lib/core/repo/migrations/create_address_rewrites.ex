defmodule Sovite.Core.Repo.Migrations.CreateAddressRewrites do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:address_rewrites) do
      # sender, recipient, or both
      add(:kind, :string, size: 16, null: false)
      # A full address, "@domain", or a local part.
      add(:pattern, :string, size: 320, null: false)
      # A full address, "@domain" (new domain), or a local part.
      add(:replacement, :string, size: 320, null: false)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:address_rewrites, [:kind, :pattern]))
  end
end
