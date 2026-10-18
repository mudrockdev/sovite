defmodule Sovite.Core.Repo.Migrations.CreateIPAddressCounts do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:ip_address_counts) do
      # The source address, as text ("192.0.2.10", "2001:db8::10").
      add(:address, :string, size: 45, null: false)
      add(:day, :date, null: false)
      add(:messages, :integer, null: false, default: 0)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:ip_address_counts, [:address, :day]))
    create(index(:ip_address_counts, [:day]))
  end
end
