defmodule Sovite.Core.Repo.Migrations.CreateSenderRelays do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:sender_relays) do
      # A sender address, or "@domain".
      add(:sender, :string, size: 320, null: false)
      add(:relayhost, :string, size: 300)
      add(:source_address, :string, size: 100)
      add(:username, :string, size: 320)
      add(:password, :string, size: 512)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:sender_relays, [:sender]))
  end
end
