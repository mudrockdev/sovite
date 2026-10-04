defmodule Sovite.Core.Repo.Migrations.CreateTransports do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:transports) do
      # An address, a domain, ".domain" (subdomains), or "*".
      add(:pattern, :string, size: 320, null: false)
      # A transport specification, such as "lmtp:unix:/run/dovecot/lmtp".
      add(:transport, :string, size: 512, null: false)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:transports, [:pattern]))
  end
end
