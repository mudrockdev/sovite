defmodule Sovite.Core.Repo.Migrations.CreateFilterThresholds do
  @moduledoc false
  use Ecto.Migration

  def change do
    create table(:filter_thresholds) do
      # A full address, or "@domain".
      add(:pattern, :string, size: 320, null: false)
      # reject, soft_reject, quarantine, rewrite_subject, add_header, greylist
      add(:action, :string, size: 16, null: false)
      # The score from which the action is taken; NULL turns it off.
      add(:score, :float)
      timestamps(type: :utc_datetime)
    end

    create(unique_index(:filter_thresholds, [:pattern, :action]))
  end
end
