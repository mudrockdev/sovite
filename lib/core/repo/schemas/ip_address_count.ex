defmodule Sovite.Core.Repo.Schemas.IPAddressCount do
  @moduledoc """
  How many messages went out from one source address of an IP pool on
  one day (UTC), for warm-up schedules and daily limits, see
  `Sovite.Core.MTA.IPPools`.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{}

  schema "ip_address_counts" do
    field(:address, :string)
    field(:day, :date)
    field(:messages, :integer, default: 0)
    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(count, attrs) do
    count
    |> cast(attrs, [:address, :day, :messages])
    |> validate_required([:address, :day, :messages])
    |> validate_length(:address, max: 45)
    |> validate_number(:messages, greater_than_or_equal_to: 0)
    |> unique_constraint([:address, :day])
  end
end
