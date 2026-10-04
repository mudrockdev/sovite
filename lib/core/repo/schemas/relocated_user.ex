defmodule Sovite.Core.Repo.Schemas.RelocatedUser do
  @moduledoc """
  A user who moved: mail for `address` is rejected with `5.1.6` and
  `new_location` (usually the new address).
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Sovite.Core.Repo.Data

  @type t :: %__MODULE__{}

  schema "relocated_users" do
    field(:address, :string)
    field(:new_location, :string)
    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(user, attrs) do
    user
    |> cast(attrs, [:address, :new_location])
    |> Data.fold_fields([:address])
    |> update_change(:new_location, &String.trim/1)
    |> validate_required([:address, :new_location])
    |> validate_length(:address, max: 320)
    |> validate_length(:new_location, max: 512)
    |> validate_format(:new_location, ~r/\A[^\r\n]*\z/, message: "must be one line")
    |> Data.validate_pattern(:address, [:address, :catchall], ~s(must be an address or "@domain"))
    |> unique_constraint(:address)
  end
end
