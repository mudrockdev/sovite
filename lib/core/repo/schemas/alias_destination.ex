defmodule Sovite.Core.Repo.Schemas.AliasDestination do
  @moduledoc "One address an alias delivers to."

  use Ecto.Schema

  import Ecto.Changeset

  alias Sovite.Core.Repo.Data

  @type t :: %__MODULE__{}

  schema "alias_destinations" do
    # A plain field, not belongs_to: the schemas must not depend on each other.
    field(:alias_id, :id)
    field(:address, :string)
    timestamps(type: :utc_datetime, updated_at: false)
  end

  @doc false
  def changeset(destination, attrs) do
    destination
    |> cast(attrs, [:address])
    |> update_change(:address, &String.trim/1)
    |> Data.ascii_fields([:address])
    |> validate_required([:address])
    |> validate_length(:address, max: 320)
    |> Data.validate_pattern(:address, [:address], "is not a valid email address")
    |> unique_constraint([:alias_id, :address])
  end
end
