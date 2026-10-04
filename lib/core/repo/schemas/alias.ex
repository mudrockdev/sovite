defmodule Sovite.Core.Repo.Schemas.Alias do
  @moduledoc """
  An alias: mail for `address` goes to its destinations instead.
  `address` is a full address, `@domain` (every address of the domain
  that has no alias of its own), or a bare local part (for local domains).
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Sovite.Core.Repo.Data

  @type t :: %__MODULE__{}

  schema "aliases" do
    field(:address, :string)
    field(:enabled, :boolean, default: true)
    has_many(:destinations, Sovite.Core.Repo.Schemas.AliasDestination)
    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(entry, attrs) do
    entry
    |> cast(attrs, [:address, :enabled])
    |> Data.fold_fields([:address])
    |> validate_required([:address])
    |> validate_length(:address, max: 320)
    |> Data.validate_pattern(
      :address,
      [:address, :catchall, :local_part],
      ~s(must be an address, "@domain", or a local part)
    )
    |> unique_constraint(:address)
  end
end
