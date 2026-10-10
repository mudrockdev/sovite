defmodule Sovite.Core.Repo.Schemas.Domain do
  @moduledoc """
  A domain this server handles, and its class (see
  `Sovite.Core.Routing`): `:local`, `:aliased`, `:hosted`, or `:relay`.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Sovite.Core.Repo.Data

  @kinds [:local, :aliased, :hosted, :relay]

  @type kind :: :local | :aliased | :hosted | :relay
  @type t :: %__MODULE__{}

  schema "domains" do
    field(:name, :string)
    field(:kind, Ecto.Enum, values: @kinds)
    field(:enabled, :boolean, default: true)
    timestamps(type: :utc_datetime)
  end

  @doc "The domain classes."
  @spec kinds() :: [kind()]
  def kinds, do: @kinds

  @doc false
  def changeset(domain, attrs) do
    domain
    |> cast(attrs, [:name, :kind, :enabled])
    |> Data.fold_fields([:name], domain: true)
    |> validate_required([:name, :kind])
    |> validate_length(:name, max: 253)
    |> Data.validate_pattern(:name, [:domain], "is not a valid domain")
    |> unique_constraint(:name)
  end
end
