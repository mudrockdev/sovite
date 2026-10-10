defmodule Sovite.Core.Repo.Schemas.AddressRewrite do
  @moduledoc """
  An address rewrite: addresses matching `pattern` (a full address,
  `@domain`, or a local part) become `replacement` (a full address,
  `@domain` to change only the domain, or a local part to change only the
  local part). `kind` says which addresses: `:sender`, `:recipient`, or
  `:both`.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Sovite.Core.Repo.Data

  @type t :: %__MODULE__{}

  schema "address_rewrites" do
    field(:kind, Ecto.Enum, values: [:sender, :recipient, :both])
    field(:pattern, :string)
    field(:replacement, :string)
    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(rewrite, attrs) do
    rewrite
    |> cast(attrs, [:kind, :pattern, :replacement])
    |> Data.fold_fields([:pattern])
    |> update_change(:replacement, &String.trim/1)
    |> Data.ascii_fields([:replacement])
    |> validate_required([:kind, :pattern, :replacement])
    |> validate_length(:pattern, max: 320)
    |> validate_length(:replacement, max: 320)
    |> Data.validate_pattern(
      :pattern,
      [:address, :catchall, :local_part],
      ~s(must be an address, "@domain", or a local part)
    )
    |> Data.validate_pattern(
      :replacement,
      [:address, :catchall, :local_part],
      ~s(must be an address, "@domain", or a local part)
    )
    |> unique_constraint([:kind, :pattern])
  end
end
