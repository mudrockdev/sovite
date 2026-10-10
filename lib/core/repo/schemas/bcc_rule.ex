defmodule Sovite.Core.Repo.Schemas.BccRule do
  @moduledoc """
  A BCC rule: messages whose sender (`kind: :sender`) or one of whose
  recipients (`kind: :recipient`) matches `pattern` (a full address, or
  `@domain`) are also sent to `address`.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Sovite.Core.Repo.Data

  @type t :: %__MODULE__{}

  schema "bcc_rules" do
    field(:kind, Ecto.Enum, values: [:sender, :recipient])
    field(:pattern, :string)
    field(:address, :string)
    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(rule, attrs) do
    rule
    |> cast(attrs, [:kind, :pattern, :address])
    |> Data.fold_fields([:pattern])
    |> update_change(:address, &String.trim/1)
    |> Data.ascii_fields([:address])
    |> validate_required([:kind, :pattern, :address])
    |> validate_length(:pattern, max: 320)
    |> validate_length(:address, max: 320)
    |> Data.validate_pattern(:pattern, [:address, :catchall], ~s(must be an address or "@domain"))
    |> Data.validate_pattern(:address, [:address], "is not a valid email address")
    |> unique_constraint([:kind, :pattern, :address])
  end
end
