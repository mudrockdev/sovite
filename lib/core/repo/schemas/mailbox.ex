defmodule Sovite.Core.Repo.Schemas.Mailbox do
  @moduledoc """
  A mailbox in a virtual mailbox domain: `address`, or `@domain` to
  accept every address of the domain.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Sovite.Core.Repo.Data

  @type t :: %__MODULE__{}

  schema "mailboxes" do
    field(:address, :string)
    field(:enabled, :boolean, default: true)
    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(mailbox, attrs) do
    mailbox
    |> cast(attrs, [:address, :enabled])
    |> Data.fold_fields([:address])
    |> validate_required([:address])
    |> validate_length(:address, max: 320)
    |> Data.validate_pattern(:address, [:address, :catchall], ~s(must be an address or "@domain"))
    |> unique_constraint(:address)
  end
end
