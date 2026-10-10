defmodule Sovite.Core.Repo.Schemas.GreylistEntry do
  @moduledoc """
  A greylisting triplet (client network, sender, recipient), see
  `Sovite.Abuse.Greylist`: when it was first and last seen, and when it
  passed. Deleted after `expires_at`.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{}

  schema "greylist_entries" do
    field(:triplet, :string)
    field(:client_network, :string)
    field(:sender, :string)
    field(:recipient, :string)
    field(:first_seen, :utc_datetime)
    field(:last_seen, :utc_datetime)
    field(:passed_at, :utc_datetime)
    field(:expires_at, :utc_datetime)
    timestamps(type: :utc_datetime)
  end

  @required [:triplet, :client_network, :sender, :recipient, :first_seen, :last_seen, :expires_at]

  @doc false
  def changeset(entry, attrs) do
    entry
    # The null sender is "", which must not become nil.
    |> cast(attrs, @required ++ [:passed_at], empty_values: [])
    |> validate_required(@required -- [:sender])
    |> validate_length(:triplet, is: 64)
    |> validate_length(:client_network, max: 43)
    |> validate_length(:sender, max: 320)
    |> validate_length(:recipient, max: 320)
    |> unique_constraint(:triplet)
  end
end
