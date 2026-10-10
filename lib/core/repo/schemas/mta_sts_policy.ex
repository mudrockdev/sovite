defmodule Sovite.Core.Repo.Schemas.MTASTSPolicy do
  @moduledoc """
  The cached MTA-STS policy of a domain Sovite delivers to (RFC 8461
  §5.1), kept by `Sovite.Core.MTASTS` until `expires_at`.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{}

  schema "mta_sts_policies" do
    field(:domain, :string)
    field(:policy_id, :string)
    field(:mode, Ecto.Enum, values: [:enforce, :testing, :none])
    field(:max_age, :integer)
    field(:policy, :string)
    field(:fetched_at, :utc_datetime)
    field(:expires_at, :utc_datetime)
    timestamps(type: :utc_datetime)
  end

  @fields [:domain, :policy_id, :mode, :max_age, :policy, :fetched_at, :expires_at]

  @doc false
  def changeset(policy, attrs) do
    policy
    |> cast(attrs, @fields)
    |> validate_required(@fields)
    |> validate_length(:domain, max: 253)
    |> validate_length(:policy_id, max: 32)
    |> validate_number(:max_age, greater_than_or_equal_to: 0)
    |> unique_constraint(:domain)
  end
end
