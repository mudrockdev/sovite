defmodule Sovite.Core.Repo.Schemas.FilterThreshold do
  @moduledoc """
  A filter threshold for the mail of an address or a domain (`pattern`:
  a full address, or `@domain`): the score from which the filter takes
  `action` (see `Sovite.Rules.Actions`), or `nil` to never take it. It
  comes before those of the tenant and of `[filter.actions]`.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Sovite.Core.Repo.Data

  @type t :: %__MODULE__{}

  schema "filter_thresholds" do
    field(:pattern, :string)

    field(:action, Ecto.Enum,
      values: [:reject, :soft_reject, :quarantine, :rewrite_subject, :add_header, :greylist]
    )

    field(:score, :float)
    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(threshold, attrs) do
    threshold
    |> cast(attrs, [:pattern, :action, :score])
    |> Data.fold_fields([:pattern])
    |> validate_required([:pattern, :action])
    |> validate_length(:pattern, max: 320)
    |> Data.validate_pattern(:pattern, [:address, :catchall], ~s(must be an address or "@domain"))
    |> validate_number(:score,
      greater_than_or_equal_to: -1_000_000,
      less_than_or_equal_to: 1_000_000
    )
    |> unique_constraint([:pattern, :action])
  end
end
