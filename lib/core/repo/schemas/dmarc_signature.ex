defmodule Sovite.Core.Repo.Schemas.DMARCSignature do
  @moduledoc """
  One DKIM signature result of a `Sovite.Core.Repo.Schemas.DMARCReportEntry`,
  stored inside it.
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{}

  @primary_key false
  embedded_schema do
    field(:domain, :string)
    field(:selector, :string)

    field(:result, Ecto.Enum,
      values: [:pass, :fail, :neutral, :policy, :temperror, :permerror, :none]
    )
  end

  @doc false
  def changeset(signature, attrs) do
    signature
    |> cast(attrs, [:domain, :selector, :result])
    |> validate_required([:domain, :result])
    |> update_change(:domain, &String.slice(&1, 0, 253))
    |> update_change(:selector, &String.slice(&1, 0, 253))
  end
end
