defmodule Sovite.Core.Repo.Schemas.Transport do
  @moduledoc """
  A transport map entry: mail for `pattern` (an address, a domain,
  `.domain` for its subdomains, or `*`) goes through `transport`, a
  `Sovite.Core.Transport` specification.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Sovite.Core.Repo.Data
  alias Sovite.Core.Transport, as: TransportSpec

  @type t :: %__MODULE__{}

  schema "transports" do
    field(:pattern, :string)
    field(:transport, :string)
    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(entry, attrs) do
    entry
    |> cast(attrs, [:pattern, :transport])
    |> Data.fold_fields([:pattern])
    |> update_change(:transport, &String.trim/1)
    |> validate_required([:pattern, :transport])
    |> validate_length(:pattern, max: 320)
    |> validate_length(:transport, max: 512)
    |> Data.validate_pattern(
      :pattern,
      [:address, :domain, :subdomains, :wildcard],
      ~s(must be an address, a domain, ".domain", or "*")
    )
    |> validate_change(:transport, fn :transport, spec ->
      case TransportSpec.parse(spec) do
        {:ok, _} -> []
        :error -> [transport: "is not a valid transport, such as \"smtp:[relay.example.com]\""]
      end
    end)
    |> unique_constraint(:pattern)
  end
end
