defmodule Sovite.Core.Users.SenderLogin do
  @moduledoc """
  A sender address a user may use in `MAIL FROM`: a full address
  (`sales@example.com`), every address at a domain (`@example.com`), or
  any address (`*`).
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Sovite.Core.SenderCheck

  @type t :: %__MODULE__{}

  schema "sender_logins" do
    # A plain field, not belongs_to: the schemas must not depend on each other.
    field :user_id, :id
    field(:address, :string)
    timestamps(type: :utc_datetime, updated_at: false)
  end

  @doc false
  def changeset(login, attrs) do
    login
    |> cast(attrs, [:address])
    |> update_change(:address, &String.downcase(String.trim(&1), :ascii))
    |> validate_required([:address])
    |> validate_change(:address, fn :address, address ->
      if SenderCheck.valid_pattern?(address),
        do: [],
        else: [address: ~s(must be an address, "@domain", or "*")]
    end)
    |> unique_constraint([:user_id, :address])
  end
end
