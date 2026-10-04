defmodule Sovite.Core.Repo.Schemas.User do
  @moduledoc """
  A user who can authenticate (SMTP AUTH), with the sender addresses
  they may use.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Sovite.SASL.Password

  @type t :: %__MODULE__{}

  schema "users" do
    field(:username, :string)
    field(:password_hash, :string, redact: true)
    field(:enabled, :boolean, default: true)
    has_many(:sender_logins, Sovite.Core.Repo.Schemas.SenderLogin)
    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(user, attrs) do
    user
    |> cast(attrs, [:username, :password_hash, :enabled])
    |> update_change(:username, &normalize/1)
    |> validate_required([:username, :password_hash])
    |> validate_length(:username, max: 320)
    |> validate_format(:username, ~r/\A[^\s:\x00-\x1f]+\z/,
      message: "must not contain spaces, colons, or control characters"
    )
    |> validate_change(:password_hash, fn :password_hash, hash ->
      if Password.supported?(hash), do: [], else: [password_hash: "is not a supported hash"]
    end)
    |> unique_constraint(:username)
  end

  @doc "User names are compared case-insensitively."
  @spec normalize(String.t()) :: String.t()
  def normalize(username), do: username |> String.trim() |> String.downcase()
end
