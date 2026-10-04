defmodule Sovite.Core.Repo.Schemas.AccessRule do
  @moduledoc """
  An access rule for the restriction chains (`Sovite.Core.Restrictions`):
  when the client address, `EHLO` name, sender, or recipient (`kind`)
  matches `pattern`, take `action` (`ACCEPT`, `CONTINUE`, `REJECT`,
  `DEFER`, `DISCARD`, `HOLD`, `WARN`, or a `4NN`/`5NN` reply code) with
  optional `text`.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Sovite.Core.Repo.Data

  @actions ~w(ACCEPT CONTINUE REJECT DEFER DISCARD HOLD WARN)

  @type t :: %__MODULE__{}

  schema "access_rules" do
    field(:kind, Ecto.Enum, values: [:client, :helo, :sender, :recipient])
    field(:pattern, :string)
    field(:action, :string)
    field(:text, :string)
    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(rule, attrs) do
    rule
    |> cast(attrs, [:kind, :pattern, :action, :text])
    |> Data.fold_fields([:pattern])
    |> update_change(:action, &String.upcase(String.trim(&1)))
    |> validate_required([:kind, :pattern, :action])
    |> validate_length(:pattern, max: 320)
    |> validate_length(:text, max: 512)
    |> validate_format(:text, ~r/\A[^\r\n]*\z/, message: "must be one line")
    |> validate_change(:action, fn :action, action ->
      if action in @actions or String.match?(action, ~r/\A[45]\d\d\z/),
        do: [],
        else: [action: "must be one of #{Enum.join(@actions, ", ")}, or a 4NN/5NN reply code"]
    end)
    |> unique_constraint([:kind, :pattern])
  end
end
