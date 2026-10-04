defmodule Sovite.Core.Repo.Schemas.SenderRelay do
  @moduledoc """
  How mail from `sender` (an address, or `@domain`) leaves: through
  `relayhost`, from `source_address`, logging in with `username` and
  `password`. Each part is optional.

  The password is stored as given, since it has to be sent to the relay
  host: protect the database accordingly.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Sovite.Core.Repo.Data
  alias Sovite.Core.Transport

  @type t :: %__MODULE__{}

  schema "sender_relays" do
    field(:sender, :string)
    field(:relayhost, :string)
    field(:source_address, :string)
    field(:username, :string)
    field(:password, :string, redact: true)
    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(relay, attrs) do
    relay
    |> cast(attrs, [:sender, :relayhost, :source_address, :username, :password])
    |> Data.fold_fields([:sender])
    |> validate_required([:sender])
    |> validate_length(:sender, max: 320)
    |> Data.validate_pattern(:sender, [:address, :catchall], ~s(must be an address or "@domain"))
    |> validate_change(:relayhost, fn :relayhost, host ->
      case Transport.parse_host(host, 25) do
        {:ok, _} -> []
        :error -> [relayhost: ~s(must be "host", "[host]", or "[host]:port")]
      end
    end)
    |> validate_change(:source_address, fn :source_address, value ->
      if source_address?(value),
        do: [],
        else: [source_address: "must be one IPv4 and/or one IPv6 address"]
    end)
    |> validate_format(:username, ~r/\A[^:\r\n]+\z/, message: "must not contain : or line breaks")
    |> unique_constraint(:sender)
  end

  defp source_address?(value) do
    ips = value |> String.split(~r/[\s,]+/, trim: true) |> Enum.map(&Sovite.Net.parse_ip/1)
    {v4, v6} = Enum.split_with(ips, &match?({:ok, ip} when tuple_size(ip) == 4, &1))

    ips != [] and Enum.all?(ips, &match?({:ok, _}, &1)) and length(v4) <= 1 and length(v6) <= 1
  end
end
