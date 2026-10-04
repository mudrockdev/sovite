defmodule Sovite.Test.FakeDNS do
  @moduledoc """
  A `Sovite.DNS.Resolver` that answers from a static table passed in its
  options. It keeps no state, so concurrent tests can each use their own
  table.

      resolver =
        Sovite.Test.FakeDNS.resolver(%{
          {"example.com", :mx} => [{10, "mx.example.com"}],
          {"mx.example.com", :a} => [{192, 0, 2, 25}],
          {"down.example", :mx} => {:error, :servfail}
        })

      Sovite.DNS.lookup(resolver, "example.com", :mx)
      #=> {:ok, [{10, "mx.example.com"}]}

  Lookups are case-insensitive. A name with entries for other types gets
  NODATA (`{:ok, []}`), and a name with no entries at all gets
  `{:error, :nxdomain}`, matching real DNS.
  """

  @behaviour Sovite.DNS.Resolver

  @doc "Builds a `{module, opts}` resolver tuple for `records`."
  def resolver(records) do
    records = Map.new(records, fn {{name, type}, answer} -> {{normalize(name), type}, answer} end)
    {__MODULE__, records: records}
  end

  @impl true
  def lookup(name, type, opts) do
    records = Keyword.fetch!(opts, :records)
    name = normalize(name)

    case Map.fetch(records, {name, type}) do
      {:ok, {:error, _} = error} ->
        error

      {:ok, answers} ->
        {:ok, answers}

      :error ->
        if Enum.any?(Map.keys(records), &match?({^name, _}, &1)),
          do: {:ok, []},
          else: {:error, :nxdomain}
    end
  end

  defp normalize(name), do: name |> String.trim_trailing(".") |> String.downcase(:ascii)
end
