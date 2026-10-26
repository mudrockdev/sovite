defmodule Sovite.Test.MemoryTable do
  @moduledoc "A `Sovite.Core.MTA.Lookup` table held in a map, for tests. Keys are case-insensitive."

  @behaviour Sovite.Core.MTA.Lookup

  def new(map),
    do: {__MODULE__, Map.new(map, fn {key, value} -> {String.downcase(key), value} end)}

  @impl true
  def lookup(map, key), do: Map.fetch(map, String.downcase(key))
end
