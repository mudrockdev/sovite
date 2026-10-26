defmodule Sovite.Test.FailingTable do
  @moduledoc "A `Sovite.Core.MTA.Lookup` table that always fails, for testing temporary errors."

  @behaviour Sovite.Core.MTA.Lookup

  def new, do: {__MODULE__, nil}

  @impl true
  def lookup(_handle, _key), do: {:error, :down}
end
