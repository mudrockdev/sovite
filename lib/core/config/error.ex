defmodule Sovite.Core.Config.Error do
  @moduledoc """
  A single configuration problem.

  `path` is the list of keys leading to the bad value, for example
  `["queue", "directory"]`, or `["listener", "[0]", "port"]` inside an
  array. It is empty for file-level problems such as a missing file or a
  TOML syntax error.
  """

  defexception path: [], reason: ""

  @type t :: %__MODULE__{path: [String.t()], reason: String.t()}

  @impl true
  def message(%__MODULE__{path: [], reason: reason}), do: reason
  def message(%__MODULE__{path: path, reason: reason}), do: format_path(path) <> ": " <> reason

  # Array indexes attach to their key: "listener[0].port".
  defp format_path(path) do
    path
    |> Enum.with_index()
    |> Enum.map_join(fn
      {"[" <> _ = index, _position} -> index
      {key, 0} -> key
      {key, _position} -> "." <> key
    end)
  end
end
