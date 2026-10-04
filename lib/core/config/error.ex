defmodule Sovite.Core.Config.Error do
  @moduledoc """
  A single configuration problem.

  `path` is the list of keys leading to the bad value, for example
  `["queue", "directory"]`. It is empty for file-level problems such as a
  missing file or a TOML syntax error.
  """

  defexception path: [], reason: ""

  @type t :: %__MODULE__{path: [String.t()], reason: String.t()}

  @impl true
  def message(%__MODULE__{path: [], reason: reason}), do: reason
  def message(%__MODULE__{path: path, reason: reason}), do: Enum.join(path, ".") <> ": " <> reason
end
