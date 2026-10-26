defmodule Sovite.Core.Config.FilterRules do
  @moduledoc false
  # Cross-key checks for [filter]: its rule files are read and compiled,
  # so a broken rule is a config error rather than a surprise at reload.

  alias Sovite.Core.Config.Error
  alias Sovite.Core.Filter.RuleFiles

  @spec errors(map()) :: [Error.t()]
  def errors(%{stack: %{filter: false}}), do: []

  def errors(values) do
    case RuleFiles.load(values.filter.rules, RuleFiles.flags()) do
      {:ok, _rules} ->
        []

      {:error, errors} ->
        for reason <- errors, do: %Error{path: ["filter", "rules"], reason: reason}
    end
  end
end
