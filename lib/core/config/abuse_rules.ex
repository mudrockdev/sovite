defmodule Sovite.Core.Config.AbuseRules do
  @moduledoc false
  # Defaults and cross-key checks for [screen], [greylist], [rate_limit],
  # and [outbound].

  alias Sovite.Core.Config.Error

  @spec defaults(map()) :: map()
  def defaults(values) do
    # An early talker alone is refused unless told otherwise.
    update_in(values.screen.early_talker_weight, &(&1 || values.screen.threshold))
  end

  @spec errors(map()) :: [Error.t() | false]
  def errors(values) do
    greylist = values.greylist

    [
      greylist.delay >= greylist.retry_window &&
        %Error{path: ["greylist", "retry_window"], reason: "must be longer than greylist.delay"}
    ]
  end
end
