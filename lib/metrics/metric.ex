defmodule Sovite.Metrics.Metric do
  @moduledoc """
  A metric definition, built by `Sovite.Metrics.counter/2`,
  `Sovite.Metrics.sum/2`, `Sovite.Metrics.last_value/2` or
  `Sovite.Metrics.distribution/2`. See `Sovite.Metrics` for the options.
  """

  @enforce_keys [:type, :name, :event]
  defstruct [
    :type,
    :name,
    :event,
    :measurement,
    :tag_values,
    :keep,
    :help,
    :unit,
    :buckets,
    tags: [],
    max_series: 1000
  ]

  @typedoc "The kind of metric."
  @type type :: :counter | :sum | :last_value | :distribution

  @type t :: %__MODULE__{
          type: type(),
          name: String.t(),
          event: :telemetry.event_name(),
          measurement: atom() | (map(), map() -> number() | nil) | nil,
          tags: [atom()],
          tag_values: (map() -> map()) | nil,
          keep: (map() -> boolean()) | nil,
          help: String.t() | nil,
          unit: {:native, :second | :millisecond | :microsecond} | nil,
          buckets: [number()] | nil,
          max_series: pos_integer()
        }
end
