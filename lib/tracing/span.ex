defmodule Sovite.Tracing.Span do
  @moduledoc false
  # A finished span, as the handlers send it to the exporter. IDs are raw
  # bytes and times nanoseconds since the epoch; attribute values are
  # still Elixir terms, converted by `Sovite.Tracing.OTLP`.

  @type event :: %{name: String.t(), time: integer(), attributes: map()}

  @type t :: %__MODULE__{
          trace_id: <<_::128>>,
          span_id: <<_::64>>,
          parent_span_id: <<_::64>> | nil,
          name: String.t(),
          kind: :internal | :server | :client | :producer | :consumer,
          start_time: integer(),
          end_time: integer(),
          attributes: map(),
          events: [event()],
          status: nil | {:error, String.t()}
        }

  @enforce_keys [:trace_id, :span_id, :name, :start_time, :end_time]
  defstruct [
    :trace_id,
    :span_id,
    :parent_span_id,
    :name,
    :start_time,
    :end_time,
    :status,
    kind: :internal,
    attributes: %{},
    events: []
  ]
end
