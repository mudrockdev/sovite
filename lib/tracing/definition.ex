defmodule Sovite.Tracing.Definition do
  @moduledoc false
  # What `Sovite.Tracing.span/2`, `event_span/2` and `span_event/2`
  # return: which events to handle and how to turn their metadata into a
  # span. `:id` is set by the exporter, so `stop` events can find the
  # spans their own definition opened.

  @kinds [:internal, :server, :client, :producer, :consumer]

  @type name :: String.t() | (map() -> String.t())

  @type t :: %__MODULE__{
          type: :span | :event_span | :span_event,
          id: non_neg_integer() | nil,
          name: name(),
          start: :telemetry.event_name() | nil,
          stop: :telemetry.event_name() | nil,
          exception: :telemetry.event_name() | nil,
          event: :telemetry.event_name() | nil,
          kind: :internal | :server | :client | :producer | :consumer,
          attributes: [atom()] | (map() -> map()),
          error: (map() -> String.t() | nil) | nil,
          trace_id: (map() -> String.t() | nil) | nil,
          keep: (map() -> boolean()) | nil,
          duration: atom()
        }

  defstruct [
    :type,
    :id,
    :name,
    :start,
    :stop,
    :exception,
    :event,
    :error,
    :trace_id,
    :keep,
    kind: :internal,
    attributes: [],
    duration: :duration
  ]

  @shared [:kind, :attributes, :error, :trace_id, :keep]

  @doc false
  @spec new(:span | :event_span | :span_event, name(), keyword()) :: t()
  def new(type, name, opts) do
    opts = Keyword.validate!(opts, allowed(type))
    check_name!(name)

    definition = struct!(__MODULE__, [type: type, name: name] ++ opts)

    for key <- events(type), do: check_event!(key, Map.fetch!(definition, key))
    if definition.exception, do: check_event!(:exception, definition.exception)

    check_kind!(definition.kind)
    check_attributes!(definition.attributes)
    for key <- [:error, :trace_id, :keep], do: check_fun!(key, Map.fetch!(definition, key))

    unless is_atom(definition.duration),
      do: raise(ArgumentError, ":duration must be an atom, got: #{inspect(definition.duration)}")

    definition
  end

  @doc false
  @spec event_names(t()) :: [{atom(), :telemetry.event_name()}]
  def event_names(%__MODULE__{type: :span} = definition) do
    [start: definition.start, stop: definition.stop, exception: definition.exception]
    |> Enum.reject(fn {_role, event} -> is_nil(event) end)
  end

  def event_names(%__MODULE__{type: :event_span, event: event}), do: [event_span: event]
  def event_names(%__MODULE__{type: :span_event, event: event}), do: [span_event: event]

  defp allowed(:span), do: [:start, :stop, :exception] ++ @shared
  defp allowed(:event_span), do: [:event, :duration] ++ @shared
  defp allowed(:span_event), do: [:event, :attributes, :keep]

  defp events(:span), do: [:start, :stop]
  defp events(_type), do: [:event]

  defp check_name!(name) when is_binary(name) or is_function(name, 1), do: :ok

  defp check_name!(name),
    do: raise(ArgumentError, "name must be a string or a 1-arity function, got: #{inspect(name)}")

  defp check_event!(key, [_ | _] = event) do
    if Enum.all?(event, &is_atom/1), do: :ok, else: invalid_event!(key, event)
  end

  defp check_event!(key, event), do: invalid_event!(key, event)

  defp invalid_event!(key, event),
    do: raise(ArgumentError, "#{inspect(key)} must be an event name, got: #{inspect(event)}")

  defp check_kind!(kind) when kind in @kinds, do: :ok

  defp check_kind!(kind),
    do: raise(ArgumentError, ":kind must be one of #{inspect(@kinds)}, got: #{inspect(kind)}")

  defp check_attributes!(fun) when is_function(fun, 1), do: :ok

  defp check_attributes!(keys) when is_list(keys) do
    if Enum.all?(keys, &is_atom/1), do: :ok, else: invalid_attributes!(keys)
  end

  defp check_attributes!(other), do: invalid_attributes!(other)

  defp invalid_attributes!(value) do
    raise ArgumentError,
          ":attributes must be a list of atoms or a 1-arity function, got: #{inspect(value)}"
  end

  defp check_fun!(_key, nil), do: :ok
  defp check_fun!(_key, fun) when is_function(fun, 1), do: :ok

  defp check_fun!(key, value),
    do: raise(ArgumentError, "#{inspect(key)} must be a 1-arity function, got: #{inspect(value)}")
end
