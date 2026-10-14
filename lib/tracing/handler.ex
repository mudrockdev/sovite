defmodule Sovite.Tracing.Handler do
  @moduledoc false
  # The telemetry handlers. They run in the process that emits the
  # event, so the spans open in a process are kept in its process
  # dictionary, as a stack (innermost first) under the instance's key.
  # Finished, sampled spans are cast to the exporter.

  alias Sovite.Tracing.{Definition, Span}

  # Bounds on what a process holds, for processes that open spans and
  # never close them.
  @max_depth 64
  @max_events 128

  @typedoc "The handler config: the role of the event, its definition, and the instance."
  @type config :: {atom(), Definition.t(), %{name: atom(), threshold: non_neg_integer()}}

  @doc false
  @spec attach(atom(), [Definition.t()], non_neg_integer()) :: [term()]
  def attach(name, definitions, threshold) do
    instance = %{name: name, threshold: threshold}

    for definition <- definitions, {role, event} <- Definition.event_names(definition) do
      id = {__MODULE__, name, definition.id, role}
      config = {role, definition, instance}

      # A handler left behind by an exporter that was killed.
      with {:error, :already_exists} <- attach_handler(id, event, config) do
        :telemetry.detach(id)
        attach_handler(id, event, config)
      end

      id
    end
  end

  defp attach_handler(id, event, config),
    do: :telemetry.attach(id, event, &__MODULE__.handle_event/4, config)

  @doc false
  @spec detach([term()]) :: :ok
  def detach(ids), do: Enum.each(ids, &:telemetry.detach/1)

  @doc false
  @spec handle_event(:telemetry.event_name(), map(), map(), config()) :: :ok
  def handle_event(event, measurements, metadata, {role, definition, instance}) do
    handle(role, measurements, metadata, definition, instance)
    :ok
  catch
    # A handler that raises is detached by telemetry, so nothing may
    # escape.
    kind, reason ->
      unless match?([:sovite, :tracing | _], event) do
        :telemetry.execute([:sovite, :tracing, :handler, :error], %{}, %{
          name: instance.name,
          event: event,
          kind: kind,
          reason: reason
        })
      end

      :ok
  end

  defp handle(:start, _measurements, metadata, definition, instance) do
    if keep?(definition, metadata) do
      stack = stack(instance.name)
      {trace_id, parent_span_id, sampled} = context(stack, definition, metadata, instance)

      entry = %{
        definition: definition,
        context: metadata[:telemetry_span_context],
        trace_id: trace_id,
        span_id: span_id(),
        parent_span_id: parent_span_id,
        sampled: sampled,
        start_time: System.os_time(:nanosecond),
        metadata: start_metadata(definition, metadata),
        events: [],
        event_count: 0
      }

      put_stack(instance.name, Enum.take([entry | stack], @max_depth))
    end
  end

  defp handle(:stop, _measurements, metadata, definition, instance),
    do: close(definition, metadata, instance, nil)

  defp handle(:exception, _measurements, metadata, definition, instance),
    do: close(definition, metadata, instance, {:error, exception_message(metadata)})

  defp handle(:event_span, measurements, metadata, definition, instance) do
    if keep?(definition, metadata) do
      {trace_id, parent_span_id, sampled} =
        context(stack(instance.name), definition, metadata, instance)

      if sampled do
        end_time = System.os_time(:nanosecond)

        start_time = end_time - duration(measurements[definition.duration])

        export(instance, %Span{
          trace_id: trace_id,
          span_id: span_id(),
          parent_span_id: parent_span_id,
          name: name(definition, metadata),
          kind: definition.kind,
          start_time: start_time,
          end_time: end_time,
          attributes: attributes(definition, metadata),
          status: error(definition, metadata)
        })
      end
    end
  end

  defp handle(:span_event, _measurements, metadata, definition, instance) do
    case stack(instance.name) do
      [%{sampled: true, event_count: count} = top | rest] when count < @max_events ->
        if keep?(definition, metadata) do
          event = %{
            name: name(definition, metadata),
            time: System.os_time(:nanosecond),
            attributes: attributes(definition, metadata)
          }

          top = %{top | events: [event | top.events], event_count: count + 1}
          put_stack(instance.name, [top | rest])
        end

      _ ->
        :ok
    end
  end

  defp duration(duration) when is_integer(duration) and duration > 0,
    do: System.convert_time_unit(duration, :native, :nanosecond)

  defp duration(_duration), do: 0

  # Closes the innermost open span of the definition; spans opened
  # above it and never closed end with it. A stop with no open span,
  # such as a second stop for the same start, is ignored.
  defp close(definition, metadata, instance, status) do
    stack = stack(instance.name)
    context = metadata[:telemetry_span_context]

    case Enum.split_while(stack, &(not open?(&1, definition, context))) do
      {_stack, []} ->
        :ok

      {above, [entry | below]} ->
        put_stack(instance.name, below)
        end_time = System.os_time(:nanosecond)

        for unclosed <- above,
            unclosed.sampled,
            do: export(instance, finish(unclosed, %{}, end_time, nil))

        if entry.sampled do
          status = status || error(definition, Map.merge(entry.metadata, metadata))
          export(instance, finish(entry, metadata, end_time, status))
        end
    end
  end

  defp open?(entry, definition, context) do
    entry.definition.id == definition.id and
      (is_nil(context) or is_nil(entry.context) or entry.context == context)
  end

  defp finish(entry, stop_metadata, end_time, status) do
    metadata = Map.merge(entry.metadata, stop_metadata)

    %Span{
      trace_id: entry.trace_id,
      span_id: entry.span_id,
      parent_span_id: entry.parent_span_id,
      name: name(entry.definition, metadata),
      kind: entry.definition.kind,
      start_time: entry.start_time,
      end_time: end_time,
      attributes: attributes(entry.definition, metadata),
      events: Enum.reverse(entry.events),
      status: status
    }
  end

  defp export(instance, span), do: GenServer.cast(instance.name, {:span, span})

  # Only what the definition can use is kept until the stop event.
  defp start_metadata(%Definition{attributes: keys} = definition, metadata) when is_list(keys) do
    if is_function(definition.name) or is_function(definition.error),
      do: metadata,
      else: Map.take(metadata, keys)
  end

  defp start_metadata(_definition, metadata), do: metadata

  defp context([parent | _], _definition, _metadata, _instance),
    do: {parent.trace_id, parent.span_id, parent.sampled}

  defp context([], definition, metadata, instance) do
    trace_id = trace_id(definition, metadata)
    {trace_id, nil, sampled?(trace_id, instance.threshold)}
  end

  defp keep?(%Definition{keep: nil}, _metadata), do: true
  defp keep?(%Definition{keep: keep}, metadata), do: keep.(metadata) == true

  defp name(%Definition{name: name}, _metadata) when is_binary(name), do: name
  defp name(%Definition{name: name}, metadata), do: to_string(name.(metadata))

  defp attributes(%Definition{attributes: keys}, metadata) when is_list(keys),
    do: Map.take(metadata, keys)

  defp attributes(%Definition{attributes: fun}, metadata) do
    case fun.(metadata) do
      %{} = attributes -> attributes
      _ -> %{}
    end
  end

  defp error(%Definition{error: nil}, _metadata), do: nil

  defp error(%Definition{error: fun}, metadata) do
    case fun.(metadata) do
      nil -> nil
      message when is_binary(message) -> {:error, message}
      other -> {:error, inspect(other)}
    end
  end

  defp exception_message(metadata) do
    case {metadata[:reason], metadata[:kind]} do
      {nil, nil} -> "exception"
      {nil, kind} -> to_string(kind)
      {reason, _kind} when is_exception(reason) -> Exception.message(reason)
      {reason, _kind} -> inspect(reason)
    end
  end

  defp stack(name), do: Process.get({__MODULE__, name}, [])

  defp put_stack(name, []), do: Process.delete({__MODULE__, name})
  defp put_stack(name, stack), do: Process.put({__MODULE__, name}, stack)

  ## IDs and sampling

  defp trace_id(%Definition{trace_id: nil}, _metadata), do: random_id(16)

  defp trace_id(%Definition{trace_id: fun}, metadata) do
    case fun.(metadata) do
      key when is_binary(key) -> trace_id(key)
      _ -> random_id(16)
    end
  end

  @doc false
  @spec trace_id(String.t()) :: <<_::128>>
  def trace_id(key) do
    case :crypto.hash(:sha256, key) do
      <<0::128, _::binary>> -> random_id(16)
      <<id::binary-size(16), _::binary>> -> id
    end
  end

  defp span_id, do: random_id(8)

  defp random_id(size) do
    id = :crypto.strong_rand_bytes(size)
    if id == :binary.copy(<<0>>, size), do: random_id(size), else: id
  end

  # TraceIdRatioBased: the lower 8 bytes of the trace ID, compared with
  # the ratio of 2^64, so a trace ID is always sampled the same way.
  @doc false
  @spec threshold(float()) :: non_neg_integer()
  def threshold(ratio), do: trunc(ratio * 18_446_744_073_709_551_616)

  defp sampled?(<<_::64, low::unsigned-64>>, threshold), do: low < threshold
end
