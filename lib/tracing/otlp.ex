defmodule Sovite.Tracing.OTLP do
  @moduledoc false
  # The OTLP/JSON encoding of an export request (opentelemetry-proto,
  # ExportTraceServiceRequest). Per the OTLP/JSON rules, trace and span
  # IDs are lower-case hex, 64-bit integers (including nanosecond
  # timestamps) are decimal strings, and enums are integers.

  alias Sovite.Tracing.Span

  @kinds %{internal: 1, server: 2, client: 3, producer: 4, consumer: 5}

  @int64_min -0x8000000000000000
  @int64_max 0x7FFFFFFFFFFFFFFF

  @doc false
  @spec encode([Span.t()], map() | [{String.t() | atom(), term()}], String.t()) :: binary()
  def encode(spans, resource_attributes, scope) do
    JSON.encode!(%{
      "resourceSpans" => [
        %{
          "resource" => %{"attributes" => attributes(resource_attributes)},
          "scopeSpans" => [%{"scope" => %{"name" => scope}, "spans" => Enum.map(spans, &span/1)}]
        }
      ]
    })
  end

  defp span(%Span{} = span) do
    %{
      "traceId" => hex(span.trace_id),
      "spanId" => hex(span.span_id),
      "name" => span.name,
      "kind" => Map.fetch!(@kinds, span.kind),
      "startTimeUnixNano" => Integer.to_string(span.start_time),
      "endTimeUnixNano" => Integer.to_string(span.end_time),
      "attributes" => attributes(span.attributes),
      "status" => status(span.status)
    }
    |> put_parent(span.parent_span_id)
    |> put_events(span.events)
  end

  defp put_parent(json, nil), do: json
  defp put_parent(json, parent), do: Map.put(json, "parentSpanId", hex(parent))

  defp put_events(json, []), do: json

  defp put_events(json, events) do
    Map.put(
      json,
      "events",
      for event <- events do
        %{
          "timeUnixNano" => Integer.to_string(event.time),
          "name" => event.name,
          "attributes" => attributes(event.attributes)
        }
      end
    )
  end

  defp status({:error, message}), do: %{"code" => 2, "message" => message}
  defp status(nil), do: %{"code" => 0}

  defp hex(bytes), do: Base.encode16(bytes, case: :lower)

  @doc false
  @spec attributes(map() | [{String.t() | atom(), term()}]) :: [map()]
  def attributes(attributes) do
    attributes
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Enum.map(fn {key, value} -> {key(key), value} end)
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.map(fn {key, value} -> %{"key" => key, "value" => value(value)} end)
  end

  defp key(key) when is_binary(key), do: string(key)
  defp key(key) when is_atom(key), do: Atom.to_string(key)
  defp key(key), do: inspect(key)

  @doc false
  @spec value(term()) :: map()
  def value(value) when is_binary(value), do: %{"stringValue" => string(value)}
  def value(value) when is_boolean(value), do: %{"boolValue" => value}

  def value(value) when is_integer(value) and value >= @int64_min and value <= @int64_max,
    do: %{"intValue" => Integer.to_string(value)}

  def value(value) when is_integer(value), do: %{"stringValue" => Integer.to_string(value)}
  def value(value) when is_float(value), do: %{"doubleValue" => value}
  def value(value) when is_atom(value), do: %{"stringValue" => Atom.to_string(value)}

  def value(value) when is_tuple(value) and tuple_size(value) in [4, 8] do
    if :inet.is_ip_address(value),
      do: %{"stringValue" => List.to_string(:inet.ntoa(value))},
      else: %{"stringValue" => inspect(value)}
  end

  def value(value) when is_list(value) do
    if Enum.all?(value, &is_binary/1),
      do: %{"arrayValue" => %{"values" => Enum.map(value, &value/1)}},
      else: %{"stringValue" => inspect(value)}
  end

  def value(value), do: %{"stringValue" => inspect(value)}

  defp string(value), do: if(String.valid?(value), do: value, else: inspect(value))
end
