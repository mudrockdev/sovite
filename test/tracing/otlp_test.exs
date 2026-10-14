defmodule Sovite.Tracing.OTLPTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias Sovite.Tracing.{OTLP, Span}

  @trace_id <<0x0123456789ABCDEF0123456789ABCDEF::128>>

  defp span(fields) do
    struct!(
      Span,
      [
        trace_id: @trace_id,
        span_id: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        name: "test",
        start_time: 1_700_000_000_000_000_000,
        end_time: 1_700_000_000_500_000_000
      ] ++ fields
    )
  end

  defp encode(spans, resource \\ %{"service.name" => "sovite"}, scope \\ "sovite"),
    do: spans |> OTLP.encode(resource, scope) |> JSON.decode!()

  defp spans(body) do
    [%{"scopeSpans" => [%{"spans" => spans}]}] = body["resourceSpans"]
    spans
  end

  test "encodes the resource and scope" do
    body = encode([span([])], %{"service.name" => "mx", host: "mx1"}, "scope")

    assert [%{"resource" => resource, "scopeSpans" => [%{"scope" => scope}]}] =
             body["resourceSpans"]

    assert resource["attributes"] == [
             %{"key" => "host", "value" => %{"stringValue" => "mx1"}},
             %{"key" => "service.name", "value" => %{"stringValue" => "mx"}}
           ]

    assert scope == %{"name" => "scope"}
  end

  test "encodes IDs as hex and times as decimal strings" do
    [root] = spans(encode([span([])]))

    assert root["traceId"] == "0123456789abcdef0123456789abcdef"
    assert root["spanId"] == "0102030405060708"
    assert root["startTimeUnixNano"] == "1700000000000000000"
    assert root["endTimeUnixNano"] == "1700000000500000000"
    refute Map.has_key?(root, "parentSpanId")
    refute Map.has_key?(root, "events")
    assert root["status"] == %{"code" => 0}

    [child] = spans(encode([span(parent_span_id: <<255, 0, 0, 0, 0, 0, 0, 1>>)]))
    assert child["parentSpanId"] == "ff00000000000001"
  end

  test "encodes kinds as integers" do
    kinds = [internal: 1, server: 2, client: 3, producer: 4, consumer: 5]

    for {kind, code} <- kinds do
      assert [%{"kind" => ^code}] = spans(encode([span(kind: kind)]))
    end
  end

  test "encodes the error status and events" do
    [json] =
      spans(
        encode([
          span(
            status: {:error, "550 rejected"},
            events: [%{name: "queued", time: 1_700_000_000_100_000_000, attributes: %{id: "Q1"}}]
          )
        ])
      )

    assert json["status"] == %{"code" => 2, "message" => "550 rejected"}

    assert json["events"] == [
             %{
               "name" => "queued",
               "timeUnixNano" => "1700000000100000000",
               "attributes" => [%{"key" => "id", "value" => %{"stringValue" => "Q1"}}]
             }
           ]
  end

  test "encodes attribute values by type" do
    attributes = %{
      string: "text",
      int: 42,
      big: 1 <<< 70,
      float: 1.5,
      bool: true,
      atom: :relay,
      ipv4: {192, 0, 2, 1},
      ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1},
      list: ["a", "b"],
      mixed: ["a", 1],
      binary: <<255, 254>>,
      tuple: {1, 2},
      skipped: nil
    }

    [json] = spans(encode([span(attributes: attributes)]))
    values = Map.new(json["attributes"], &{&1["key"], &1["value"]})

    assert values == %{
             "string" => %{"stringValue" => "text"},
             "int" => %{"intValue" => "42"},
             "big" => %{"stringValue" => Integer.to_string(1 <<< 70)},
             "float" => %{"doubleValue" => 1.5},
             "bool" => %{"boolValue" => true},
             "atom" => %{"stringValue" => "relay"},
             "ipv4" => %{"stringValue" => "192.0.2.1"},
             "ipv6" => %{"stringValue" => "2001:db8::1"},
             "list" => %{
               "arrayValue" => %{"values" => [%{"stringValue" => "a"}, %{"stringValue" => "b"}]}
             },
             "mixed" => %{"stringValue" => ~s(["a", 1])},
             "binary" => %{"stringValue" => "<<255, 254>>"},
             "tuple" => %{"stringValue" => "{1, 2}"}
           }

    assert Enum.map(json["attributes"], & &1["key"]) == Enum.sort(Map.keys(values))
  end
end
