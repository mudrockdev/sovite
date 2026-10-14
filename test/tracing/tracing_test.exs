defmodule Sovite.TracingTest do
  # Each test starts its own instance on the same events, so the tests
  # of this module run one at a time; the event names are its own.
  use ExUnit.Case, async: true

  alias Sovite.Test.{FakeHTTP, TelemetryForwarder}
  alias Sovite.Tracing

  @session_start [:sovite_test, :tracing, :session, :start]
  @session_stop [:sovite_test, :tracing, :session, :stop]
  @command_start [:sovite_test, :tracing, :command, :start]
  @command_stop [:sovite_test, :tracing, :command, :stop]
  @command [:sovite_test, :tracing, :command]
  @delivery_start [:sovite_test, :tracing, :delivery, :start]
  @delivery_stop [:sovite_test, :tracing, :delivery, :stop]
  @delivery_exception [:sovite_test, :tracing, :delivery, :exception]
  @queued [:sovite_test, :tracing, :queued]

  @export_stop [:sovite, :tracing, :export, :stop]
  @export_error [:sovite, :tracing, :export, :error]
  @dropped [:sovite, :tracing, :spans, :dropped]
  @handler_error [:sovite, :tracing, :handler, :error]

  defp collector(status \\ 200) do
    test = self()

    {:ok, http} =
      FakeHTTP.start_link(fn request ->
        send(test, {:otlp, request, JSON.decode!(request.body)})
        {status, [], ""}
      end)

    FakeHTTP.url(http, "/v1/traces")
  end

  defp start_tracing(spans, opts \\ []) do
    name = :"tracing_test_#{System.unique_integer([:positive])}"
    endpoint = Keyword.get_lazy(opts, :endpoint, fn -> collector() end)
    opts = Keyword.merge([name: name, endpoint: endpoint, spans: spans, interval: 60_000], opts)
    start_supervised!({Tracing, opts})
    name
  end

  defp spans(body) do
    [%{"scopeSpans" => [%{"spans" => spans}]}] = body["resourceSpans"]
    spans
  end

  defp exported(name) do
    :ok = Tracing.flush(name)
    assert_receive {:otlp, _request, body}
    spans(body)
  end

  defp attribute(span, key),
    do: Enum.find_value(span["attributes"], fn attr -> attr["key"] == key && attr["value"] end)

  defp session(opts \\ []) do
    Tracing.span(
      "session",
      [start: @session_start, stop: @session_stop, kind: :server, attributes: [:id, :remote_ip]] ++
        opts
    )
  end

  defp command do
    Tracing.span(&"command #{&1.verb}",
      start: @command_start,
      stop: @command_stop,
      attributes: [:verb, :reply]
    )
  end

  defp emit(event, metadata \\ %{}, measurements \\ %{}),
    do: :telemetry.execute(event, measurements, metadata)

  test "a span started inside another is its child" do
    name =
      start_tracing([session(), command()],
        headers: [{"authorization", "Bearer token"}],
        service_name: "mx",
        resource: %{"host.name" => "mx1"}
      )

    emit(@session_start, %{id: "S1", remote_ip: {192, 0, 2, 1}})
    emit(@command_start, %{verb: "MAIL", reply: 0})
    emit(@command_stop, %{reply: 250})
    emit(@session_stop, %{id: "S1-stop"})

    :ok = Tracing.flush(name)
    assert_receive {:otlp, request, body}

    assert List.keyfind(request.headers, "content-type", 0) ==
             {"content-type", "application/json"}

    assert List.keyfind(request.headers, "authorization", 0) == {"authorization", "Bearer token"}

    [%{"resource" => resource}] = body["resourceSpans"]

    assert %{"key" => "service.name", "value" => %{"stringValue" => "mx"}} in resource[
             "attributes"
           ]

    assert %{"key" => "host.name", "value" => %{"stringValue" => "mx1"}} in resource["attributes"]

    [command, session] = spans(body)

    assert session["name"] == "session"
    assert session["kind"] == 2
    refute Map.has_key?(session, "parentSpanId")
    assert attribute(session, "id") == %{"stringValue" => "S1-stop"}
    assert attribute(session, "remote_ip") == %{"stringValue" => "192.0.2.1"}

    assert command["name"] == "command MAIL"
    assert command["kind"] == 1
    assert command["traceId"] == session["traceId"]
    assert command["parentSpanId"] == session["spanId"]
    assert attribute(command, "reply") == %{"intValue" => "250"}
    assert String.length(session["traceId"]) == 32
    assert String.length(session["spanId"]) == 16
    assert session["startTimeUnixNano"] <= command["startTimeUnixNano"]
  end

  test "an event span lasts its duration, inside the open span" do
    name =
      start_tracing([
        session(),
        Tracing.event_span(&"smtp #{&1.verb}",
          event: @command,
          attributes: &%{"verb" => &1.verb},
          error: fn meta -> if meta.code >= 500, do: "#{meta.code} rejected" end
        )
      ])

    duration = System.convert_time_unit(5, :millisecond, :native)
    emit(@session_start, %{id: "S2"})
    emit(@command, %{verb: "RCPT", code: 550}, %{duration: duration})
    emit(@session_stop)
    emit(@command, %{verb: "QUIT", code: 221})

    [rcpt, session, quit] = exported(name)

    assert rcpt["name"] == "smtp RCPT"
    assert rcpt["parentSpanId"] == session["spanId"]
    assert rcpt["traceId"] == session["traceId"]
    assert attribute(rcpt, "verb") == %{"stringValue" => "RCPT"}

    assert String.to_integer(rcpt["endTimeUnixNano"]) -
             String.to_integer(rcpt["startTimeUnixNano"]) == 5_000_000

    assert rcpt["status"] == %{"code" => 2, "message" => "550 rejected"}

    assert quit["startTimeUnixNano"] == quit["endTimeUnixNano"]
    refute Map.has_key?(quit, "parentSpanId")
    assert quit["traceId"] != session["traceId"]
    assert quit["status"] == %{"code" => 0}
  end

  test "a span event is added to the open span" do
    name =
      start_tracing([
        session(),
        Tracing.span_event("queued", event: @queued, attributes: [:queue_id])
      ])

    emit(@queued, %{queue_id: "Q0"})
    emit(@session_start, %{id: "S3"})
    emit(@queued, %{queue_id: "Q1"})
    emit(@session_stop)

    assert [%{"events" => [event]}] = exported(name)
    assert event["name"] == "queued"
    assert event["attributes"] == [%{"key" => "queue_id", "value" => %{"stringValue" => "Q1"}}]
    assert is_binary(event["timeUnixNano"])
  end

  test "an exception event closes the span with an error" do
    name =
      start_tracing([
        Tracing.span("delivery",
          start: @delivery_start,
          stop: @delivery_stop,
          exception: @delivery_exception,
          kind: :client
        )
      ])

    emit(@delivery_start)
    emit(@delivery_exception, %{kind: :error, reason: %RuntimeError{message: "boom"}})
    emit(@delivery_start)
    emit(@delivery_exception, %{kind: :exit, reason: :timeout})
    emit(@delivery_start)
    emit(@delivery_exception, %{kind: :throw})

    assert [first, second, third] = exported(name)
    assert first["kind"] == 3
    assert first["status"] == %{"code" => 2, "message" => "boom"}
    assert second["status"] == %{"code" => 2, "message" => ":timeout"}
    assert third["status"] == %{"code" => 2, "message" => "throw"}
  end

  test "stop events with no open span are ignored" do
    name = start_tracing([session()])

    emit(@session_stop)
    emit(@session_start, %{id: "S4"})
    emit(@session_stop)
    emit(@session_stop)
    emit(@session_stop)

    assert [%{"name" => "session"}] = exported(name)
    refute_receive {:otlp, _, _}, 100
  end

  test "the span context matches stop events to their start" do
    name = start_tracing([session(), command()])

    outer = make_ref()
    emit(@session_start, %{id: "outer", telemetry_span_context: outer})
    emit(@session_start, %{id: "inner", telemetry_span_context: make_ref()})
    emit(@command_start, %{verb: "DATA"})
    emit(@session_stop, %{telemetry_span_context: make_ref()})
    emit(@session_stop, %{telemetry_span_context: outer})

    spans = exported(name)
    assert Enum.map(spans, & &1["name"]) == ["command DATA", "session", "session"]
    [command, inner, outer] = spans
    assert attribute(inner, "id") == %{"stringValue" => "inner"}
    assert attribute(outer, "id") == %{"stringValue" => "outer"}
    assert command["parentSpanId"] == inner["spanId"]
    assert inner["parentSpanId"] == outer["spanId"]
    assert inner["endTimeUnixNano"] == outer["endTimeUnixNano"]
    assert inner["status"] == %{"code" => 0}
  end

  test "a trace ID from a key is the same in every process" do
    name =
      start_tracing([
        Tracing.span("delivery",
          start: @delivery_start,
          stop: @delivery_stop,
          trace_id: & &1[:queue_id],
          attributes: [:relay]
        )
      ])

    for relay <- ["mx1", "mx2"] do
      Task.async(fn ->
        emit(@delivery_start, %{queue_id: "Q42", relay: relay})
        emit(@delivery_stop)
      end)
      |> Task.await()
    end

    [first, second] = exported(name)
    <<expected::binary-size(16), _::binary>> = :crypto.hash(:sha256, "Q42")
    assert first["traceId"] == Base.encode16(expected, case: :lower)
    assert second["traceId"] == first["traceId"]
    assert first["spanId"] != second["spanId"]
  end

  test "nothing is exported with a sample ratio of 0" do
    name =
      start_tracing([session(), command(), Tracing.event_span("command", event: @command)],
        sample_ratio: 0.0
      )

    emit(@session_start)
    emit(@command_start, %{verb: "EHLO"})
    emit(@command)
    emit(@command_stop)
    emit(@session_stop)

    assert Tracing.flush(name) == :ok
    refute_receive {:otlp, _, _}, 100
  end

  test "a full batch is exported without waiting for the interval" do
    TelemetryForwarder.attach([@export_stop])
    name = start_tracing([Tracing.event_span("command", event: @command)], batch_size: 3)

    for _ <- 1..3, do: emit(@command)

    assert_receive {:otlp, _request, body}
    assert length(spans(body)) == 3
    assert_receive {:telemetry, @export_stop, %{spans: 3, duration: duration}, %{name: ^name}}
    assert is_integer(duration)
  end

  test "spans are exported every interval" do
    _name = start_tracing([Tracing.event_span("command", event: @command)], interval: 50)

    emit(@command)
    assert_receive {:otlp, _request, body}, 1_000
    assert [%{"name" => "command"}] = spans(body)
  end

  test "spans over the queue limit are dropped and counted" do
    TelemetryForwarder.attach([@dropped])

    name =
      start_tracing([Tracing.event_span("command", event: @command)], max_queue: 2, interval: 50)

    :sys.suspend(name)
    for _ <- 1..5, do: emit(@command)
    :sys.resume(name)

    assert_receive {:telemetry, @dropped, %{spans: 3}, %{name: ^name}}, 1_000
    assert_receive {:otlp, _request, body}, 1_000
    assert length(spans(body)) == 2
  end

  test "a failed export is reported and the batch dropped" do
    TelemetryForwarder.attach([@export_error])

    name =
      start_tracing([Tracing.event_span("command", event: @command)], endpoint: collector(500))

    emit(@command)
    assert Tracing.flush(name) == :ok
    assert_receive {:otlp, _, _}
    assert_receive {:telemetry, @export_error, %{spans: 1}, %{name: ^name, reason: reason}}
    assert reason == {:http_status, 500}

    emit(@command)
    assert Tracing.flush(name) == :ok
    assert_receive {:telemetry, @export_error, %{spans: 1}, %{name: ^name}}
  end

  test "an unreachable collector is reported" do
    TelemetryForwarder.attach([@export_error])
    {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)

    name =
      start_tracing([Tracing.event_span("command", event: @command)],
        endpoint: "http://127.0.0.1:#{port}/v1/traces"
      )

    emit(@command)
    assert Tracing.flush(name) == :ok
    assert_receive {:telemetry, @export_error, %{spans: 1}, %{name: ^name, reason: reason}}
    assert {:failed_connect, _} = reason
    assert Process.alive?(Process.whereis(name))
  end

  test "stopping exports the remaining spans and detaches the handlers" do
    name = start_tracing([session()])

    emit(@session_start, %{id: "S5"})
    emit(@session_stop)
    :ok = stop_supervised({Tracing, name})

    assert_receive {:otlp, _request, body}
    assert [%{"name" => "session"}] = spans(body)

    emit(@session_start)
    emit(@session_stop)
    assert :telemetry.list_handlers(@session_start) == []
  end

  test "a definition that raises skips the event and stays attached" do
    TelemetryForwarder.attach([@handler_error])

    name =
      start_tracing([
        Tracing.event_span("command", event: @command, attributes: &%{"verb" => &1.verb})
      ])

    emit(@command)

    assert_receive {:telemetry, @handler_error, %{},
                    %{name: ^name, event: @command, kind: :error}}

    emit(@command, %{verb: "NOOP"})
    assert [span] = exported(name)
    assert attribute(span, "verb") == %{"stringValue" => "NOOP"}
  end

  test "keep skips events" do
    name =
      start_tracing([
        Tracing.event_span("command", event: @command, keep: &(&1[:verb] == "NOOP"))
      ])

    emit(@command, %{verb: "QUIT"})
    emit(@command, %{verb: "NOOP"})
    assert [_span] = exported(name)
  end

  test "options are validated" do
    assert_raise ArgumentError, ~r/:endpoint/, fn -> Tracing.start_link(name: :tracing_x) end

    assert_raise ArgumentError, ~r/:sample_ratio/, fn ->
      Tracing.start_link(name: :tracing_x, endpoint: "http://localhost/", sample_ratio: 2)
    end

    assert_raise ArgumentError, ~r/:kind/, fn ->
      Tracing.span("x", start: @session_start, stop: @session_stop, kind: :other)
    end

    assert_raise ArgumentError, ~r/:stop/, fn -> Tracing.span("x", start: @session_start) end
    assert_raise ArgumentError, fn -> Tracing.span_event("x", event: @queued, kind: :client) end
  end
end
