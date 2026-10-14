defmodule Sovite.MetricsTest do
  use ExUnit.Case, async: true

  alias Sovite.Metrics

  # Telemetry handlers are global, so each test uses its own events.
  defp start(metrics, opts \\ []) do
    name = :"metrics_#{System.unique_integer([:positive])}"
    pid = start_supervised!({Metrics, [name: name, metrics: metrics] ++ opts})
    {name, pid}
  end

  defp family(name, metric), do: Enum.find(Metrics.collect(name), &(&1.name == metric))

  defp samples(name, metric), do: family(name, metric).samples

  test "counters count events by tag" do
    event = [:sovite_test, :metrics, :counter]

    {name, _pid} =
      start([
        Metrics.counter("commands_total", event: event, tags: [:command], help: "Commands."),
        Metrics.counter("events_total", event: event),
        Metrics.counter("idle_total", event: [:sovite_test, :metrics, :counter_idle]),
        Metrics.counter("idle_by_tag_total",
          event: [:sovite_test, :metrics, :counter_idle],
          tags: [:command]
        )
      ])

    for command <- ["MAIL", "EHLO", "EHLO", :quit],
        do: :telemetry.execute(event, %{}, %{command: command})

    assert family(name, "commands_total") == %{
             name: "commands_total",
             type: :counter,
             help: "Commands.",
             samples: [
               {%{"command" => "EHLO"}, 2},
               {%{"command" => "MAIL"}, 1},
               {%{"command" => "quit"}, 1}
             ]
           }

    assert samples(name, "events_total") == [{%{}, 4}]
    # An unlabeled counter reports 0; a labeled one has no series yet.
    assert samples(name, "idle_total") == [{%{}, 0}]
    assert samples(name, "idle_by_tag_total") == []
  end

  test "sums add up a measurement" do
    event = [:sovite_test, :metrics, :sum]

    {name, _pid} =
      start([
        Metrics.sum("bytes_total", event: event, measurement: :size),
        Metrics.sum("weight_total",
          event: event,
          measurement: fn measurements, _metadata -> measurements[:size] && 0.25 end
        )
      ])

    :telemetry.execute(event, %{size: 100}, %{})
    :telemetry.execute(event, %{size: 23}, %{})
    :telemetry.execute(event, %{size: "big"}, %{})
    :telemetry.execute(event, %{other: 1}, %{})

    assert samples(name, "bytes_total") == [{%{}, 123}]
    assert family(name, "weight_total").type == :counter
    assert samples(name, "weight_total") == [{%{}, 0.75}]
  end

  test "last values keep the latest measurement" do
    event = [:sovite_test, :metrics, :last_value]

    {name, _pid} =
      start([Metrics.last_value("queue_size", event: event, measurement: :size, tags: [:queue])])

    assert family(name, "queue_size") == %{
             name: "queue_size",
             type: :gauge,
             help: nil,
             samples: []
           }

    :telemetry.execute(event, %{size: 5}, %{queue: :active})
    :telemetry.execute(event, %{size: 2.5}, %{queue: :deferred})
    :telemetry.execute(event, %{size: 3}, %{queue: :active})

    assert samples(name, "queue_size") == [
             {%{"queue" => "active"}, 3},
             {%{"queue" => "deferred"}, 2.5}
           ]
  end

  test "distributions count values into buckets, in converted units" do
    event = [:sovite_test, :metrics, :distribution]

    {name, _pid} =
      start([
        Metrics.distribution("duration_seconds",
          event: event,
          measurement: :duration,
          unit: {:native, :second},
          buckets: [0.01, 0.1, 1, 10],
          tags: [:command]
        ),
        Metrics.distribution("duration_milliseconds",
          event: event,
          measurement: :duration,
          unit: {:native, :millisecond},
          buckets: [100]
        ),
        Metrics.distribution("size_bytes", event: event, measurement: :size, buckets: [10, 100])
      ])

    for {ms, size} <- [{5, 1}, {50, 10}, {500, 11}, {20_000, 1000}] do
      duration = System.convert_time_unit(ms, :millisecond, :native)
      :telemetry.execute(event, %{duration: duration, size: size}, %{command: "DATA"})
    end

    assert family(name, "duration_seconds") == %{
             name: "duration_seconds",
             type: :histogram,
             help: nil,
             samples: [
               {%{"command" => "DATA"},
                %{buckets: [{0.01, 1}, {0.1, 2}, {1, 3}, {10, 3}], sum: 20.555, count: 4}}
             ]
           }

    assert [{%{}, %{buckets: [{100, 2}], sum: 20_555.0, count: 4}}] =
             samples(name, "duration_milliseconds")

    assert samples(name, "size_bytes") == [
             {%{}, %{buckets: [{10, 2}, {100, 3}], sum: 1022, count: 4}}
           ]
  end

  test "keep filters events and tag_values derives labels" do
    event = [:sovite_test, :metrics, :keep]

    {name, _pid} =
      start([
        Metrics.counter("delivered_total",
          event: event,
          keep: &(&1.status == :sent),
          tag_values: fn %{to: to} -> %{domain: to |> String.split("@") |> List.last()} end,
          tags: [:domain]
        )
      ])

    :telemetry.execute(event, %{}, %{status: :sent, to: "a@example.com"})
    :telemetry.execute(event, %{}, %{status: :sent, to: "b@example.com"})
    :telemetry.execute(event, %{}, %{status: :bounced, to: "c@example.com"})
    :telemetry.execute(event, %{}, %{status: :sent, to: "d@example.org"})

    assert samples(name, "delivered_total") == [
             {%{"domain" => "example.com"}, 2},
             {%{"domain" => "example.org"}, 1}
           ]
  end

  test "label values are strings" do
    event = [:sovite_test, :metrics, :labels]

    {name, _pid} = start([Metrics.counter("labels_total", event: event, tags: [:value])])

    for value <- [<<255>>, {192, 0, 2, 1}, {0, 0, 0, 0, 0, 0, 0, 1}, 25, nil, {:a, 1}, 1.5],
        do: :telemetry.execute(event, %{}, %{value: value})

    labels = for {%{"value" => value}, 1} <- samples(name, "labels_total"), do: value

    assert Enum.sort(labels) ==
             Enum.sort(["<<255>>", "192.0.2.1", "::1", "25", "", "{:a, 1}", "1.5"])
  end

  test "a metric keeps at most max_series series" do
    event = [:sovite_test, :metrics, :max_series]

    {name, _pid} =
      start([
        Metrics.counter("clients_total", event: event, tags: [:ip], max_series: 2),
        Metrics.last_value("client_size",
          event: event,
          measurement: :size,
          tags: [:ip],
          max_series: 1
        )
      ])

    for ip <- ["a", "b", "c", "a", "d"], do: :telemetry.execute(event, %{size: 1}, %{ip: ip})

    assert samples(name, "clients_total") == [{%{"ip" => "a"}, 2}, {%{"ip" => "b"}, 1}]
    assert samples(name, "client_size") == [{%{"ip" => "a"}, 1}]

    assert family(name, "sovite_metrics_dropped_series_total") == %{
             name: "sovite_metrics_dropped_series_total",
             type: :counter,
             help: "Events not recorded because their metric had reached its series limit.",
             samples: [
               {%{"metric" => "client_size"}, 3},
               {%{"metric" => "clients_total"}, 2}
             ]
           }

    Metrics.reset(name)
    assert samples(name, "clients_total") == []
    assert family(name, "sovite_metrics_dropped_series_total") == nil

    :telemetry.execute(event, %{size: 1}, %{ip: "d"})
    assert samples(name, "clients_total") == [{%{"ip" => "d"}, 1}]
  end

  test "collectors add families, and broken ones are skipped" do
    family = %{name: "queue_messages", type: :gauge, help: nil, samples: [{%{}, 3}]}

    {name, _pid} =
      start([Metrics.counter("x_total", event: [:sovite_test, :metrics, :collectors])],
        collectors: [
          fn -> raise "broken" end,
          fn -> exit(:broken) end,
          fn -> throw(:broken) end,
          fn -> :not_a_list end,
          fn -> [family] end
        ]
      )

    assert Metrics.collect(name) == [
             %{name: "x_total", type: :counter, help: nil, samples: [{%{}, 0}]},
             family
           ]
  end

  test "bad measurements and metadata never detach the handler" do
    event = [:sovite_test, :metrics, :robust]

    {name, _pid} =
      start([
        Metrics.counter("robust_total",
          event: event,
          tags: [:command],
          tag_values: fn %{command: command} -> %{command: command} end
        ),
        Metrics.sum("robust_sum_total",
          event: event,
          measurement: fn %{size: size}, _metadata -> size * 2 end
        ),
        Metrics.counter("robust_keep_total", event: event, keep: fn %{keep: keep} -> keep end)
      ])

    :telemetry.execute(event, %{}, %{})
    :telemetry.execute(event, %{size: :big}, %{keep: :yes})
    assert [_handler] = :telemetry.list_handlers(event)

    :telemetry.execute(event, %{size: 2}, %{command: "RSET", keep: true})

    assert samples(name, "robust_total") == [{%{"command" => "RSET"}, 1}]
    assert samples(name, "robust_sum_total") == [{%{}, 4}]
    assert samples(name, "robust_keep_total") == [{%{}, 1}]
  end

  test "terminate/2 detaches the handlers" do
    events = [[:sovite_test, :metrics, :stop_a], [:sovite_test, :metrics, :stop_b]]
    metrics = for event <- events, do: Metrics.counter("#{List.last(event)}_total", event: event)
    {name, _pid} = start(metrics)

    assert Enum.all?(events, &(length(:telemetry.list_handlers(&1)) == 1))
    :ok = stop_supervised({Metrics, name})
    assert Enum.all?(events, &(:telemetry.list_handlers(&1) == []))
  end

  test "rejects invalid definitions" do
    event = [:sovite_test, :metrics, :invalid]

    assert_raise ArgumentError, ~r/invalid metric name/, fn ->
      Metrics.counter("bad-name", event: event)
    end

    assert_raise ArgumentError, ~r/invalid metric name/, fn ->
      Metrics.counter("1x", event: event)
    end

    assert_raise ArgumentError, ~r/:tags/, fn ->
      Metrics.counter("x", event: event, tags: [:"bad-label"])
    end

    assert_raise ArgumentError, ~r/:tags/, fn ->
      Metrics.counter("x", event: event, tags: [:__reserved])
    end

    assert_raise ArgumentError, ~r/:tags/, fn ->
      Metrics.distribution("x", event: event, measurement: :v, buckets: [1], tags: [:le])
    end

    assert_raise ArgumentError, ~r/distinct/, fn ->
      Metrics.counter("x", event: event, tags: [:a, :a])
    end

    assert_raise ArgumentError, ~r/unknown keys/, fn ->
      Metrics.counter("x", event: event, measurement: :size)
    end

    assert_raise ArgumentError, ~r/:measurement/, fn -> Metrics.sum("x", event: event) end
    assert_raise ArgumentError, ~r/:event/, fn -> Metrics.sum("x", measurement: :v) end

    assert_raise ArgumentError, ~r/:buckets/, fn ->
      Metrics.distribution("x", event: event, measurement: :v)
    end

    assert_raise ArgumentError, ~r/:buckets/, fn ->
      Metrics.distribution("x", event: event, measurement: :v, buckets: [1, 1])
    end

    assert_raise ArgumentError, ~r/:unit/, fn ->
      Metrics.sum("x", event: event, measurement: :v, unit: {:native, :hour})
    end

    assert_raise ArgumentError, ~r/:max_series/, fn ->
      Metrics.counter("x", event: event, max_series: 0)
    end

    assert_raise ArgumentError, ~r/duplicate metric "x"/, fn ->
      Metrics.start_link(
        name: :metrics_duplicate,
        metrics: [Metrics.counter("x", event: event), Metrics.counter("x", event: event)]
      )
    end

    assert_raise ArgumentError, ~r/:collectors/, fn ->
      Metrics.start_link(name: :metrics_collectors, collectors: [fn _ -> [] end])
    end
  end
end
