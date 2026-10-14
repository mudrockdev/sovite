defmodule Sovite.Metrics.PrometheusTest do
  use ExUnit.Case, async: true

  alias Sovite.Metrics
  alias Sovite.Metrics.Prometheus

  doctest Prometheus

  defp format(families), do: families |> Prometheus.format() |> IO.iodata_to_binary()

  test "formats counters, gauges and histograms" do
    families = [
      %{
        name: "smtp_commands_total",
        type: :counter,
        help: "Commands with a \\ and\na newline.",
        samples: [
          {%{"command" => "EHLO", "listener" => "smtp"}, 2},
          {%{"command" => "say \"hi\"\\\n"}, 1}
        ]
      },
      %{name: "queue_size", type: :gauge, help: nil, samples: [{%{}, 2.5}]},
      %{name: "empty", type: :gauge, help: "Nothing yet.", samples: []},
      %{
        name: "duration_seconds",
        type: :histogram,
        help: "Durations.",
        samples: [
          {%{"command" => "DATA"},
           %{buckets: [{0.01, 1}, {0.1, 2}, {1, 3}], sum: 20.555, count: 4}}
        ]
      }
    ]

    assert format(families) == ~S"""
           # HELP smtp_commands_total Commands with a \\ and\na newline.
           # TYPE smtp_commands_total counter
           smtp_commands_total{command="EHLO",listener="smtp"} 2
           smtp_commands_total{command="say \"hi\"\\\n"} 1
           # TYPE queue_size gauge
           queue_size 2.5
           # HELP empty Nothing yet.
           # TYPE empty gauge
           # HELP duration_seconds Durations.
           # TYPE duration_seconds histogram
           duration_seconds_bucket{command="DATA",le="0.01"} 1
           duration_seconds_bucket{command="DATA",le="0.1"} 2
           duration_seconds_bucket{command="DATA",le="1"} 3
           duration_seconds_bucket{command="DATA",le="+Inf"} 4
           duration_seconds_sum{command="DATA"} 20.555
           duration_seconds_count{command="DATA"} 4
           """
  end

  test "formats special and small values, and keeps the first of duplicate families" do
    families = [
      %{
        name: "values",
        type: :gauge,
        help: nil,
        samples: [
          {%{"v" => "inf"}, :infinity},
          {%{"v" => "-inf"}, :neg_infinity},
          {%{"v" => "nan"}, :nan},
          {%{"v" => "small"}, 0.001},
          {%{v: :atom_key}, -3}
        ]
      },
      %{name: "values", type: :counter, help: nil, samples: [{%{}, 1}]}
    ]

    assert format(families) == ~S"""
           # TYPE values gauge
           values{v="inf"} +Inf
           values{v="-inf"} -Inf
           values{v="nan"} NaN
           values{v="small"} 0.001
           values{v="atom_key"} -3
           """
  end

  test "formats collected metrics" do
    event = [:sovite_test, :prometheus, :collect]
    name = :"metrics_#{System.unique_integer([:positive])}"

    start_supervised!(
      {Metrics,
       name: name,
       metrics: [
         Metrics.distribution("size_bytes",
           event: event,
           measurement: :size,
           buckets: [100, 1000],
           help: "Sizes."
         )
       ]}
    )

    :telemetry.execute(event, %{size: 50}, %{})
    :telemetry.execute(event, %{size: 5000}, %{})

    assert format(Metrics.collect(name)) == """
           # HELP size_bytes Sizes.
           # TYPE size_bytes histogram
           size_bytes_bucket{le="100"} 1
           size_bytes_bucket{le="1000"} 1
           size_bytes_bucket{le="+Inf"} 2
           size_bytes_sum 5050
           size_bytes_count 2
           """
  end

  test "content type" do
    assert Prometheus.content_type() == "text/plain; version=0.0.4; charset=utf-8"
  end
end
