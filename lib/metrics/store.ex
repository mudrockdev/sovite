defmodule Sovite.Metrics.Store do
  @moduledoc false

  # The ETS table of a `Sovite.Metrics` instance. Rows:
  #
  #   {:definitions, [{index, metric}], collectors}
  #   {{:series, index}, count} and {{:dropped, index}, count}
  #   {{index, label_values}, ...}, the values of one series:
  #     counter, sum:  {key, integer, scaled}
  #     last_value:    {key, value}
  #     distribution:  {key, count, integer_sum, scaled_sum, bucket_1, ..., bucket_n}
  #
  # Floats are added as integers scaled by @scale, so every update is a
  # single atomic `:ets.update_counter/3`. Integers are kept apart so
  # integer sums stay exact.

  alias Sovite.Metrics.{Label, Metric}

  @scale 1_000_000
  @dropped "sovite_metrics_dropped_series_total"

  @doc "Creates the table of instance `name`."
  @spec new(atom(), [Metric.t()], [(-> [Sovite.Metrics.family()])]) ::
          [{non_neg_integer(), Metric.t()}]
  def new(name, metrics, collectors) do
    table = :ets.new(name, [:named_table, :public, :set, write_concurrency: true])
    metrics = Enum.with_index(metrics, fn metric, index -> {index, metric} end)
    :ets.insert(table, {:definitions, metrics, collectors})
    metrics
  end

  @doc "Clears every value of the table."
  @spec reset(atom()) :: :ok
  def reset(table) do
    :ets.select_delete(table, [{:"$1", [{:"=/=", {:element, 1, :"$1"}, :definitions}], [true]}])
    :ok
  end

  @doc "The telemetry handler. `config` has the table and the event's metrics."
  @spec handle_event(:telemetry.event_name(), map(), map(), map()) :: :ok
  def handle_event(_event, measurements, metadata, %{table: table, metrics: metrics}) do
    Enum.each(metrics, fn {index, metric} ->
      record(table, index, metric, measurements, metadata)
    end)
  end

  # Telemetry detaches a handler that raises, so nothing may escape.
  defp record(table, index, metric, measurements, metadata) do
    with true <- keep?(metric, metadata),
         {:ok, value} <- value(metric, measurements, metadata) do
      write(table, index, metric, {index, label_values(metric, metadata)}, value)
    end
  catch
    _kind, _reason -> :ok
  end

  defp keep?(%Metric{keep: nil}, _metadata), do: true
  defp keep?(%Metric{keep: keep}, metadata), do: keep.(metadata) == true

  defp value(%Metric{type: :counter}, _measurements, _metadata), do: {:ok, 1}

  defp value(%Metric{measurement: measurement, unit: unit}, measurements, metadata) do
    case measure(measurement, measurements, metadata) do
      value when is_number(value) -> {:ok, convert(value, unit)}
      _ -> :skip
    end
  end

  defp measure(fun, measurements, metadata) when is_function(fun, 2),
    do: fun.(measurements, metadata)

  defp measure(key, measurements, _metadata), do: Map.get(measurements, key)

  defp convert(value, nil), do: value
  defp convert(value, {:native, unit}), do: value / System.convert_time_unit(1, unit, :native)

  defp label_values(%Metric{tags: []}, _metadata), do: []

  defp label_values(%Metric{tags: tags, tag_values: tag_values}, metadata) do
    metadata = if tag_values, do: tag_values.(metadata), else: metadata
    Enum.map(tags, &Label.value(Map.get(metadata, &1)))
  end

  defp write(table, index, %Metric{type: :last_value} = metric, key, value) do
    if admitted?(table, index, metric, key), do: :ets.insert(table, {key, value})
  end

  defp write(table, index, metric, key, value) do
    if admitted?(table, index, metric, key),
      do: :ets.update_counter(table, key, ops(metric, value))
  end

  defp ops(%Metric{type: :counter}, _value), do: [{2, 1}]
  defp ops(%Metric{type: :sum}, value), do: [sum_op(value, 2)]

  defp ops(%Metric{type: :distribution, buckets: buckets}, value),
    do: [{2, 1}, sum_op(value, 3) | bucket_op(buckets, value, 5)]

  defp sum_op(value, position) when is_integer(value), do: {position, value}
  defp sum_op(value, position), do: {position + 1, round(value * @scale)}

  # Buckets are stored non-cumulative; values above the last bound only count.
  defp bucket_op([], _value, _position), do: []
  defp bucket_op([bound | _], value, position) when value <= bound, do: [{position, 1}]
  defp bucket_op([_ | bounds], value, position), do: bucket_op(bounds, value, position + 1)

  defp admitted?(table, index, metric, key),
    do: :ets.member(table, key) or admit(table, index, metric, key)

  # The series count is raised before the row is created, so concurrent
  # new series never take a metric over its limit.
  defp admit(table, index, metric, key) do
    series = {:series, index}

    if :ets.update_counter(table, series, 1, {series, 0}) <= metric.max_series do
      if not :ets.insert_new(table, default(metric, key)),
        do: :ets.update_counter(table, series, -1)

      true
    else
      :ets.update_counter(table, series, -1)
      :ets.update_counter(table, {:dropped, index}, 1, {{:dropped, index}, 0})
      false
    end
  end

  defp default(%Metric{type: :last_value}, key), do: {key, nil}

  defp default(%Metric{type: :distribution, buckets: buckets}, key),
    do: List.to_tuple([key, 0, 0, 0 | List.duplicate(0, length(buckets))])

  defp default(_metric, key), do: {key, 0, 0}

  @doc "Returns the families of the table, then those of its collectors."
  @spec families(atom()) :: [Sovite.Metrics.family()]
  def families(table) do
    [{:definitions, metrics, collectors}] = :ets.lookup(table, :definitions)
    rows = :ets.tab2list(table)
    series = rows |> Enum.filter(&series?/1) |> Enum.group_by(&index/1)
    names = Map.new(metrics, fn {index, metric} -> {index, metric.name} end)

    dropped =
      for {{:dropped, index}, count} <- rows, count > 0 do
        {%{"metric" => Map.fetch!(names, index)}, count}
      end

    Enum.map(metrics, fn {index, metric} -> family(metric, Map.get(series, index, [])) end) ++
      dropped_family(dropped) ++ Enum.flat_map(collectors, &collect/1)
  end

  defp series?(row), do: match?({index, _values} when is_integer(index), elem(row, 0))

  defp index(row), do: row |> elem(0) |> elem(0)

  defp family(metric, rows) do
    samples =
      rows
      |> Enum.flat_map(&sample(metric, &1))
      |> Enum.sort_by(fn {labels, _value} -> Enum.sort(labels) end)

    samples =
      if samples == [] and metric.tags == [] and metric.type in [:counter, :sum],
        do: [{%{}, 0}],
        else: samples

    %{name: metric.name, type: type(metric.type), help: metric.help, samples: samples}
  end

  defp type(:last_value), do: :gauge
  defp type(:distribution), do: :histogram
  defp type(_counter_or_sum), do: :counter

  defp sample(%Metric{type: :last_value}, {_key, nil}), do: []

  defp sample(%Metric{type: :last_value} = metric, {key, value}),
    do: [{labels(metric, key), value}]

  defp sample(%Metric{type: :distribution} = metric, row) do
    [key, count, integer, scaled | buckets] = Tuple.to_list(row)
    cumulative = Enum.zip(metric.buckets, Enum.scan(buckets, &+/2))
    [{labels(metric, key), %{buckets: cumulative, sum: number(integer, scaled), count: count}}]
  end

  defp sample(metric, {key, integer, scaled}),
    do: [{labels(metric, key), number(integer, scaled)}]

  defp labels(metric, {_index, values}),
    do: metric.tags |> Enum.map(&Atom.to_string/1) |> Enum.zip(values) |> Map.new()

  defp number(integer, 0), do: integer
  defp number(integer, scaled), do: integer + scaled / @scale

  defp dropped_family([]), do: []

  defp dropped_family(samples) do
    [
      %{
        name: @dropped,
        type: :counter,
        help: "Events not recorded because their metric had reached its series limit.",
        samples: Enum.sort(samples)
      }
    ]
  end

  # One broken collector must not break the scrape.
  defp collect(collector) do
    case collector.() do
      families when is_list(families) -> families
      _ -> []
    end
  catch
    _kind, _reason -> []
  end
end
