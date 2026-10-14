defmodule Sovite.Metrics do
  @moduledoc """
  Metrics computed from `:telemetry` events and kept in memory, for
  export in the Prometheus text format with `Sovite.Metrics.Prometheus`.

      children = [
        {Sovite.Metrics,
         name: MyApp.Metrics,
         metrics: [
           Sovite.Metrics.counter("smtp_commands_total",
             event: [:sovite, :smtp, :server, :command, :stop],
             tags: [:command],
             help: "SMTP commands received."
           ),
           Sovite.Metrics.distribution("smtp_command_duration_seconds",
             event: [:sovite, :smtp, :server, :command, :stop],
             measurement: :duration,
             unit: {:native, :second},
             buckets: [0.01, 0.1, 1, 10],
             tags: [:command]
           )
         ]}
      ]

      MyApp.Metrics |> Sovite.Metrics.collect() |> Sovite.Metrics.Prometheus.format()

  There are four kinds of metric:

    * `counter/2` - the number of events. A Prometheus counter.
    * `sum/2` - the sum of a measurement. A Prometheus counter.
    * `last_value/2` - the latest value of a measurement. A Prometheus
      gauge.
    * `distribution/2` - a measurement counted into buckets. A Prometheus
      histogram.

  The process attaches a telemetry handler for each event the metrics
  name, and owns an ETS table with the values. Handlers run in the
  process that emits the event and update the table directly, so
  recording never waits on the process. An event a metric cannot use,
  such as one with its measurement missing or not a number, is skipped
  by that metric: the handler never raises, so telemetry never detaches
  it. Values are in memory: a restart starts from zero.

  Each distinct combination of tag values is a series. A metric keeps at
  most `:max_series` of them, so tag values from untrusted input cannot
  grow memory without bound. Events for further combinations are not
  recorded, and are counted in a `sovite_metrics_dropped_series_total`
  counter with a `metric` label naming the metric. That family is only
  reported once an event was dropped.

  Collectors add families computed at collection time, such as the size
  of a queue:

      collectors: [
        fn ->
          [%{name: "queue_messages", type: :gauge, help: "Queued messages.",
             samples: [{%{"queue" => "deferred"}, MyApp.Queue.size(:deferred)}]}]
        end
      ]

  ## Options

    * `:name` - an atom naming the process and its ETS table. Required.
    * `:metrics` - metric definitions. Defaults to `[]`.
    * `:collectors` - 0-arity functions returning a list of `t:family/0`,
      called by `collect/1` in the calling process. A collector that
      raises or exits is skipped. Defaults to `[]`.

  ## Metric options

    * `:event` - the telemetry event name. Required.
    * `:measurement` - the measurement key, or a 2-arity function given
      the measurements and metadata and returning a number or `nil`.
      Required, except for counters, which take none and count events.
    * `:tags` - metadata keys whose values become labels, named after
      the key. Defaults to `[]`.
    * `:tag_values` - a 1-arity function given the metadata and returning
      the map tags are taken from, to derive labels. Defaults to the
      metadata itself.
    * `:keep` - a 1-arity function given the metadata; events for which
      it does not return `true` are ignored. Defaults to keeping all.
    * `:help` - the help text. Defaults to `nil`.
    * `:unit` - `{:native, unit}` converts a measurement in `:native` time
      units, as telemetry spans report durations, to `:second`,
      `:millisecond` or `:microsecond`. Defaults to `nil`, no conversion.
    * `:buckets` - for distributions, the ascending bucket upper bounds,
      in the converted unit. Required for distributions.
    * `:max_series` - distinct label combinations kept. Defaults to 1000.

  Label values are strings: binaries as they are (inspected if not
  UTF-8), atoms and integers converted, `nil` empty, IP addresses in
  their text form, and anything else inspected.
  """

  use GenServer

  alias Sovite.Metrics.{Metric, Store}

  @typedoc "Label names to label values."
  @type labels :: %{optional(String.t()) => String.t()}

  @typedoc "A sample value. Collectors can also use the special values."
  @type value :: number() | :infinity | :neg_infinity | :nan

  @typedoc """
  A histogram sample: cumulative counts for each finite upper bound,
  the sum of the values, and their count.
  """
  @type histogram :: %{
          buckets: [{number(), non_neg_integer()}],
          sum: value(),
          count: non_neg_integer()
        }

  @typedoc """
  A metric family. Counters and gauges have `{labels, value}` samples,
  histograms `{labels, histogram}` ones.
  """
  @type family :: %{
          name: String.t(),
          type: :counter | :gauge | :histogram,
          help: String.t() | nil,
          samples: [{labels(), value() | histogram()}]
        }

  @name ~r/\A[a-zA-Z_:][a-zA-Z0-9_:]*\z/
  @label ~r/\A[a-zA-Z_][a-zA-Z0-9_]*\z/
  @units [:second, :millisecond, :microsecond]
  @common [:event, :help, :keep, :tag_values, tags: [], max_series: 1000]

  @doc false
  def child_spec(opts),
    do: %{id: {__MODULE__, Keyword.fetch!(opts, :name)}, start: {__MODULE__, :start_link, [opts]}}

  @doc "Starts the metrics process. See the module docs for options."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    opts = Keyword.validate!(opts, [:name, metrics: [], collectors: []])
    name = opts[:name]

    if not is_atom(name) or is_nil(name),
      do: raise(ArgumentError, "the :name option must be an atom")

    if not Enum.all?(opts[:metrics], &is_struct(&1, Metric)),
      do: raise(ArgumentError, ":metrics must be a list of metric definitions")

    if not Enum.all?(opts[:collectors], &is_function(&1, 0)),
      do: raise(ArgumentError, ":collectors must be a list of 0-arity functions")

    case opts[:metrics] |> Enum.frequencies_by(& &1.name) |> Enum.find(&(elem(&1, 1) > 1)) do
      nil -> GenServer.start_link(__MODULE__, opts, name: name)
      {metric, _count} -> raise ArgumentError, "duplicate metric #{inspect(metric)}"
    end
  end

  @doc "Defines a counter of events. See the module docs for options."
  @spec counter(String.t(), keyword()) :: Metric.t()
  def counter(name, opts), do: build(:counter, name, opts, [])

  @doc "Defines a counter summing a measurement. See the module docs for options."
  @spec sum(String.t(), keyword()) :: Metric.t()
  def sum(name, opts), do: build(:sum, name, opts, [:measurement, :unit])

  @doc "Defines a gauge with the latest value of a measurement. See the module docs for options."
  @spec last_value(String.t(), keyword()) :: Metric.t()
  def last_value(name, opts), do: build(:last_value, name, opts, [:measurement, :unit])

  @doc "Defines a histogram of a measurement. See the module docs for options."
  @spec distribution(String.t(), keyword()) :: Metric.t()
  def distribution(name, opts),
    do: build(:distribution, name, opts, [:measurement, :unit, :buckets])

  @doc """
  Returns the families of the metrics, in definition order, then the
  dropped series family if any, then the collectors' families.
  """
  @spec collect(atom()) :: [family()]
  def collect(name), do: Store.families(name)

  @doc "Clears all values, including dropped series counts."
  @spec reset(atom()) :: :ok
  def reset(name), do: Store.reset(name)

  defp build(type, name, opts, keys) do
    check!(is_binary(name) and name =~ @name, "invalid metric name #{inspect(name)}")
    opts = Keyword.validate!(opts, keys ++ @common)
    metric = struct!(Metric, [type: type, name: name] ++ opts)
    validate!(metric)
    metric
  end

  defp validate!(%Metric{} = metric) do
    check!(event?(metric.event), ":event must be a list of atoms")

    check!(
      metric.type == :counter or measurement?(metric.measurement),
      ":measurement must be an atom or a 2-arity function"
    )

    check!(tags?(metric.tags, metric.type), ":tags must be a list of distinct label names")
    check!(optional_fun?(metric.tag_values, 1), ":tag_values must be a 1-arity function")
    check!(optional_fun?(metric.keep, 1), ":keep must be a 1-arity function")
    check!(is_nil(metric.help) or is_binary(metric.help), ":help must be a string")
    check!(unit?(metric.unit), ":unit must be nil or {:native, unit}")

    check!(
      is_integer(metric.max_series) and metric.max_series > 0,
      ":max_series must be a positive integer"
    )

    check!(
      metric.type != :distribution or buckets?(metric.buckets),
      ":buckets must be a non-empty list of ascending numbers"
    )
  end

  defp check!(true, _message), do: :ok
  defp check!(false, message), do: raise(ArgumentError, message)

  defp event?([_ | _] = event), do: Enum.all?(event, &is_atom/1)
  defp event?(_event), do: false

  defp measurement?(nil), do: false
  defp measurement?(measurement), do: is_atom(measurement) or is_function(measurement, 2)

  defp tags?(tags, type) when is_list(tags),
    do: Enum.all?(tags, &label?(&1, type)) and Enum.uniq(tags) == tags

  defp tags?(_tags, _type), do: false

  defp label?(tag, type) when is_atom(tag) and not is_nil(tag) do
    label = Atom.to_string(tag)

    label =~ @label and not String.starts_with?(label, "__") and
      not (type == :distribution and label == "le")
  end

  defp label?(_tag, _type), do: false

  defp optional_fun?(fun, arity), do: is_nil(fun) or is_function(fun, arity)

  defp unit?(nil), do: true
  defp unit?({:native, unit}), do: unit in @units
  defp unit?(_unit), do: false

  defp buckets?([_ | _] = buckets) do
    Enum.all?(buckets, &is_number/1) and
      buckets |> Enum.chunk_every(2, 1, :discard) |> Enum.all?(fn [a, b] -> a < b end)
  end

  defp buckets?(_buckets), do: false

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    name = opts[:name]
    metrics = Store.new(name, opts[:metrics], opts[:collectors])

    handlers =
      for {event, metrics} <- Enum.group_by(metrics, fn {_index, metric} -> metric.event end) do
        id = {__MODULE__, name, event}
        # A previous instance that was killed could not detach its handler.
        :telemetry.detach(id)
        config = %{table: name, metrics: metrics}
        :ok = :telemetry.attach(id, event, &Store.handle_event/4, config)
        id
      end

    {:ok, %{handlers: handlers}}
  end

  @impl true
  def terminate(_reason, state), do: Enum.each(state.handlers, &:telemetry.detach/1)
end
