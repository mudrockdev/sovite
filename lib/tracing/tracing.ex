defmodule Sovite.Tracing do
  @moduledoc """
  OpenTelemetry traces built from `:telemetry` events, exported to a
  collector with OTLP/HTTP and JSON.

  Spans are described by definitions: which events open and close them,
  and which metadata becomes their attributes. The process started with
  `start_link/1` attaches a handler for each, buffers the finished spans,
  and posts them to the collector in batches.

      {Sovite.Tracing,
       name: MyApp.Tracing,
       endpoint: "http://127.0.0.1:4318/v1/traces",
       service_name: "sovite",
       spans: [
         Sovite.Tracing.span("smtp.session",
           start: [:sovite, :smtp, :server, :session, :start],
           stop: [:sovite, :smtp, :server, :session, :stop],
           kind: :server,
           attributes: [:session_id, :remote_ip]
         ),
         Sovite.Tracing.event_span(&("smtp " <> &1.command),
           event: [:sovite, :smtp, :server, :command, :stop],
           attributes: [:command, :reply_code]
         ),
         Sovite.Tracing.span_event("message queued",
           event: [:sovite, :queue, :message, :enqueued],
           attributes: [:queue_id]
         )
       ]}

  There are three kinds of definition:

    * `span/2` - a span opened by a start event and closed by a stop or
      exception event in the same process.
    * `event_span/2` - a finished span from one event, ending when it is
      emitted and lasting its `duration` measurement.
    * `span_event/2` - an event added to the span open in the process.

  ## Context

  Telemetry handlers run in the process that emits the event, so the
  spans open in a process are kept in its process dictionary. A span
  started while another is open in the same process is its child, in the
  same trace. Other spans start a new trace, with a random trace ID or
  one derived from the definition's `:trace_id` function: spans in
  different processes, such as the deliveries of one message, can share
  a trace by deriving its ID from the same key.

  A stop event closes the innermost open span of its definition, or,
  when both events carry `:telemetry_span_context`, the span with the
  same context. Spans opened after it and still open end with it, with
  their status unset. A stop event with no open span is ignored, so
  events that fire several times for one start, such as once per
  recipient, close the span the first time. Without
  `:telemetry_span_context`, a repeated stop of a definition nested in
  itself closes the outer span.

  A process keeps at most 64 open spans, dropping the oldest, and adds at
  most 128 events to a span.

  ## Sampling

  `:sample_ratio` decides whether a new trace is exported, from its trace
  ID (as OpenTelemetry's `TraceIdRatioBased` sampler): its last 8 bytes
  as an integer must be below the ratio of 2^64. Spans of a trace with a
  derived ID are sampled the same way wherever they start. Child spans
  follow their parent. Spans that are not sampled are still tracked, so
  their children stay in their trace, but are not exported.

  ## Attributes

  Strings, integers, floats, booleans, and lists of strings keep their
  type. Atoms and IP address tuples become strings; anything else,
  including strings that are not UTF-8, is `inspect/1`ed. Attributes
  whose value is `nil` are left out.

  ## Export

  Spans are posted when `:batch_size` of them are buffered, and every
  `:interval` otherwise, one request at a time. A failed request drops
  its spans, without retrying. When the buffer holds `:max_queue` spans,
  new spans are dropped. When the process stops, it detaches its
  handlers and posts the spans it still holds, giving up after
  `:shutdown_timeout`.

  ## Options

    * `:name` - registered name of the process, an atom. Required.
    * `:endpoint` - the collector's traces URL, such as
      `"http://127.0.0.1:4318/v1/traces"`. Required.
    * `:headers` - extra request headers, as `{name, value}` strings.
      Defaults to `[]`.
    * `:service_name` - the `service.name` resource attribute. Defaults
      to `"sovite"`.
    * `:resource` - other resource attributes, a map. Defaults to `%{}`.
    * `:scope` - the instrumentation scope name. Defaults to `"sovite"`.
    * `:spans` - the span definitions. Defaults to `[]`.
    * `:sample_ratio` - the share of traces exported, from `0.0` to
      `1.0`. Defaults to `1.0`.
    * `:batch_size` - spans per request. Defaults to 512.
    * `:max_queue` - spans buffered at most. Defaults to 2048.
    * `:interval` - milliseconds between exports. Defaults to 5 seconds.
    * `:timeout` - milliseconds for connecting and for the response.
      Defaults to 10 seconds.
    * `:shutdown_timeout` - milliseconds for the last export when the
      process stops. Defaults to 2 seconds.
    * `:cacerts` - CAs to verify an `https` endpoint against. Defaults to
      the system's.

  ## Telemetry

  The metadata of each event includes the instance's `name`.

    * `[:sovite, :tracing, :export, :stop]` - `%{spans, duration}`,
      `%{name}`: a batch was accepted by the collector.
    * `[:sovite, :tracing, :export, :error]` - `%{spans}`,
      `%{name, reason}`: a batch was dropped. `reason` is
      `{:http_status, status}` for a status other than 2xx, or an
      `:httpc` error, such as `{:failed_connect, _}` or `:timeout`.
    * `[:sovite, :tracing, :spans, :dropped]` - `%{spans}`, `%{name}`:
      spans dropped because the buffer was full, counted over an
      interval.
    * `[:sovite, :tracing, :handler, :error]` - `%{}`,
      `%{name, event, kind, reason}`: handling `event` raised, for
      example in a definition's function. The event is skipped.
  """

  alias Sovite.Tracing.{Definition, Exporter}

  @typedoc "A span definition, from `span/2`, `event_span/2`, or `span_event/2`."
  @type definition :: Definition.t()

  @typedoc "A span or event name, or a function of the event metadata returning one."
  @type name :: String.t() | (map() -> String.t())

  @defaults [
    headers: [],
    service_name: "sovite",
    resource: %{},
    scope: "sovite",
    spans: [],
    sample_ratio: 1.0,
    batch_size: 512,
    max_queue: 2048,
    interval: 5_000,
    timeout: 10_000,
    shutdown_timeout: 2_000,
    cacerts: nil
  ]

  @doc false
  def child_spec(opts) do
    %{
      id: {__MODULE__, Keyword.get(opts, :name)},
      start: {__MODULE__, :start_link, [opts]},
      shutdown: Keyword.get(opts, :shutdown_timeout, 2_000) + 1_000
    }
  end

  @doc "Starts the exporter and attaches its handlers. See the module docs for options."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    opts = Keyword.validate!(opts, [:name, :endpoint] ++ @defaults)
    validate!(opts)
    Exporter.start_link(opts)
  end

  @doc """
  Exports the spans finished so far, waiting up to `timeout`
  milliseconds. Spans finished by other processes count once their
  handlers have run.
  """
  @spec flush(GenServer.server(), timeout()) :: :ok
  def flush(server, timeout \\ 5_000), do: GenServer.call(server, :flush, timeout)

  @doc """
  Defines a span opened by the `:start` event and closed by the `:stop`
  or `:exception` event, emitted by the same process.

  Its attributes come from the start metadata merged with the stop
  metadata. The `:exception` event sets the status to error, with the
  metadata's `:reason`, or else its `:kind`, as the message.

  ## Options

    * `:start` - the event that opens the span. Required.
    * `:stop` - the event that closes it. Required.
    * `:exception` - an event that closes it with an error.

  The other options are those of `event_span/2`, except `:duration`.
  `name` and the functions are given the merged metadata, except
  `:trace_id` and `:keep`, which are given the start metadata.
  """
  @spec span(name(), keyword()) :: definition()
  def span(name, opts), do: Definition.new(:span, name, opts)

  @doc """
  Defines a finished span from one `:event`. It ends when the event is
  emitted and starts `duration` earlier, or is zero-length without that
  measurement. Its parent is the span open in the process, if any.

  ## Options

    * `:event` - the event. Required.
    * `:duration` - the measurement with the duration, in `:native` time
      units. Defaults to `:duration`.
    * `:kind` - `:internal`, `:server`, `:client`, `:producer`, or
      `:consumer`. Defaults to `:internal`.
    * `:attributes` - the metadata keys copied into the attributes, or a
      function of the metadata returning a map of attributes. Defaults to
      `[]`.
    * `:error` - a function of the metadata returning `nil`, or a message
      that sets the status to error.
    * `:trace_id` - a function of the metadata returning `nil`, or a key
      from which the trace ID of a new trace is derived (the first 16
      bytes of its SHA-256).
    * `:keep` - a function of the metadata returning whether to handle
      the event. Defaults to handling all.

  `name` can be a function of the metadata.
  """
  @spec event_span(name(), keyword()) :: definition()
  def event_span(name, opts), do: Definition.new(:event_span, name, opts)

  @doc """
  Defines an event added to the innermost span open in the process when
  `:event` is emitted. With no open span, it is ignored.

  ## Options

    * `:event` - the event. Required.
    * `:attributes` - as in `event_span/2`.
    * `:keep` - as in `event_span/2`.
  """
  @spec span_event(name(), keyword()) :: definition()
  def span_event(name, opts), do: Definition.new(:span_event, name, opts)

  defp validate!(opts) do
    check!(opts, :name, &is_atom/1, "an atom")
    check!(opts, :endpoint, &endpoint?/1, "an http or https URL")
    check!(opts, :headers, &headers?/1, "a list of {name, value} strings")
    check!(opts, :service_name, &is_binary/1, "a string")
    check!(opts, :resource, &is_map/1, "a map")
    check!(opts, :scope, &is_binary/1, "a string")
    check!(opts, :spans, &spans?/1, "a list of span definitions")
    check!(opts, :sample_ratio, &(is_number(&1) and &1 >= 0 and &1 <= 1), "from 0.0 to 1.0")

    for key <- [:batch_size, :max_queue, :interval, :timeout, :shutdown_timeout],
        do: check!(opts, key, &(is_integer(&1) and &1 > 0), "a positive integer")

    :ok
  end

  defp check!(opts, key, valid?, expected) do
    value = opts[key]

    unless value != nil and valid?.(value),
      do: raise(ArgumentError, "#{inspect(key)} must be #{expected}, got: #{inspect(value)}")
  end

  defp endpoint?(url) when is_binary(url) do
    case URI.new(url) do
      {:ok, %URI{scheme: scheme, host: host}} ->
        scheme in ["http", "https"] and host not in [nil, ""]

      {:error, _} ->
        false
    end
  end

  defp endpoint?(_url), do: false

  defp headers?(headers) do
    is_list(headers) and
      Enum.all?(headers, &match?({name, value} when is_binary(name) and is_binary(value), &1))
  end

  defp spans?(spans), do: is_list(spans) and Enum.all?(spans, &is_struct(&1, Definition))
end
