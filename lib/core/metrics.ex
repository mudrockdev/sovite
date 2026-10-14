defmodule Sovite.Core.Metrics do
  @moduledoc """
  The Prometheus metrics of the MTA, served at `/metrics` on the admin
  listener (see `Sovite.Core.Admin`) with `metrics.enabled`.

  Counters and histograms come from the telemetry events of
  `Sovite.Core.Telemetry` (`Sovite.Metrics`); they start from zero at
  each start. Gauges are read when scraped.

  | Metric | Type | Labels |
  |---|---|---|
  | `sovite_smtp_connections_total` | counter | `listener` |
  | `sovite_smtp_connections_rejected_total` | counter | `listener`, `reason` |
  | `sovite_smtp_sessions_total` | counter | |
  | `sovite_smtp_session_duration_seconds` | histogram | |
  | `sovite_smtp_commands_total` | counter | `command`, `status` (`2xx`, `4xx`, `5xx`, ...) |
  | `sovite_smtp_command_duration_seconds` | histogram | `command` |
  | `sovite_smtp_tls_handshakes_total` | counter | `result` (`ok`, `error`), `protocol` |
  | `sovite_auth_total` | counter | `mechanism`: successful logins |
  | `sovite_auth_failures_total` | counter | `mechanism` |
  | `sovite_messages_received_total` | counter | |
  | `sovite_messages_received_bytes_total` | counter | |
  | `sovite_messages_deferred_total` | counter | |
  | `sovite_messages_removed_total` | counter | `reason` |
  | `sovite_messages_corrupt_total` | counter | |
  | `sovite_messages_authenticated_total` | counter | `dmarc` |
  | `sovite_notifications_total` | counter | `kind` |
  | `sovite_deliveries_total` | counter | `status` (`delivered`, `deferred`, `failed`) |
  | `sovite_delivery_duration_seconds` | histogram | |
  | `sovite_delivery_exceptions_total` | counter | |
  | `sovite_screen_rejected_total` | counter | `stage` |
  | `sovite_greylist_deferred_total` | counter | |
  | `sovite_rate_limit_exceeded_total` | counter | `rate_limit` |
  | `sovite_auth_bans_total` | counter | |
  | `sovite_outbound_suspended_total` | counter | |
  | `sovite_milter_errors_total` | counter | `milter` |
  | `sovite_policy_errors_total` | counter | |
  | `sovite_queue_messages` | gauge | `queue` (`incoming`, `active`, `deferred`, `hold`, `corrupt`) |
  | `sovite_deliveries_running` | gauge | |
  | `sovite_deliveries_ready` | gauge | |
  | `sovite_smtp_open_connections` | gauge | `listener` |
  | `sovite_start_time_seconds` | gauge | |
  | `sovite_build_info` | gauge | `version` |
  | `sovite_vm_memory_bytes` | gauge | `kind` |
  | `sovite_vm_processes` | gauge | |
  | `sovite_vm_run_queue` | gauge | |
  """

  alias Sovite.Core.{Control, QueueInfo, QueueManager}
  alias Sovite.Metrics

  @version Mix.Project.config()[:version]

  @seconds [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60]
  @long_seconds [0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600, 1800]

  @doc """
  The `Sovite.Metrics` child spec. `runtime` has the `:name` of the
  metrics process, the `:queue_manager`, the queue `:directory`, the
  `:supervisor` whose listeners are counted, and `:started_at`.
  """
  @spec child_spec(map()) :: Supervisor.child_spec()
  def child_spec(runtime) do
    Supervisor.child_spec(
      {Metrics, name: runtime.name, metrics: metrics(), collectors: collectors(runtime)},
      []
    )
  end

  @doc false
  def metrics do
    smtp_metrics() ++ queue_metrics() ++ abuse_metrics()
  end

  defp smtp_metrics do
    [
      Metrics.counter("sovite_smtp_connections_total",
        event: [:sovite, :listener, :connection, :start],
        tags: [:listener],
        help: "Connections accepted."
      ),
      Metrics.counter("sovite_smtp_connections_rejected_total",
        event: [:sovite, :listener, :connection, :rejected],
        tags: [:listener, :reason],
        help: "Connections refused by a limit."
      ),
      Metrics.counter("sovite_smtp_sessions_total",
        event: [:sovite, :smtp, :server, :session, :stop],
        help: "SMTP sessions ended."
      ),
      Metrics.distribution("sovite_smtp_session_duration_seconds",
        event: [:sovite, :smtp, :server, :session, :stop],
        measurement: :duration,
        unit: {:native, :second},
        buckets: @long_seconds,
        help: "Length of SMTP sessions."
      ),
      Metrics.counter("sovite_smtp_commands_total",
        event: [:sovite, :smtp, :server, :command, :stop],
        tags: [:command, :status],
        tag_values: &Map.put(&1, :status, "#{div(&1.reply_code, 100)}xx"),
        help: "SMTP commands answered, by reply class."
      ),
      Metrics.distribution("sovite_smtp_command_duration_seconds",
        event: [:sovite, :smtp, :server, :command, :stop],
        measurement: :duration,
        unit: {:native, :second},
        buckets: @seconds,
        tags: [:command],
        help: "Time to answer SMTP commands."
      ),
      Metrics.counter("sovite_smtp_tls_handshakes_total",
        event: [:sovite, :smtp, :server, :tls, :stop],
        tags: [:result, :protocol],
        tag_values: &Map.put(&1, :result, if(&1.error, do: "error", else: "ok")),
        help: "TLS handshakes of SMTP sessions."
      ),
      Metrics.counter("sovite_auth_total",
        event: [:sovite, :auth, :success],
        tags: [:mechanism],
        help: "Successful SMTP logins."
      ),
      Metrics.counter("sovite_auth_failures_total",
        event: [:sovite, :auth, :failure],
        tags: [:mechanism],
        help: "Failed SMTP logins."
      )
    ]
  end

  defp queue_metrics do
    [
      Metrics.counter("sovite_messages_received_total",
        event: [:sovite, :queue, :message, :enqueued],
        help: "Messages queued, notifications and reports included."
      ),
      Metrics.sum("sovite_messages_received_bytes_total",
        event: [:sovite, :queue, :message, :enqueued],
        measurement: :size,
        help: "Bytes of the messages queued."
      ),
      Metrics.counter("sovite_messages_deferred_total",
        event: [:sovite, :queue, :message, :deferred],
        help: "Delivery attempts after which a message stayed queued."
      ),
      Metrics.counter("sovite_messages_removed_total",
        event: [:sovite, :queue, :message, :removed],
        tags: [:reason],
        help: "Messages removed from the queue."
      ),
      Metrics.counter("sovite_messages_corrupt_total",
        event: [:sovite, :queue, :message, :corrupt],
        help: "Queue files that failed verification."
      ),
      Metrics.counter("sovite_messages_authenticated_total",
        event: [:sovite, :smtp, :message, :authenticated],
        tags: [:dmarc],
        help: "Received messages checked with SPF, DKIM, ARC, and DMARC, by DMARC result."
      ),
      Metrics.counter("sovite_notifications_total",
        event: [:sovite, :queue, :notification, :sent],
        tags: [:kind],
        help: "Delivery status notifications queued."
      ),
      Metrics.counter("sovite_deliveries_total",
        event: [:sovite, :smtp, :client, :delivery, :stop],
        tags: [:status],
        help: "Delivery results, per recipient."
      ),
      Metrics.distribution("sovite_delivery_duration_seconds",
        event: [:sovite, :smtp, :client, :delivery, :stop],
        measurement: :duration,
        unit: {:native, :second},
        buckets: @long_seconds,
        help: "Time of delivery attempts, per recipient."
      ),
      Metrics.counter("sovite_delivery_exceptions_total",
        event: [:sovite, :smtp, :client, :delivery, :exception],
        help: "Deliveries that crashed."
      )
    ]
  end

  defp abuse_metrics do
    [
      Metrics.counter("sovite_screen_rejected_total",
        event: [:sovite, :screen, :rejected],
        tags: [:stage],
        help: "Clients refused by the screen."
      ),
      Metrics.counter("sovite_greylist_deferred_total",
        event: [:sovite, :greylist, :deferred],
        help: "Recipients deferred by greylisting."
      ),
      Metrics.counter("sovite_rate_limit_exceeded_total",
        event: [:sovite, :abuse, :rate_limit, :exceeded],
        tags: [:rate_limit],
        help: "Rate limits hit."
      ),
      Metrics.counter("sovite_auth_bans_total",
        event: [:sovite, :abuse, :penalty, :banned],
        help: "Clients banned after failed logins."
      ),
      Metrics.counter("sovite_outbound_suspended_total",
        event: [:sovite, :outbound, :suspended],
        help: "Users suspended because their mail failed too often."
      ),
      Metrics.counter("sovite_milter_errors_total",
        event: [:sovite, :milter, :error],
        tags: [:milter],
        help: "Milter errors."
      ),
      Metrics.counter("sovite_policy_errors_total",
        event: [:sovite, :policy, :client, :error],
        help: "Failed policy server requests."
      )
    ]
  end

  ## Gauges

  defp collectors(runtime) do
    [
      fn -> queue_gauges(runtime) end,
      fn -> connection_gauges(runtime) end,
      fn -> vm_gauges(runtime) end
    ]
  end

  defp queue_gauges(runtime) do
    counts = QueueInfo.counts(runtime.directory)
    stats = QueueManager.stats(runtime.queue_manager)
    # The manager knows the active and deferred messages without listing.
    counts = %{counts | active: stats.active, deferred: stats.deferred}

    [
      gauge(
        "sovite_queue_messages",
        "Messages in each queue.",
        for(queue <- QueueInfo.queues(), do: {%{"queue" => "#{queue}"}, counts[queue]})
      ),
      gauge("sovite_deliveries_running", "Deliveries running.", [{%{}, stats.deliveries}]),
      gauge("sovite_deliveries_ready", "Deliveries waiting for a free slot.", [
        {%{}, stats.ready}
      ])
    ]
  end

  defp connection_gauges(runtime) do
    samples =
      for {id, count} <- Control.listener_connections(runtime.supervisor),
          do: {%{"listener" => id}, count}

    [gauge("sovite_smtp_open_connections", "Open SMTP connections.", samples)]
  end

  defp vm_gauges(runtime) do
    memory = :erlang.memory()

    [
      gauge("sovite_start_time_seconds", "When Sovite started, in Unix time.", [
        {%{}, runtime.started_at}
      ]),
      gauge("sovite_build_info", "The Sovite version.", [{%{"version" => @version}, 1}]),
      gauge(
        "sovite_vm_memory_bytes",
        "Memory used by the Erlang VM.",
        for(
          kind <- [:total, :processes, :binary, :ets, :atom, :code],
          do: {%{"kind" => "#{kind}"}, memory[kind]}
        )
      ),
      gauge("sovite_vm_processes", "Erlang processes.", [
        {%{}, :erlang.system_info(:process_count)}
      ]),
      gauge("sovite_vm_run_queue", "Processes waiting to run.", [
        {%{}, :erlang.statistics(:total_run_queue_lengths)}
      ])
    ]
  end

  defp gauge(name, help, samples), do: %{name: name, type: :gauge, help: help, samples: samples}
end
