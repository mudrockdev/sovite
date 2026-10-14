defmodule Sovite.Core.Tracing do
  @moduledoc """
  The OpenTelemetry traces of the MTA, sent with `tracing.enabled` to the
  OTLP/HTTP collector at `tracing.endpoint` (`Sovite.Tracing`).

  Each SMTP session is a trace: an `smtp.session` server span, with a
  span for each command (`smtp MAIL`, `smtp RCPT`, ...) and the TLS
  handshake, and the events `message accepted` (with its `queue_id` and
  `message_id`) and `message authenticated`. Milter and policy server
  requests made during the session are spans in it too.

  Each queued message is a trace of its own, with a `delivery` client
  span for each delivery attempt. Its trace ID is derived from the queue
  ID, so every attempt, hours or days apart, lands in the same trace;
  the `queue_id` attribute of `message accepted` links it to the session.
  """

  alias Sovite.Tracing

  @version Mix.Project.config()[:version]

  @doc """
  The `Sovite.Tracing` child spec for the `[tracing]` config section.
  `name` is the process name, `hostname` the `host.name` resource
  attribute.
  """
  @spec child_spec(map(), atom(), String.t()) :: Supervisor.child_spec()
  def child_spec(tracing, name, hostname) do
    Supervisor.child_spec(
      {Tracing,
       name: name,
       endpoint: tracing.endpoint,
       headers: Enum.to_list(tracing.headers),
       service_name: tracing.service_name,
       sample_ratio: tracing.sample_ratio,
       resource: %{"host.name" => hostname, "service.version" => @version},
       spans: spans()},
      []
    )
  end

  @doc false
  def spans do
    [
      Tracing.span("smtp.session",
        start: [:sovite, :smtp, :server, :session, :start],
        stop: [:sovite, :smtp, :server, :session, :stop],
        kind: :server,
        attributes: [:session_id, :remote_ip]
      ),
      Tracing.event_span(&"smtp #{&1.command}",
        event: [:sovite, :smtp, :server, :command, :stop],
        attributes: [:command, :reply_code, :reply]
      ),
      Tracing.event_span("smtp tls",
        event: [:sovite, :smtp, :server, :tls, :stop],
        attributes: [:protocol, :cipher, :sni],
        error: &(&1.error && inspect(&1.error))
      ),
      Tracing.span_event("message accepted",
        event: [:sovite, :smtp, :message, :accepted],
        attributes: [:queue_id, :message_id, :sender, :user]
      ),
      Tracing.span_event("message authenticated",
        event: [:sovite, :smtp, :message, :authenticated],
        attributes: [:queue_id, :spf, :dkim, :arc, :dmarc, :disposition]
      ),
      Tracing.event_span(&"milter #{&1.stage}",
        event: [:sovite, :milter, :reply],
        attributes: [:milter, :stage, :reply]
      ),
      Tracing.event_span("policy",
        event: [:sovite, :policy, :client, :request, :stop],
        kind: :client,
        attributes: [:address, :action]
      ),
      Tracing.span("delivery",
        start: [:sovite, :smtp, :client, :delivery, :start],
        stop: [:sovite, :smtp, :client, :delivery, :stop],
        exception: [:sovite, :smtp, :client, :delivery, :exception],
        kind: :client,
        trace_id: & &1[:queue_id],
        attributes: [:queue_id, :relay, :status, :reply],
        error: &if(&1[:status] == :failed, do: &1[:reply])
      )
    ]
  end
end
