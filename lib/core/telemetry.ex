defmodule Sovite.Core.Telemetry do
  @moduledoc """
  The catalog of `:telemetry` events emitted by Sovite, and the default
  handler that turns them into log lines.

  Components emit events named `[:sovite, component, ...]`. Durations are
  in `:native` time units, as with `:telemetry.span/3`.

  | Event | Measurements | Metadata |
  |---|---|---|
  | `[:sovite, :listener, :connection, :start]` | `system_time` | `listener`, `remote_ip`, `remote_port` |
  | `[:sovite, :listener, :connection, :stop]` | `duration` | `listener`, `remote_ip`, `remote_port` |
  | `[:sovite, :listener, :connection, :rejected]` | | `listener`, `remote_ip`, `reason` |
  | `[:sovite, :smtp, :server, :session, :start]` | `system_time` | `session_id`, `remote_ip` |
  | `[:sovite, :smtp, :server, :session, :stop]` | `duration` | `session_id`, `remote_ip` |
  | `[:sovite, :smtp, :server, :command, :stop]` | `duration` | `session_id`, `remote_ip`, `command`, `argument`, `reply_code`, `reply` |
  | `[:sovite, :smtp, :server, :tls, :stop]` | `duration` | `session_id`, `remote_ip`, `protocol`, `cipher`, `sni`, `error` |
  | `[:sovite, :auth, :success]` | | `session_id`, `remote_ip`, `mechanism`, `username` |
  | `[:sovite, :auth, :failure]` | | `session_id`, `remote_ip`, `mechanism`, `username`, `reason` |
  | `[:sovite, :abuse, :penalty, :banned]` | `failures` | `penalty`, `key`, `ban_time` |
  | `[:sovite, :tls, :certificate, :loaded]` | | `cert_file`, `names`, `not_after` |
  | `[:sovite, :tls, :certificate, :error]` | | `cert_file`, `reason` |
  | `[:sovite, :tls, :acme, :issued]` | | `domains`, `not_after` |
  | `[:sovite, :tls, :acme, :failed]` | | `domains`, `reason` |
  | `[:sovite, :queue, :message, :enqueued]` | `size`, `recipients` | `queue_id`, `session_id`, `sender` |
  | `[:sovite, :queue, :message, :removed]` | | `queue_id`, `reason` (`delivered`, `bounced`, `expired`) |
  | `[:sovite, :queue, :message, :deferred]` | `attempts`, `recipients` | `queue_id`, `next_attempt` |
  | `[:sovite, :queue, :message, :corrupt]` | | `queue_id`, `reason` |
  | `[:sovite, :queue, :notification, :sent]` | `recipients` | `queue_id`, `kind`, `to`, `notification_id` |
  | `[:sovite, :queue, :notification, :discarded]` | `recipients` | `queue_id`, `kind`, `sender` |
  | `[:sovite, :smtp, :client, :delivery, :start]` | `system_time` | `queue_id`, `relay` |
  | `[:sovite, :smtp, :client, :delivery, :stop]` | `duration` | `queue_id`, `relay`, `recipient`, `status`, `reply` |
  | `[:sovite, :smtp, :client, :delivery, :exception]` | `duration` | `queue_id`, `relay`, `kind`, `reason` |
  | `[:sovite, :smtp, :message, :authenticated]` | | `session_id`, `queue_id`, `spf`, `dkim`, `arc`, `dmarc`, `disposition` |
  | `[:sovite, :dmarc, :report, :sent]` | `rows`, `messages` | `domain`, `report_id`, `queue_id`, `to` |
  | `[:sovite, :dmarc, :report, :skipped]` | `messages` | `domain`, `reason` |

  Delivery `:stop` events come once per recipient; `status` is
  `:delivered`, `:deferred`, or `:failed`. `:notification` events are
  about the original message: `queue_id` is its ID, and `notification_id`
  the ID of the queued notification.

  Message lifecycle events (`:queue`, delivery `:stop` and `:exception`),
  authentication results of received mail, sent DMARC reports,
  successful logins, certificate loads and ACME issuance, failed TLS
  handshakes, and SMTP commands that got a 4xx or 5xx reply are logged at
  `:info`. Corrupt messages, discarded notifications, failed logins, bans,
  certificate errors, and failed ACME orders are logged at `:warning`.
  All other events are logged at `:debug`.

  Failed logins are logged as `auth.failure: mechanism=PLAIN,
  reason=invalid_credentials, username=alice` with `remote_ip` in the
  metadata, ready for tools such as fail2ban.
  """

  require Logger

  alias Sovite.Core.Logging

  @handler_id {__MODULE__, :logger}

  @events [
    [:sovite, :listener, :connection, :start],
    [:sovite, :listener, :connection, :stop],
    [:sovite, :listener, :connection, :rejected],
    [:sovite, :smtp, :server, :session, :start],
    [:sovite, :smtp, :server, :session, :stop],
    [:sovite, :smtp, :server, :command, :stop],
    [:sovite, :smtp, :server, :tls, :stop],
    [:sovite, :auth, :success],
    [:sovite, :auth, :failure],
    [:sovite, :abuse, :penalty, :banned],
    [:sovite, :tls, :certificate, :loaded],
    [:sovite, :tls, :certificate, :error],
    [:sovite, :tls, :acme, :issued],
    [:sovite, :tls, :acme, :failed],
    [:sovite, :queue, :message, :enqueued],
    [:sovite, :queue, :message, :removed],
    [:sovite, :queue, :message, :deferred],
    [:sovite, :queue, :message, :corrupt],
    [:sovite, :queue, :notification, :sent],
    [:sovite, :queue, :notification, :discarded],
    [:sovite, :smtp, :client, :delivery, :start],
    [:sovite, :smtp, :client, :delivery, :stop],
    [:sovite, :smtp, :client, :delivery, :exception],
    [:sovite, :smtp, :message, :authenticated],
    [:sovite, :dmarc, :report, :sent],
    [:sovite, :dmarc, :report, :skipped]
  ]

  @info_events [
    [:sovite, :queue, :message, :enqueued],
    [:sovite, :queue, :message, :removed],
    [:sovite, :queue, :message, :deferred],
    [:sovite, :queue, :notification, :sent],
    [:sovite, :smtp, :client, :delivery, :stop],
    [:sovite, :smtp, :client, :delivery, :exception],
    [:sovite, :smtp, :message, :authenticated],
    [:sovite, :dmarc, :report, :sent],
    [:sovite, :auth, :success],
    [:sovite, :tls, :certificate, :loaded],
    [:sovite, :tls, :acme, :issued]
  ]

  @warning_events [
    [:sovite, :queue, :message, :corrupt],
    [:sovite, :queue, :notification, :discarded],
    [:sovite, :auth, :failure],
    [:sovite, :abuse, :penalty, :banned],
    [:sovite, :tls, :certificate, :error],
    [:sovite, :tls, :acme, :failed]
  ]

  @doc "Returns every event in the catalog."
  @spec events() :: [:telemetry.event_name()]
  def events, do: @events

  @doc "Attaches the logging handler to every cataloged event. Safe to call repeatedly."
  @spec attach_logger() :: :ok
  def attach_logger do
    _ = :telemetry.detach(@handler_id)
    :ok = :telemetry.attach_many(@handler_id, @events, &__MODULE__.handle_event/4, nil)
  end

  @doc "Detaches the logging handler."
  @spec detach_logger() :: :ok
  def detach_logger do
    _ = :telemetry.detach(@handler_id)
    :ok
  end

  @doc false
  def handle_event(event, measurements, metadata, _config) do
    level =
      cond do
        event in @warning_events -> :warning
        event in @info_events or rejected?(event, metadata) -> :info
        true -> :debug
      end

    name = event |> tl() |> Enum.join(".")

    Logger.log(level, fn -> format(name, measurements, metadata) end,
      queue_id: metadata[:queue_id],
      session_id: metadata[:session_id],
      remote_ip: format_ip(metadata[:remote_ip]),
      event: name
    )
  end

  defp format_ip(ip) when is_tuple(ip), do: Logging.format_ip(ip)
  defp format_ip(ip), do: ip

  defp rejected?([:sovite, :smtp, :server, :command, :stop], %{reply_code: code}), do: code >= 400
  defp rejected?([:sovite, :smtp, :server, :tls, :stop], %{error: error}), do: error != nil
  defp rejected?(_event, _metadata), do: false

  # Postfix-style "key=value, key=value" so existing log tooling stays usable.
  defp format(name, measurements, metadata) do
    pairs =
      measurements
      |> Map.update(:duration, nil, &System.convert_time_unit(&1, :native, :millisecond))
      |> Map.delete(:system_time)
      |> Map.merge(
        Map.drop(metadata, [:queue_id, :session_id, :remote_ip, :telemetry_span_context])
      )
      |> Map.reject(fn {_key, value} -> is_nil(value) end)
      |> Enum.sort()
      |> Enum.map_join(", ", fn {key, value} -> "#{key}=#{format_value(value)}" end)

    if pairs == "", do: name, else: name <> ": " <> pairs
  end

  # Metadata often holds network input (EHLO names, addresses). Quote
  # anything with control characters so it cannot forge log lines.
  defp format_value(value) when is_binary(value) do
    if String.valid?(value) and not String.match?(value, ~r/[\x00-\x1f\x7f]/),
      do: value,
      else: inspect(value)
  end

  defp format_value(value) when is_atom(value) or is_number(value), do: to_string(value)
  defp format_value(%DateTime{} = value), do: DateTime.to_iso8601(value)

  defp format_value(value) when is_tuple(value) do
    if :inet.is_ip_address(value), do: Logging.format_ip(value), else: inspect(value)
  end

  defp format_value([value | _] = list) when is_binary(value) do
    if Enum.all?(list, &is_binary/1),
      do: Enum.map_join(list, " ", &format_value/1),
      else: inspect(list)
  end

  defp format_value(value), do: inspect(value)
end
