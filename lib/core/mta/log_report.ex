defmodule Sovite.Core.MTA.LogReport do
  @moduledoc """
  A summary of mail traffic from the logs, in the style of Postfix's
  `pflogsumm`, for `sovitectl report`.

  It counts messages received, recipients delivered, deferred, and
  bounced, messages held, discarded, expired, and deleted, and commands
  rejected; bytes received and delivered; distinct senders and
  recipients. Then, at most `:top` lines each: traffic per hour (or per
  day, for more than one day), the domains delivered to with their
  delays, the senders and sender domains, and the most common deferral,
  bounce, and rejection reasons, warnings, and failed logins.

  It reads the `info` level events (see `Sovite.Core.Telemetry`), so
  logs at `warning` and above give an incomplete report.

  ## Options

    * `:top` - lines in each list. Defaults to 10.
    * `:date` - only count lines of this `Date`. Defaults to all.
  """

  alias Sovite.Core.LogReader

  @doc "Builds the report from log entries (see `Sovite.Core.LogReader`)."
  @spec build(Enumerable.t(LogReader.entry()), keyword()) :: map()
  def build(entries, opts \\ []) do
    date = Keyword.get(opts, :date)

    entries
    |> Stream.filter(
      &(date == nil or (&1.time != nil and NaiveDateTime.to_date(&1.time) == date))
    )
    |> Enum.reduce(new(), &count/2)
    |> Map.put(:top, Keyword.get(opts, :top, 10))
  end

  defp new do
    %{
      totals: %{
        received: 0,
        delivered: 0,
        deferred: 0,
        bounced: 0,
        rejected: 0,
        temporary_rejected: 0,
        held: 0,
        discarded: 0,
        expired: 0,
        deleted: 0,
        notifications: 0,
        warnings: 0,
        failed_logins: 0,
        bytes_received: 0,
        bytes_delivered: 0
      },
      # Per queue ID, until the message is removed: size and arrival.
      messages: %{},
      senders: %{},
      sender_domains: %{},
      recipients: MapSet.new(),
      domains: %{},
      deferrals: %{},
      bounces: %{},
      rejections: %{},
      warnings: %{},
      failed_logins: %{},
      periods: %{},
      first: nil,
      last: nil
    }
  end

  defp count(entry, report) do
    report
    |> span(entry.time)
    |> count_event(entry.event, entry)
    |> count_warning(entry)
  end

  defp span(report, nil), do: report

  defp span(report, time) do
    %{
      report
      | first:
          if(report.first == nil or before?(time, report.first), do: time, else: report.first),
        last: if(report.last == nil or before?(report.last, time), do: time, else: report.last)
    }
  end

  defp before?(a, b), do: NaiveDateTime.compare(a, b) == :lt

  defp count_event(report, "queue.message.enqueued", entry) do
    size = int(entry.fields["size"])
    sender = sender(entry.fields["sender"])

    report
    |> bump([:totals, :received])
    |> bump([:totals, :bytes_received], size)
    |> period(entry.time, :received)
    |> put_message(entry.queue_id, %{size: size, at: entry.time})
    |> tally(:senders, sender, size)
    |> tally(:sender_domains, domain(sender), size)
  end

  defp count_event(report, "smtp.client.delivery.stop", entry) do
    fields = entry.fields
    recipient = fields["recipient"]

    case fields["status"] do
      "delivered" ->
        message = Map.get(report.messages, entry.queue_id, %{})
        size = Map.get(message, :size, 0)
        delay = delay(message[:at], entry.time)

        report
        |> bump([:totals, :delivered])
        |> bump([:totals, :bytes_delivered], size)
        |> period(entry.time, :delivered)
        |> Map.update!(:recipients, &if(recipient, do: MapSet.put(&1, recipient), else: &1))
        |> domain_delivery(domain(recipient), size, delay)

      "deferred" ->
        report
        |> bump([:totals, :deferred])
        |> period(entry.time, :deferred)
        |> tally(:deferrals, reason(fields["reply"]), 0)

      "failed" ->
        report
        |> bump([:totals, :bounced])
        |> period(entry.time, :bounced)
        |> tally(:bounces, reason(fields["reply"]), 0)

      _ ->
        report
    end
  end

  defp count_event(report, "smtp.server.command.stop", entry) do
    case int(entry.fields["reply_code"]) do
      code when code >= 500 ->
        report
        |> bump([:totals, :rejected])
        |> period(entry.time, :rejected)
        |> tally(:rejections, reason(entry.fields["reply"]), 0)

      code when code >= 400 ->
        report
        |> bump([:totals, :temporary_rejected])
        |> tally(:rejections, reason(entry.fields["reply"]), 0)

      _ ->
        report
    end
  end

  defp count_event(report, "queue.message.removed", entry) do
    report =
      case entry.fields["reason"] do
        "expired" -> bump(report, [:totals, :expired])
        "deleted" -> bump(report, [:totals, :deleted])
        _ -> report
      end

    %{report | messages: Map.delete(report.messages, entry.queue_id)}
  end

  defp count_event(report, event, _entry)
       when event in ["smtp.message.held", "queue.message.held"],
       do: bump(report, [:totals, :held])

  defp count_event(report, "smtp.message.discarded", _entry),
    do: bump(report, [:totals, :discarded])

  defp count_event(report, "queue.notification.sent", _entry),
    do: bump(report, [:totals, :notifications])

  defp count_event(report, "auth.failure", entry) do
    key = "#{entry.fields["username"] || "-"} from #{entry.remote_ip || "?"}"

    report
    |> bump([:totals, :failed_logins])
    |> tally(:failed_logins, key, 0)
  end

  defp count_event(report, _event, _entry), do: report

  defp count_warning(report, %{level: level} = entry) when level in ["warning", "error"] do
    report
    |> bump([:totals, :warnings])
    |> tally(:warnings, entry.event || warning_text(entry.line), 0)
  end

  defp count_warning(report, _entry), do: report

  defp warning_text(line) do
    line |> String.replace(~r/\A.*?\[(warning|error)\] /, "") |> String.slice(0, 80)
  end

  defp put_message(report, nil, _message), do: report
  defp put_message(report, id, message), do: put_in(report.messages[id], message)

  defp bump(report, path, by \\ 1), do: update_in(report, path, &(&1 + by))

  defp tally(report, _key, nil, _size), do: report

  defp tally(report, key, name, size) do
    Map.update!(report, key, fn counts ->
      Map.update(counts, name, {1, size}, fn {n, bytes} -> {n + 1, bytes + size} end)
    end)
  end

  defp domain_delivery(report, nil, _size, _delay), do: report

  defp domain_delivery(report, domain, size, delay) do
    update_in(report.domains, fn domains ->
      Map.update(domains, domain, {1, size, delay, delay}, fn {n, bytes, total, max} ->
        {n + 1, bytes + size, total + delay, max(max, delay)}
      end)
    end)
  end

  # Hours of one day, or days.
  defp period(report, nil, _kind), do: report

  defp period(report, time, kind) do
    key = {NaiveDateTime.to_date(time), time.hour}

    update_in(report.periods, fn periods ->
      periods
      |> Map.put_new(key, %{received: 0, delivered: 0, deferred: 0, bounced: 0, rejected: 0})
      |> update_in([key, kind], &(&1 + 1))
    end)
  end

  defp delay(%NaiveDateTime{} = from, %NaiveDateTime{} = to),
    do: max(NaiveDateTime.diff(to, from), 0)

  defp delay(_from, _to), do: 0

  defp sender(nil), do: nil
  defp sender(""), do: "<>"
  defp sender(sender), do: String.downcase(sender)

  defp domain(nil), do: nil
  defp domain("<>"), do: nil

  defp domain(address) do
    case :binary.split(address, "@", [:global]) do
      [_ | _] = parts when length(parts) > 1 -> parts |> List.last() |> String.downcase()
      _ -> nil
    end
  end

  # Replies differ by queue IDs and addresses; keep the gist.
  defp reason(nil), do: "(no reply)"

  defp reason(reply) do
    reply
    |> String.replace(~r/<[^>]*>/, "<...>")
    |> String.replace(~r/\b[0-9A-Za-z]{12,}\b/, "...")
    |> String.slice(0, 100)
  end

  defp int(nil), do: 0

  defp int(value) do
    case Integer.parse(value) do
      {n, _} -> n
      :error -> 0
    end
  end

  ## Output

  @doc "Formats a report from `build/2` as text."
  @spec format(map()) :: String.t()
  def format(report) do
    [
      header(report),
      totals(report.totals, report),
      periods(report),
      domains(report),
      list("Senders by message count", report.senders, report.top, &bytes_line/2),
      list("Sender domains by message count", report.sender_domains, report.top, &bytes_line/2),
      list("Deferral reasons", report.deferrals, report.top, &count_line/2),
      list("Bounce reasons", report.bounces, report.top, &count_line/2),
      list("Rejection reasons", report.rejections, report.top, &count_line/2),
      list("Warnings", report.warnings, report.top, &count_line/2),
      list("Failed logins", report.failed_logins, report.top, &count_line/2)
    ]
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("\n")
  end

  defp header(%{first: nil}), do: "Sovite log summary: no log lines\n"

  defp header(report),
    do:
      "Sovite log summary for #{NaiveDateTime.truncate(report.first, :second)} " <>
        "to #{NaiveDateTime.truncate(report.last, :second)}\n"

  defp totals(totals, report) do
    """
    Grand Totals
    ------------
    #{pad(totals.received)}   received
    #{pad(totals.delivered)}   delivered (recipients)
    #{pad(totals.deferred)}   deferred (recipient attempts)
    #{pad(totals.bounced)}   bounced (recipients)
    #{pad(totals.rejected)}   rejected (commands with 5xx replies)
    #{pad(totals.temporary_rejected)}   temporarily rejected (4xx)
    #{pad(totals.held)}   held
    #{pad(totals.discarded)}   discarded
    #{pad(totals.expired)}   expired
    #{pad(totals.deleted)}   deleted by the administrator
    #{pad(totals.notifications)}   notifications sent
    #{pad(totals.warnings)}   warnings
    #{pad(totals.failed_logins)}   failed logins

    #{pad(size(totals.bytes_received))}   bytes received
    #{pad(size(totals.bytes_delivered))}   bytes delivered
    #{pad(map_size(report.senders))}   senders
    #{pad(map_size(report.sender_domains))}   sending domains
    #{pad(MapSet.size(report.recipients))}   recipients
    #{pad(map_size(report.domains))}   recipient domains
    """
  end

  defp periods(%{periods: periods}) when map_size(periods) == 0, do: ""

  defp periods(report) do
    days = report.periods |> Map.keys() |> Enum.map(&elem(&1, 0)) |> Enum.uniq()

    rows =
      if length(days) == 1 do
        for {{_date, hour}, counts} <- Enum.sort(report.periods),
            do: {"#{pad2(hour)}:00-#{pad2(hour)}:59", counts}
      else
        report.periods
        |> Enum.group_by(fn {{date, _hour}, _counts} -> date end, &elem(&1, 1))
        |> Enum.sort_by(&elem(&1, 0), Date)
        |> Enum.map(fn {date, counts} -> {Date.to_iso8601(date), sum_counts(counts)} end)
      end

    title = if length(days) == 1, do: "Per-Hour Traffic", else: "Per-Day Traffic"

    lines =
      for {label, c} <- rows do
        String.pad_trailing(label, 12) <>
          Enum.map_join(
            [c.received, c.delivered, c.deferred, c.bounced, c.rejected],
            &String.pad_leading(Integer.to_string(&1), 10)
          )
      end

    Enum.join(
      [
        title,
        String.duplicate("-", String.length(title)),
        String.pad_trailing("", 12) <>
          Enum.map_join(
            ~w(received delivered deferred bounced rejected),
            &String.pad_leading(&1, 10)
          )
        | lines
      ],
      "\n"
    ) <> "\n"
  end

  defp sum_counts(counts) do
    Enum.reduce(counts, fn a, b -> Map.merge(a, b, fn _key, x, y -> x + y end) end)
  end

  defp domains(%{domains: domains}) when map_size(domains) == 0, do: ""

  defp domains(report) do
    lines =
      report.domains
      |> Enum.sort_by(fn {domain, {n, _bytes, _total, _max}} -> {-n, domain} end)
      |> Enum.take(report.top)
      |> Enum.map(fn {domain, {n, bytes, total, max}} ->
        pad(n) <>
          pad(size(bytes)) <>
          String.pad_leading(duration(div(total, n)), 8) <>
          String.pad_leading(duration(max), 8) <> "   " <> domain
      end)

    Enum.join(
      [
        "Recipient Domains by delivered count",
        "------------------------------------",
        "      sent     bytes  avg.dly  max.dly   domain" | lines
      ],
      "\n"
    ) <> "\n"
  end

  defp list(_title, counts, _top, _line) when map_size(counts) == 0, do: ""

  defp list(title, counts, top, line) do
    lines =
      counts
      |> Enum.sort_by(fn {name, {n, _bytes}} -> {-n, name} end)
      |> Enum.take(top)
      |> Enum.map(fn {name, value} -> line.(name, value) end)

    Enum.join([title, String.duplicate("-", String.length(title)) | lines], "\n") <> "\n"
  end

  defp bytes_line(name, {n, bytes}), do: pad(n) <> pad(size(bytes)) <> "   " <> name
  defp count_line(name, {n, _bytes}), do: pad(n) <> "   " <> name

  defp pad(value) when is_integer(value), do: pad(Integer.to_string(value))
  defp pad(value), do: String.pad_leading(value, 10)
  defp pad2(n), do: n |> Integer.to_string() |> String.pad_leading(2, "0")

  defp size(bytes) when bytes >= 1024 * 1024 * 1024, do: "#{div(bytes, 1024 * 1024 * 1024)}g"
  defp size(bytes) when bytes >= 1024 * 1024, do: "#{div(bytes, 1024 * 1024)}m"
  defp size(bytes) when bytes >= 1024, do: "#{div(bytes, 1024)}k"
  defp size(bytes), do: Integer.to_string(bytes)

  defp duration(seconds) when seconds >= 86_400, do: "#{Float.round(seconds / 86_400, 1)}d"
  defp duration(seconds) when seconds >= 3600, do: "#{Float.round(seconds / 3600, 1)}h"
  defp duration(seconds) when seconds >= 60, do: "#{Float.round(seconds / 60, 1)}m"
  defp duration(seconds), do: "#{seconds}s"
end
