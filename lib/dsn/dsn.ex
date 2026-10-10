defmodule Sovite.DSN do
  @moduledoc """
  Builds delivery status notifications (RFC 3464), the messages that tell
  a sender their mail was not delivered (or not yet).

  A notification is a `multipart/report` (RFC 6522) with three parts: a
  human-readable explanation, a `message/delivery-status` report for
  programs, and the headers of the original message
  (`text/rfc822-headers`; the body is not returned).

      DSN.build(%{
        kind: :failure,
        reporting_mta: "mx.example.com",
        from: "MAILER-DAEMON@mx.example.com",
        to: "alice@example.com",
        recipients: [
          %{recipient: "bob@example.net", status: "5.1.1", remote_mta: "mx.example.net",
            diagnostic: "550 5.1.1 User unknown"}
        ],
        headers: "From: alice@example.com\\r\\nSubject: hi\\r\\n\\r\\n"
      })

  The result is a complete message with CRLF line endings. Send it with
  the null reverse-path (`MAIL FROM:<>`), as RFC 5321 §6.1 requires, so a
  failing notification never causes another one.

  Text from remote servers (diagnostics) is untrusted: control and
  non-ASCII characters are replaced with `?`, and long values are cut,
  so it cannot inject header fields or MIME boundaries.

  ## Internationalized notifications

  A notification about internationalized mail is an RFC 6533 one (see
  `global?/1`): the report is `message/global-delivery-status`, the
  headers are `message/global-headers`, the explanation is UTF-8, and
  internationalized addresses are given with the `utf-8` address type
  (`Final-Recipient: utf-8; jürgen@example.com`). Untrusted text keeps
  its UTF-8 characters then, but never control characters. Such a
  notification must be sent with `SMTPUTF8`.
  """

  alias Sovite.Message.{Date, MessageID}

  @typedoc """
  One recipient in the report.

    * `:recipient` - the address. Required.
    * `:status` - enhanced status code, such as `"5.1.1"`. Required.
    * `:remote_mta` - host name of the server that gave `:diagnostic`.
    * `:diagnostic` - the remote server's SMTP reply.
    * `:reason` - a local explanation, used when there is no SMTP reply
      (for example "Host or domain name not found").
    * `:last_attempt` - time of the last delivery attempt.
  """
  @type recipient :: %{
          required(:recipient) => String.t(),
          required(:status) => String.t(),
          optional(:remote_mta) => String.t() | nil,
          optional(:diagnostic) => String.t() | nil,
          optional(:reason) => String.t() | nil,
          optional(:last_attempt) => DateTime.t() | nil
        }

  @typedoc """
  The report.

    * `:kind` - `:failure` (the listed recipients will never get the
      message) or `:delay` (still trying). Required.
    * `:reporting_mta` - this server's host name. Required.
    * `:from` - address in the `From:` field, usually
      `MAILER-DAEMON@<host>`. Required.
    * `:to` - the original sender. Required.
    * `:recipients` - at least one. Required.
    * `:headers` - the original message's header section.
    * `:queue_id` - the original message's queue ID.
    * `:smtputf8` - the original message was sent with `SMTPUTF8`, so
      its header fields may be UTF-8 (RFC 6532).
    * `:arrival_date` - when the original message was received.
    * `:will_retry_until` - for `:delay`, when delivery will be given up.
    * `:date`, `:message_id`, `:boundary` - default to now, a new ID, and
      a random boundary.
  """
  @type report :: %{
          required(:kind) => :failure | :delay,
          required(:reporting_mta) => String.t(),
          required(:from) => String.t(),
          required(:to) => String.t(),
          required(:recipients) => [recipient(), ...],
          optional(:headers) => binary() | nil,
          optional(:queue_id) => String.t() | nil,
          optional(:smtputf8) => boolean(),
          optional(:arrival_date) => DateTime.t() | nil,
          optional(:will_retry_until) => DateTime.t() | nil,
          optional(:date) => DateTime.t(),
          optional(:message_id) => String.t(),
          optional(:boundary) => String.t()
        }

  @max_value 900

  @doc """
  Whether the notification for `report` is an internationalized one
  (RFC 6533): an address in it is internationalized, or the original
  message was sent with `SMTPUTF8` and has UTF-8 header fields.
  """
  @spec global?(report()) :: boolean()
  def global?(report) do
    addresses = [report.to | Enum.map(report.recipients, & &1.recipient)]

    Enum.any?(addresses, &(not ascii?(&1))) or
      (Map.get(report, :smtputf8, false) and not ascii?(Map.get(report, :headers) || ""))
  end

  @doc """
  Builds the notification message. Returns the message and its body type:
  `:"8bitmime"` if it contains 8-bit bytes (the original headers, or an
  internationalized notification), otherwise `:"7bit"`.
  """
  @spec build(report()) :: {binary(), :"7bit" | :"8bitmime"}
  def build(%{kind: kind, recipients: [_ | _]} = report) when kind in [:failure, :delay] do
    boundary = Map.get_lazy(report, :boundary, &boundary/0)
    headers = report |> Map.get(:headers) |> Kernel.||("") |> ensure_crlf()
    global = global?(report)
    report = Map.put(report, :global, global)

    {text_type, status_type, headers_type} =
      if global,
        do:
          {"text/plain; charset=utf-8", "message/global-delivery-status",
           "message/global-headers"},
        else: {"text/plain; charset=us-ascii", "message/delivery-status", "text/rfc822-headers"}

    message =
      IO.iodata_to_binary([
        header_fields(report, boundary),
        "\r\n",
        "This is a MIME-encapsulated message.\r\n\r\n",
        part(boundary, text_type, "Notification", if(global, do: "8bit")),
        text(report),
        part(boundary, status_type, "Delivery report", if(global, do: "8bit")),
        status_fields(report),
        part(
          boundary,
          headers_type,
          if(kind == :failure,
            do: "Undelivered Message Headers",
            else: "Delayed Message Headers"
          ),
          if(not ascii?(headers), do: "8bit")
        ),
        headers,
        "\r\n--",
        boundary,
        "--\r\n"
      ])

    {message, if(ascii?(message), do: :"7bit", else: :"8bitmime")}
  end

  defp header_fields(report, boundary) do
    date = Map.get_lazy(report, :date, &DateTime.utc_now/0)

    message_id =
      Map.get_lazy(report, :message_id, fn -> MessageID.generate(report.reporting_mta) end)

    subject =
      case report.kind do
        :failure -> "Undelivered Mail Returned to Sender"
        :delay -> "Delayed Mail (still being retried)"
      end

    [
      "From: Mail Delivery System <",
      report.from,
      ">\r\n",
      "To: <",
      clean(report.to, report.global),
      ">\r\n",
      "Subject: ",
      subject,
      "\r\n",
      "Date: ",
      Date.format(date),
      "\r\n",
      "Message-ID: ",
      message_id,
      "\r\n",
      # RFC 3834 §5: notifications are automatic replies.
      "Auto-Submitted: auto-replied\r\n",
      "MIME-Version: 1.0\r\n",
      "Content-Type: multipart/report; report-type=",
      if(report.global, do: "global-delivery-status", else: "delivery-status"),
      ";\r\n",
      "\tboundary=\"",
      boundary,
      "\"\r\n"
    ]
  end

  defp part(boundary, type, description, encoding) do
    [
      "\r\n--",
      boundary,
      "\r\nContent-Type: ",
      type,
      "\r\nContent-Description: ",
      description,
      "\r\n",
      if(encoding, do: ["Content-Transfer-Encoding: ", encoding, "\r\n"], else: []),
      "\r\n"
    ]
  end

  defp text(report) do
    intro =
      case report.kind do
        :failure ->
          [
            "Your message could not be delivered to one or more recipients.\r\n",
            "The reasons are below. This is a permanent error; the headers of\r\n",
            "your message are attached.\r\n"
          ]

        :delay ->
          [
            "Your message has not been delivered yet to one or more recipients.\r\n",
            "The reasons are below. Delivery will be retried",
            if(report[:will_retry_until],
              do: [" until\r\n", Date.format(report.will_retry_until)],
              else: []
            ),
            ".\r\nYou do not need to send the message again.\r\n"
          ]
      end

    global = report.global

    [
      "This is the mail system at host ",
      clean(report.reporting_mta),
      ".\r\n\r\n",
      intro,
      "\r\n",
      Enum.map(report.recipients, fn rcpt ->
        ["<", clean(rcpt.recipient, global), ">: ", clean(explanation(rcpt), global), "\r\n"]
      end)
    ]
  end

  defp explanation(%{diagnostic: diagnostic, remote_mta: remote} = rcpt)
       when is_binary(diagnostic) and is_binary(remote),
       do: "host #{remote} said: #{diagnostic}" <> reason_suffix(rcpt)

  defp explanation(%{diagnostic: diagnostic}) when is_binary(diagnostic), do: diagnostic
  defp explanation(%{reason: reason}) when is_binary(reason), do: reason
  defp explanation(%{status: status}), do: "delivery status #{status}"

  defp reason_suffix(%{reason: reason}) when is_binary(reason), do: " (#{reason})"
  defp reason_suffix(_rcpt), do: ""

  defp status_fields(report) do
    action = if report.kind == :failure, do: "failed", else: "delayed"
    global = report.global

    message_fields = [
      field("Reporting-MTA", "dns; " <> report.reporting_mta),
      field("X-Sovite-Queue-ID", report[:queue_id]),
      field("Arrival-Date", report[:arrival_date] && Date.format(report.arrival_date))
    ]

    recipient_fields =
      Enum.map(report.recipients, fn rcpt ->
        [
          "\r\n",
          field("Final-Recipient", address_type(rcpt.recipient), global),
          field("Action", action),
          field("Status", rcpt.status),
          field("Remote-MTA", rcpt[:remote_mta] && "dns; " <> rcpt.remote_mta),
          field("Diagnostic-Code", rcpt[:diagnostic] && "smtp; " <> rcpt.diagnostic, global),
          field("Last-Attempt-Date", rcpt[:last_attempt] && Date.format(rcpt.last_attempt)),
          field(
            "Will-Retry-Until",
            report.kind == :delay && report[:will_retry_until] &&
              Date.format(report.will_retry_until)
          )
        ]
      end)

    [message_fields, recipient_fields]
  end

  # RFC 6533 §3: the utf-8 address type for internationalized addresses.
  defp address_type(address) do
    if ascii?(address), do: "rfc822; " <> address, else: "utf-8; " <> address
  end

  defp field(name, value, global \\ false)
  defp field(_name, value, _global) when value in [nil, false], do: []
  defp field(name, value, global), do: [name, ": ", clean(value, global), "\r\n"]

  # Untrusted text in a header-like field: printable ASCII only, or in an
  # internationalized notification UTF-8 without control characters;
  # bounded.
  defp clean(value, global \\ false)

  defp clean(value, false) do
    value =
      for <<c <- value>>, into: "" do
        if c in 32..126, do: <<c>>, else: "?"
      end

    if byte_size(value) > @max_value, do: binary_part(value, 0, @max_value) <> "...", else: value
  end

  defp clean(value, true) do
    {kept, _bytes} =
      value
      |> String.replace_invalid("?")
      |> String.to_charlist()
      |> Enum.reduce_while({[], 0}, fn c, {acc, bytes} ->
        c = if c in 32..126 or c > 0x9F, do: c, else: ??
        size = byte_size(<<c::utf8>>)

        if bytes + size > @max_value,
          do: {:halt, {["..." | acc], bytes}},
          else: {:cont, {[<<c::utf8>> | acc], bytes + size}}
      end)

    kept |> Enum.reverse() |> IO.iodata_to_binary()
  end

  defp ensure_crlf(""), do: ""

  defp ensure_crlf(headers) do
    if String.ends_with?(headers, "\r\n"), do: headers, else: headers <> "\r\n"
  end

  defp ascii?(binary), do: for(<<c <- binary>>, reduce: true, do: (acc -> acc and c < 128))

  defp boundary do
    "=_sovite_" <>
      (15 |> :crypto.strong_rand_bytes() |> Base.encode32(case: :lower, padding: false))
  end
end
