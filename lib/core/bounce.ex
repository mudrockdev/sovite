defmodule Sovite.Core.Bounce do
  @moduledoc """
  The bounce service: tells senders about failed and delayed delivery,
  and about successful delivery when they ask for it (DSN, RFC 3461).

  Notifications are built with `Sovite.DSN` and queued like any other
  message, from the null sender (`MAIL FROM:<>`). The rules:

    * Failed recipients are reported to the sender in one notification
      per delivery attempt.
    * Delay warnings (`queue.delay_warning`) are sent once per message.
    * The `NOTIFY` parameter of each recipient decides which of these
      are sent for it; that is up to the caller. Success notifications
      (`NOTIFY=SUCCESS`) report recipients delivered to a mailbox,
      relayed to a server that does not support DSN, or expanded by an
      alias to several addresses.
    * Notifications carry the `ENVID` and each recipient's `ORCPT`. A
      failure notification for a message sent with `RET=FULL` returns
      the whole message, unless it is larger than `bounce.size_limit`
      or binary (`BINARYMIME`); otherwise, and for every other
      notification, only the header section.
    * Nothing is ever sent to the null sender (RFC 5321 §6.1, RFC 3834):
      a failed notification is a *double bounce*. It is reported to
      `bounce.double_bounce_recipient` when set, otherwise only logged.
      A failed double-bounce report is only logged, so notifications
      can never loop.
    * Notifications about a `REQUIRETLS` message are sent with
      `REQUIRETLS` too (RFC 8689 §4.3), and only include the message's
      header section, as if `RET=HDRS` (RFC 8689 §5).
    * Notifications about internationalized mail (internationalized
      addresses, or UTF-8 header fields in a message sent with
      `SMTPUTF8`) are RFC 6533 ones, sent with `SMTPUTF8`, see
      `Sovite.DSN`.
  """

  alias Sovite.DSN
  alias Sovite.Queue.{Entry, Envelope, ID, Spool}
  alias Sovite.SMTP.Params

  @typedoc """
  Options: `:hostname`, `:directory` (the spool), `:max_lifetime`
  (milliseconds, for "will retry until"), `:double_bounce_recipient`
  (or `nil`), and optionally `:expand`, a function that turns the
  notification's recipient into the addresses to queue it for (aliases),
  and `:size_limit`, the largest message returned whole (bytes, default
  50000).
  """
  @type opts :: %{
          required(:hostname) => String.t(),
          required(:directory) => Path.t(),
          required(:max_lifetime) => pos_integer(),
          required(:double_bounce_recipient) => String.t() | nil,
          optional(:expand) => (String.t() -> [String.t(), ...]),
          optional(:size_limit) => non_neg_integer()
        }

  @typedoc """
  Where the original message is, as returned by `Sovite.Queue.Spool.load/2`,
  possibly with more keys.
  """
  @type source :: %{
          required(:path) => Path.t(),
          required(:message_offset) => non_neg_integer(),
          required(:message_size) => non_neg_integer(),
          required(:prefix) => binary(),
          optional(atom()) => term()
        }

  @doc """
  Reports `recipients` (address and `Sovite.Queue.Record.details()`
  pairs) of the message in `entry`.

  Returns `{:ok, queue_id}` for the queued notification, `{:ok, nil}` when
  the rules say not to send one, or `{:error, reason}` if it could not be
  queued; the caller should then try again later.
  """
  @spec notify(:failure | :delay | :success, Entry.t(), source(), [{String.t(), map()}], opts()) ::
          {:ok, String.t() | nil} | {:error, term()}
  def notify(kind, %Entry{envelope: envelope} = entry, source, recipients, opts) do
    case notification_target(kind, envelope, opts) do
      nil ->
        :telemetry.execute(
          [:sovite, :queue, :notification, :discarded],
          %{recipients: length(recipients)},
          %{queue_id: envelope.queue_id, kind: kind, sender: envelope.sender}
        )

        {:ok, nil}

      {to, notification} ->
        send_notification(kind, notification, to, entry, source, recipients, opts)
    end
  end

  # Delay warnings and success notifications only go to real senders.
  defp notification_target(kind, %Envelope{sender: ""}, _opts) when kind in [:delay, :success],
    do: nil

  defp notification_target(kind, envelope, _opts) when kind in [:delay, :success],
    do: {envelope.sender, kind}

  defp notification_target(:failure, %Envelope{sender: ""} = envelope, opts),
    do: double_bounce(envelope, opts)

  defp notification_target(:failure, envelope, _opts), do: {envelope.sender, :failure}

  defp double_bounce(%Envelope{notification: :double_bounce}, _opts), do: nil
  defp double_bounce(_envelope, %{double_bounce_recipient: nil}), do: nil
  defp double_bounce(_envelope, %{double_bounce_recipient: to}), do: {to, :double_bounce}

  defp send_notification(kind, notification, to, entry, source, recipients, opts) do
    envelope = entry.envelope

    with {:ok, headers} <-
           Spool.read_headers(source.path, source.message_offset, source.message_size,
             prefix: source.prefix
           ),
         {:ok, content} <- content(kind, envelope, source, opts) do
      report = %{
        kind: kind,
        reporting_mta: opts.hostname,
        from: "MAILER-DAEMON@" <> opts.hostname,
        to: to,
        recipients: Enum.map(recipients, &dsn_recipient(&1, envelope)),
        headers: headers,
        content: content,
        envid: envelope.envid,
        future_release: envelope.hold && Params.format_hold(envelope.hold),
        queue_id: envelope.queue_id,
        smtputf8: envelope.smtputf8,
        arrival_date: envelope.received_at,
        will_retry_until: if(kind == :delay, do: retry_until(envelope, opts))
      }

      {message, body_type} = DSN.build(report)

      notification_envelope = %Envelope{
        queue_id: ID.generate(),
        sender: "",
        recipients: expand(opts, to),
        received_at: DateTime.utc_now(),
        protocol: "local",
        body_type: body_type,
        notification: notification,
        requiretls: envelope.requiretls,
        smtputf8: DSN.global?(report)
      }

      with {:ok, writer} <- Spool.open(opts.directory, notification_envelope),
           {:ok, writer} <- Spool.write(writer, message),
           {:ok, _path, _size} <- Spool.commit(writer) do
        :telemetry.execute(
          [:sovite, :queue, :notification, :sent],
          %{recipients: length(recipients)},
          %{
            queue_id: envelope.queue_id,
            kind: notification,
            to: to,
            notification_id: notification_envelope.queue_id
          }
        )

        {:ok, notification_envelope.queue_id}
      end
    end
  end

  # RET=FULL: the whole message, for failures, when it may be returned.
  defp content(:failure, %Envelope{ret: :full, requiretls: false} = envelope, source, opts)
       when envelope.body_type != :binarymime do
    if source.message_size <= Map.get(opts, :size_limit, 50_000) do
      source.path
      |> Spool.stream_message(source.message_offset, source.message_size, source.prefix)
      |> Enum.into(<<>>)
      |> then(&{:ok, &1})
    else
      {:ok, nil}
    end
  rescue
    error in File.Error -> {:error, error.reason}
  end

  defp content(_kind, _envelope, _source, _opts), do: {:ok, nil}

  # Notifications go through the recipient's aliases, like any mail.
  defp expand(%{expand: expand}, to), do: expand.(to)
  defp expand(_opts, to), do: [to]

  defp retry_until(%Envelope{received_at: %DateTime{} = received_at}, %{max_lifetime: lifetime}),
    do: DateTime.add(received_at, lifetime, :millisecond)

  defp retry_until(_envelope, _opts), do: nil

  defp dsn_recipient({address, details}, envelope) do
    base = %{
      recipient: address,
      status: details.status,
      last_attempt: details.at,
      action: details[:action] || :delivered,
      original_recipient: get_in(envelope.dsn, [address, :orcpt])
    }

    if details.smtp,
      do: Map.merge(base, %{diagnostic: details.reply, remote_mta: host(details.remote)}),
      else: Map.put(base, :reason, details.reply)
  end

  # "mx.example.com[192.0.2.25]" -> "mx.example.com"
  defp host(nil), do: nil
  defp host("[" <> _ = literal), do: literal

  defp host(remote) do
    remote |> :binary.split("[") |> hd()
  end
end
