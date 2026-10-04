defmodule Sovite.Core.Bounce do
  @moduledoc """
  The bounce service: tells senders about failed and delayed delivery.

  Notifications are built with `Sovite.DSN` and queued like any other
  message, from the null sender (`MAIL FROM:<>`). The rules:

    * Failed recipients are reported to the sender in one notification
      per delivery attempt.
    * Delay warnings (`queue.delay_warning`) are sent once per message.
    * Nothing is ever sent to the null sender (RFC 5321 §6.1, RFC 3834):
      a failed notification is a *double bounce*. It is reported to
      `bounce.double_bounce_recipient` when set, otherwise only logged.
      A failed double-bounce report is only logged, so notifications
      can never loop.
  """

  alias Sovite.DSN
  alias Sovite.Queue.{Entry, Envelope, ID, Spool}

  @typedoc """
  Options: `:hostname`, `:directory` (the spool), `:max_lifetime`
  (milliseconds, for "will retry until"), `:double_bounce_recipient`
  (or `nil`), and optionally `:expand`, a function that turns the
  notification's recipient into the addresses to queue it for (aliases).
  """
  @type opts :: %{
          required(:hostname) => String.t(),
          required(:directory) => Path.t(),
          required(:max_lifetime) => pos_integer(),
          required(:double_bounce_recipient) => String.t() | nil,
          optional(:expand) => (String.t() -> [String.t(), ...])
        }

  @typedoc "Where the original message is, as returned by `Sovite.Queue.Spool.load/2`."
  @type source :: %{
          path: Path.t(),
          message_offset: non_neg_integer(),
          message_size: non_neg_integer()
        }

  @doc """
  Reports `recipients` (address and `Sovite.Queue.Record.details()`
  pairs) of the message in `entry`.

  Returns `{:ok, queue_id}` for the queued notification, `{:ok, nil}` when
  the rules say not to send one, or `{:error, reason}` if it could not be
  queued; the caller should then try again later.
  """
  @spec notify(:failure | :delay, Entry.t(), source(), [{String.t(), map()}], opts()) ::
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

  # Delay warnings only go to real senders.
  defp notification_target(:delay, %Envelope{sender: ""}, _opts), do: nil
  defp notification_target(:delay, envelope, _opts), do: {envelope.sender, :delay}

  defp notification_target(:failure, %Envelope{sender: ""} = envelope, opts),
    do: double_bounce(envelope, opts)

  defp notification_target(:failure, envelope, _opts), do: {envelope.sender, :failure}

  defp double_bounce(%Envelope{notification: :double_bounce}, _opts), do: nil
  defp double_bounce(_envelope, %{double_bounce_recipient: nil}), do: nil
  defp double_bounce(_envelope, %{double_bounce_recipient: to}), do: {to, :double_bounce}

  defp send_notification(kind, notification, to, entry, source, recipients, opts) do
    envelope = entry.envelope

    with {:ok, headers} <-
           Spool.read_headers(source.path, source.message_offset, source.message_size) do
      {message, body_type} =
        DSN.build(%{
          kind: kind,
          reporting_mta: opts.hostname,
          from: "MAILER-DAEMON@" <> opts.hostname,
          to: to,
          recipients: Enum.map(recipients, &dsn_recipient/1),
          headers: headers,
          queue_id: envelope.queue_id,
          arrival_date: envelope.received_at,
          will_retry_until: if(kind == :delay, do: retry_until(envelope, opts))
        })

      notification_envelope = %Envelope{
        queue_id: ID.generate(),
        sender: "",
        recipients: expand(opts, to),
        received_at: DateTime.utc_now(),
        protocol: "local",
        body_type: body_type,
        notification: notification
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

  # Notifications go through the recipient's aliases, like any mail.
  defp expand(%{expand: expand}, to), do: expand.(to)
  defp expand(_opts, to), do: [to]

  defp retry_until(%Envelope{received_at: %DateTime{} = received_at}, %{max_lifetime: lifetime}),
    do: DateTime.add(received_at, lifetime, :millisecond)

  defp retry_until(_envelope, _opts), do: nil

  defp dsn_recipient({address, details}) do
    base = %{recipient: address, status: details.status, last_attempt: details.at}

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
