defmodule Sovite.Core.QueueInfo do
  @moduledoc """
  Reads the queue directory for `sovitectl queue` and the admin API:
  lists of queued messages, and the details of one. Everything returned
  is plain maps, strings, and numbers, ready to be encoded as JSON.

  It only reads files, so it works whether or not the MTA runs. The
  messages are read without checking their checksums; a file that cannot
  be read at all is listed with an `error`.
  """

  alias Sovite.Message.Headers
  alias Sovite.Queue.{Entry, Envelope, ID, Spool}

  # The queues listed, in the order a message passes through them.
  @queues [:incoming, :active, :deferred, :hold, :corrupt]

  @doc "The queues `list/2` can list."
  @spec queues() :: [Spool.queue()]
  def queues, do: @queues

  @doc """
  The messages in `queues` (by default all), oldest first:

    * `queue_id`, `queue`, `size` (bytes), `received_at`, `sender`
    * `recipients` - how many, and `pending`, those not delivered yet
    * `attempts`, `next_attempt`, and `reason`, the last error of a
      pending recipient
    * `priority`, and `release_at` for a message on hold for
      `FUTURERELEASE`

  Options: `:queues`, and `:limit`, the most messages returned.
  """
  @spec list(Path.t(), keyword()) :: [map()]
  def list(directory, opts \\ []) do
    queues = Keyword.get(opts, :queues, @queues)

    messages =
      for queue <- queues,
          {:ok, ids} <- [Spool.list(directory, queue)],
          id <- ids,
          do: summary(directory, queue, id)

    messages = Enum.sort_by(messages, &{&1[:received_at] || "", &1.queue_id})

    case Keyword.get(opts, :limit) do
      nil -> messages
      limit -> Enum.take(messages, limit)
    end
  end

  @doc "The number of messages in each queue."
  @spec counts(Path.t()) :: %{Spool.queue() => non_neg_integer()}
  def counts(directory) do
    Map.new(@queues, fn queue ->
      case Spool.list(directory, queue) do
        {:ok, ids} -> {queue, length(ids)}
        {:error, _} -> {queue, 0}
      end
    end)
  end

  @doc "The queue message `id` is in, or `nil`."
  @spec locate(Path.t(), String.t()) :: Spool.queue() | nil
  def locate(directory, id) do
    if ID.valid?(id),
      do: Enum.find(@queues, &File.exists?(Spool.path(directory, &1, id))),
      else: nil
  end

  @doc """
  The details of message `id`: its summary, the rest of its envelope
  (client, `HELO` name, protocol, login, extension parameters), each
  recipient's status and last reply, and the message's header section
  (`headers`, at most 64 KiB) with its `message_id` and `subject`.
  """
  @spec show(Path.t(), String.t()) :: {:ok, map()} | {:error, :not_found | term()}
  def show(directory, id) do
    with queue when queue != nil <- locate(directory, id),
         path = Spool.path(directory, queue, id),
         {:ok, loaded} <- Spool.load(path, verify: false) do
      entry = Entry.new(loaded.envelope, loaded.records)
      headers = headers(path, loaded)
      fields = Headers.parse(headers)

      details =
        queue
        |> summarize(loaded, entry)
        |> Map.merge(envelope_details(loaded.envelope))
        |> Map.merge(%{
          recipient_status: Enum.map(loaded.envelope.recipients, &recipient(entry, &1)),
          headers: headers,
          message_id: Headers.get(fields, "message-id"),
          subject: Headers.get(fields, "subject")
        })

      {:ok, details}
    else
      nil -> {:error, :not_found}
      {:error, :enoent} -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  defp summary(directory, queue, id) do
    case Spool.load(Spool.path(directory, queue, id), verify: false) do
      {:ok, loaded} -> summarize(queue, loaded, Entry.new(loaded.envelope, loaded.records))
      {:error, reason} -> %{queue_id: id, queue: Atom.to_string(queue), error: inspect(reason)}
    end
  end

  defp summarize(queue, loaded, entry) do
    envelope = loaded.envelope
    pending = Entry.pending(entry)

    %{
      queue_id: envelope.queue_id,
      queue: Atom.to_string(queue),
      size: loaded.message_size,
      received_at: time(envelope.received_at),
      sender: envelope.sender,
      recipients: length(envelope.recipients),
      pending: pending,
      attempts: entry.attempts,
      next_attempt: time(entry.next_attempt),
      reason: Enum.find_value(pending, &reply(entry.recipients[&1].details)),
      priority: envelope.priority,
      release_at: time(Envelope.release_time(envelope))
    }
  end

  defp envelope_details(envelope) do
    %{
      session_id: envelope.session_id,
      client: envelope.remote_ip && envelope.remote_ip |> :inet.ntoa() |> List.to_string(),
      helo: envelope.helo,
      protocol: envelope.protocol,
      user: envelope.auth_user,
      body_type: envelope.body_type && Atom.to_string(envelope.body_type),
      requiretls: envelope.requiretls,
      smtputf8: envelope.smtputf8,
      content_filter: envelope.content_filter,
      envid: envelope.envid,
      ret: envelope.ret && Atom.to_string(envelope.ret),
      deliver_by: envelope.deliver_by && time(envelope.deliver_by.deadline)
    }
  end

  defp recipient(entry, address) do
    %{status: status, details: details, notified: notified} = entry.recipients[address]

    %{
      address: address,
      status: Atom.to_string(status),
      code: details && details.status,
      reply: reply(details),
      remote: details && details.remote,
      at: details && time(details.at),
      notified: notified
    }
  end

  defp headers(path, loaded) do
    case Spool.read_headers(path, loaded.message_offset, loaded.message_size,
           prefix: loaded.prefix
         ) do
      # Headers are 8-bit at times; JSON needs UTF-8.
      {:ok, headers} -> String.replace_invalid(headers)
      {:error, _} -> ""
    end
  end

  defp reply(nil), do: nil
  defp reply(details), do: details.reply

  defp time(nil), do: nil
  defp time(%DateTime{} = time), do: DateTime.to_iso8601(time)
end
