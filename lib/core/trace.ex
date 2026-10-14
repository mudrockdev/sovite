defmodule Sovite.Core.Trace do
  @moduledoc """
  Follows a message through the logs, from the connection it came in on
  to its final delivery, for `sovitectl trace`.

  The message is named by its queue ID or its `Message-ID`. The trace
  collects:

    * the queue IDs of the message: those the `Message-ID` was accepted
      under (`smtp.message.accepted`), and the notifications sent about
      it (`queue.notification.sent`), which are traced too;
    * every line with one of those queue IDs;
    * every line of the SMTP sessions they were received in (`session_id`),
      such as the client's connection, login, and rejected commands.

  Lines come back in log order. Files are read twice, so the queue IDs
  found in the first pass can pull in earlier session lines; standard
  input is read into memory once.
  """

  alias Sovite.Core.LogReader

  @doc """
  Traces `id` (a queue ID, or a `Message-ID` with or without its angle
  brackets) through the log files at `paths` (`"-"` for standard input).
  Returns the message's queue IDs and the log entries.
  """
  @spec run(String.t(), [Path.t()]) :: %{queue_ids: [String.t()], entries: [LogReader.entry()]}
  def run(id, paths) do
    source =
      if "-" in paths,
        do: Enum.to_list(LogReader.stream(paths)),
        else: LogReader.stream(paths)

    {queue_ids, session_ids} = related(source, normalize(id))

    entries =
      Enum.filter(source, fn entry ->
        MapSet.member?(queue_ids, entry.queue_id) or MapSet.member?(session_ids, entry.session_id)
      end)

    %{queue_ids: Enum.sort(queue_ids), entries: entries}
  end

  # A Message-ID is matched without its angle brackets and in any case
  # of the domain; queue IDs are taken as they are.
  defp normalize(id) do
    id = String.trim(id)

    if String.contains?(id, "@"),
      do: {:message_id, id |> String.trim_leading("<") |> String.trim_trailing(">")},
      else: {:queue_id, id}
  end

  defp related(source, {:message_id, message_id}) do
    queue_ids =
      for %{event: "smtp.message.accepted", queue_id: queue_id, fields: fields} <- source,
          queue_id != nil,
          same_message_id?(fields["message_id"], message_id),
          into: MapSet.new(),
          do: queue_id

    follow(source, queue_ids)
  end

  defp related(source, {:queue_id, queue_id}), do: follow(source, MapSet.new([queue_id]))

  # Notifications about a traced message are traced too, and the
  # sessions the messages came in on.
  defp follow(source, queue_ids) do
    Enum.reduce(source, {queue_ids, MapSet.new()}, fn entry, {queue_ids, sessions} ->
      cond do
        not MapSet.member?(queue_ids, entry.queue_id) ->
          {queue_ids, sessions}

        entry.event == "queue.notification.sent" and entry.fields["notification_id"] ->
          {MapSet.put(queue_ids, entry.fields["notification_id"]), sessions}

        entry.event in ["smtp.message.accepted", "queue.message.enqueued"] and
            entry.session_id != nil ->
          {queue_ids, MapSet.put(sessions, entry.session_id)}

        true ->
          {queue_ids, sessions}
      end
    end)
  end

  defp same_message_id?(nil, _id), do: false

  defp same_message_id?(logged, id) do
    logged = logged |> String.trim_leading("<") |> String.trim_trailing(">")

    case {:binary.split(logged, "@"), :binary.split(id, "@")} do
      {[left, domain], [left, other]} -> String.downcase(domain) == String.downcase(other)
      _ -> logged == id
    end
  end
end
