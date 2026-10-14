defmodule Sovite.Core.LogReader do
  @moduledoc """
  Reads Sovite's own log lines back, for `sovitectl trace` and
  `sovitectl report`.

  It understands every format Sovite writes (see `docs/logging.md`):

      2026-10-04 12:00:00.123 [info] queue_id=4Xb2Kq event=queue.message.enqueued queue.message.enqueued: recipients=2, sender=a@example.com, size=1024
      {"time":"2026-10-04T12:00:00.123456Z","level":"info","msg":"queue.message.enqueued: ...","queue_id":"4Xb2Kq","event":"queue.message.enqueued"}
      Oct  4 12:00:00 mx1 sovite[812]: queue_id=4Xb2Kq event=queue.message.enqueued queue.message.enqueued: ...

  and the same lines with a syslog or journald prefix. Each line becomes
  an entry with:

    * `time` - a `NaiveDateTime`, in the log's own time zone (the year of
      a classic syslog line is the current one), or `nil`
    * `level` - `"info"`, `"warning"`, ...
    * `queue_id`, `session_id`, `remote_ip`, `event` - the standard
      metadata, or `nil`
    * `fields` - the `key=value` pairs of a telemetry event's message, as
      strings
    * `line` - the line as it was

  Lines that are not Sovite log lines are skipped. Gzip-compressed files
  (as logrotate leaves them) are read too.
  """

  @type entry :: %{
          time: NaiveDateTime.t() | nil,
          level: String.t() | nil,
          queue_id: String.t() | nil,
          session_id: String.t() | nil,
          remote_ip: String.t() | nil,
          event: String.t() | nil,
          fields: %{optional(String.t()) => String.t()},
          line: String.t()
        }

  @metadata ~w(queue_id session_id remote_ip event)

  @months ~w(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)

  @doc """
  Streams the entries of the log files at `paths` (oldest first), or of
  standard input for `"-"`.
  """
  @spec stream([Path.t()]) :: Enumerable.t(entry())
  def stream(paths) do
    paths
    |> Stream.flat_map(fn
      "-" -> IO.stream(:stdio, :line)
      path -> File.stream!(path, :line, [:compressed])
    end)
    |> Stream.map(&parse/1)
    |> Stream.reject(&is_nil/1)
  end

  @doc """
  The log files in `directory` written with `file_name` (a `[log]
  file_name` pattern), oldest first, compressed copies included.
  """
  @spec files(Path.t(), String.t()) :: [Path.t()]
  def files(directory, file_name) do
    regex =
      file_name
      |> Regex.escape()
      |> String.replace(Regex.escape("{n}"), "[0-9]+")
      |> String.replace(Regex.escape("{date}"), ".+")
      |> then(&Regex.compile!("\\A" <> &1 <> "(\\.gz)?\\z"))

    case File.ls(directory) do
      {:ok, names} ->
        names
        |> Enum.filter(&Regex.match?(regex, &1))
        |> Enum.map(&Path.join(directory, &1))
        |> Enum.sort_by(&mtime/1)

      {:error, _} ->
        []
    end
  end

  defp mtime(path) do
    case File.stat(path, time: :posix) do
      {:ok, stat} -> {stat.mtime, path}
      {:error, _} -> {0, path}
    end
  end

  @doc "Parses one log line, or returns `nil` if it is not a Sovite line."
  @spec parse(String.t()) :: entry() | nil
  def parse(line) do
    line = line |> String.trim_trailing("\n") |> String.trim_trailing("\r")

    cond do
      not String.valid?(line) -> nil
      String.starts_with?(line, "{") -> parse_json(line)
      true -> parse_text(line)
    end
  end

  defp parse_json(line) do
    case JSON.decode(line) do
      {:ok, %{"msg" => msg} = map} when is_binary(msg) ->
        meta = Map.new(@metadata, &{&1, string(map[&1])})

        entry(line, json_time(map["time"]), string(map["level"]), meta, msg)

      _ ->
        nil
    end
  end

  # "$date $time [$level] $metadata$message", perhaps after a syslog
  # prefix. Without the date and level, a syslog line is still Sovite's
  # if its tag is "sovite".
  defp parse_text(line) do
    {syslog_time, rest} = strip_syslog(line)
    {time, rest} = iso_time(rest)

    case Regex.run(~r/\A\[([a-z]+)\] (.*)\z/s, rest) do
      [_, level, rest] ->
        {meta, message} = metadata(rest, %{})
        entry(line, time || syslog_time, level, meta, message)

      nil when syslog_time != nil ->
        {meta, message} = metadata(rest, %{})
        entry(line, syslog_time, nil, meta, message)

      nil ->
        nil
    end
  end

  defp entry(line, time, level, meta, message) do
    %{
      time: time,
      level: level,
      queue_id: meta["queue_id"],
      session_id: meta["session_id"],
      remote_ip: meta["remote_ip"],
      event: meta["event"],
      fields: fields(meta["event"], message),
      line: line
    }
  end

  defp metadata(text, acc) do
    case Regex.run(~r/\A(queue_id|session_id|remote_ip|event)=(\S+) (.*)\z/s, text) do
      [_, key, value, rest] -> metadata(rest, Map.put(acc, key, value))
      nil -> {acc, text}
    end
  end

  # "event.name: key=value, key=value". A value may contain ", ", so only
  # split before something that looks like the next key.
  defp fields(nil, _message), do: %{}

  defp fields(event, message) do
    case String.split(message, event <> ": ", parts: 2) do
      ["", pairs] ->
        pairs
        |> String.split(~r/, (?=[a-z_]+=)/)
        |> Map.new(&pair/1)

      _ ->
        %{}
    end
  end

  defp pair(pair) do
    case :binary.split(pair, "=") do
      [key, value] -> {key, value}
      [key] -> {key, ""}
    end
  end

  defp iso_time(text) do
    case Regex.run(~r/\A(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d(?:\.\d+)?) (.*)\z/s, text) do
      [_, date, time, rest] ->
        case NaiveDateTime.from_iso8601(date <> " " <> time) do
          {:ok, naive} -> {naive, rest}
          {:error, _} -> {nil, rest}
        end

      nil ->
        {nil, text}
    end
  end

  # "Oct  4 12:00:00 host sovite[812]: " (RFC 3164, as syslog daemons and
  # journalctl write it), "2026-10-04T12:00:00+02:00 host sovite[812]: "
  # (rsyslog's high-precision format), or "<22>1 2026-10-04T12:00:00Z
  # host sovite 812 - - " (RFC 5424).
  defp strip_syslog(line) do
    cond do
      match =
          Regex.run(
            ~r/\A([A-Z][a-z]{2}) +(\d{1,2}) (\d\d:\d\d:\d\d) \S+ sovite(?:\[\d+\])?: (.*)\z/s,
            line
          ) ->
        [_, month, day, time, rest] = match
        {classic_time(month, day, time), rest}

      match = Regex.run(~r/\A(\d{4}-\d\d-\d\dT\S+) \S+ sovite(?:\[\d+\])?: (.*)\z/s, line) ->
        [_, time, rest] = match
        {json_time(time), rest}

      match = Regex.run(~r/\A<\d+>1 (\S+) \S+ sovite \S+ \S+ (?:-|\[.*?\]) (.*)\z/s, line) ->
        [_, time, rest] = match
        {json_time(time), rest}

      true ->
        {nil, line}
    end
  end

  defp classic_time(month, day, time) do
    with index when index != nil <- Enum.find_index(@months, &(&1 == month)),
         {:ok, time} <- Time.from_iso8601(time),
         {:ok, date} <- Date.new(Date.utc_today().year, index + 1, String.to_integer(day)) do
      NaiveDateTime.new!(date, time)
    else
      _ -> nil
    end
  end

  defp json_time(time) when is_binary(time) do
    case DateTime.from_iso8601(time) do
      {:ok, datetime, _offset} -> DateTime.to_naive(datetime)
      {:error, _} -> nil
    end
  end

  defp json_time(_time), do: nil

  defp string(value) when is_binary(value), do: value
  defp string(nil), do: nil
  defp string(value), do: to_string(value)
end
