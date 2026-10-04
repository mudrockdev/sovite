defmodule Sovite.Core.Logging.FileHandler do
  @moduledoc """
  `:logger` handler that writes to rotating log files, in the style of
  pino-roll.

  File names come from a pattern such as `sovite.{date}.{n}.log`. `{date}`
  is the current date formatted with `date_format` (a `Calendar.strftime/2`
  format), and `{n}` is a number that starts at 1 and goes up with each
  rotation:

      sovite.2026-10-04.1.log
      sovite.2026-10-04.2.log
      sovite.2026-10-05.1.log

  A new file is started when the next line would push the current file
  over `max_size`, or when the `rotation` period (hour, day, ISO week, or
  month) changes. After a rotation, only the newest `max_files` files that
  match the pattern are kept (`0` keeps all). On restart, logging continues
  in the newest file for the current date if it is not full. With
  `symlink` set, a symlink of that name in the directory always points to
  the current file. Dates use local time, or UTC when
  `config :logger, utc_log: true` is set.

  Run it under a supervisor. It installs the `:logger` handler when it
  starts and removes it when it stops:

      {Sovite.Core.Logging.FileHandler,
       id: :sovite_file,
       formatter: Sovite.Core.Logging.formatter(:text),
       config: %{directory: "/var/log/sovite", file_name: "sovite.{date}.{n}.log", ...}}

  ## Options

    * `:id` - the `:logger` handler ID. Required.
    * `:config` - a map with the keys in `config_keys/0`. Required.
    * `:formatter` - the `{module, config}` formatter. Required.
    * `:level` - the handler level. Defaults to `:all`.
    * `:replace` - ID of a handler that is silenced (level `:none`) while
      this one runs, and whose filters this one copies.

  ## Overload

  Events are formatted in the logging process and sent to the writer
  process. While fewer than 10 events are waiting, logging does not block.
  Above that, callers wait until their event is buffered; above 200,
  events are dropped, and a line with the number of dropped events is
  written once the writer catches up. Writes are batched and flushed as
  soon as the writer is idle.

  If the file cannot be written, the error goes to standard error and
  opening it is retried every second. Events in between are dropped.
  """

  @behaviour :logger_handler

  use GenServer

  @type rotation :: :never | :hourly | :daily | :weekly | :monthly

  @config_keys [:directory, :file_name, :date_format, :max_size, :rotation, :max_files, :symlink]

  @sync_qlen 10
  @drop_qlen 200
  @call_timeout 5_000
  @flush_bytes 64 * 1024
  @check_interval 5_000
  @retry_interval 1_000

  # Indexes in the shared atomics array.
  @queued 1
  @dropped 2

  @doc "Keys of the `:config` option."
  @spec config_keys() :: [atom()]
  def config_keys, do: @config_keys

  @doc false
  def child_spec(opts) do
    %{id: {__MODULE__, Keyword.fetch!(opts, :id)}, start: {__MODULE__, :start_link, [opts]}}
  end

  @doc "Starts the writer and installs the `:logger` handler."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc """
  Writes everything buffered by handler `id` to its file. Events logged
  before the call are included.
  """
  @spec sync(:logger.handler_id()) :: :ok | {:error, term()}
  def sync(id) do
    with {:ok, %{config: %{writer: writer}}} <- :logger.get_handler_config(id) do
      GenServer.call(writer, :sync)
    end
  end

  ## :logger handler callbacks, run in the logging process

  @impl :logger_handler
  def adding_handler(%{config: %{writer: writer, atomics: _}} = config) when is_pid(writer),
    do: {:ok, config}

  def adding_handler(config), do: {:error, {:invalid_handler_config, config}}

  @impl :logger_handler
  def changing_config(_set_or_update, %{config: handler_config}, new_config),
    do: {:ok, Map.put(new_config, :config, handler_config)}

  @impl :logger_handler
  def log(event, %{config: %{writer: writer, atomics: atomics}} = config) do
    cond do
      # The writer never logs itself, except for its own crash report,
      # which the replaced handler gets once this one is removed.
      writer == self() -> :ok
      # Checked before formatting too, so dropping stays cheap.
      :atomics.get(atomics, @queued) >= @drop_qlen -> drop(atomics)
      true -> enqueue(writer, atomics, format(event, config.formatter))
    end

    :ok
  end

  defp enqueue(writer, atomics, line) do
    case :atomics.add_get(atomics, @queued, 1) do
      queued when queued > @drop_qlen ->
        :atomics.sub(atomics, @queued, 1)
        drop(atomics)

      queued when queued > @sync_qlen ->
        call(writer, line)

      _queued ->
        send(writer, {:log, line})
    end
  end

  defp drop(atomics), do: :atomics.add(atomics, @dropped, 1)

  defp call(writer, line) do
    GenServer.call(writer, {:log, line}, @call_timeout)
  catch
    :exit, _reason -> :ok
  end

  defp format(event, {module, formatter_config}) do
    case event |> module.format(formatter_config) |> :unicode.characters_to_binary() do
      line when is_binary(line) -> line
      _ -> "log formatting failed: invalid characters\n"
    end
  catch
    kind, reason -> "log formatting failed: " <> Exception.format_banner(kind, reason) <> "\n"
  end

  ## Writer process

  @impl GenServer
  def init(opts) do
    Process.flag(:trap_exit, true)

    state =
      opts
      |> Keyword.fetch!(:config)
      |> Map.take(@config_keys)
      |> Map.merge(%{
        id: Keyword.fetch!(opts, :id),
        clock: Keyword.get_lazy(opts, :clock, &default_clock/0),
        atomics: :atomics.new(2, signed: true),
        replace: Keyword.get(opts, :replace),
        replaced_level: nil,
        fd: nil,
        path: nil,
        inode: nil,
        size: 0,
        period: nil,
        buffer: [],
        buffer_size: 0,
        buffer_count: 0,
        failing: nil,
        retry_at: 0
      })

    case open_file(state, :resume, state.clock.()) do
      {:ok, state} ->
        state = state |> cleanup() |> install_handler(opts)
        Process.send_after(self(), :check_file, @check_interval)
        {:ok, state}

      {:error, path, reason} ->
        {:stop, {:cannot_open_log_file, path, reason}}
    end
  end

  # Test hook: `:clock` returns the current time as an Erlang datetime.
  defp default_clock do
    if Application.get_env(:logger, :utc_log, false),
      do: &:erlang.universaltime/0,
      else: &:erlang.localtime/0
  end

  defp install_handler(state, opts) do
    # A writer that was killed without cleaning up leaves its handler behind.
    _ = :logger.remove_handler(state.id)

    replaced =
      case state.replace && :logger.get_handler_config(state.replace) do
        {:ok, replaced} -> replaced
        _ -> nil
      end

    handler =
      (replaced || %{})
      |> Map.take([:filters, :filter_default])
      |> Map.merge(%{
        level: Keyword.get(opts, :level, :all),
        formatter: Keyword.fetch!(opts, :formatter),
        config: %{writer: self(), atomics: state.atomics}
      })

    :ok = :logger.add_handler(state.id, __MODULE__, handler)

    if replaced do
      :ok = :logger.update_handler_config(state.replace, :level, :none)
      %{state | replaced_level: replaced.level}
    else
      state
    end
  end

  @impl GenServer
  def handle_info({:log, line}, state), do: state |> write(line) |> noreply()
  def handle_info(:timeout, state), do: state |> flush() |> noreply()

  def handle_info(:check_file, state) do
    Process.send_after(self(), :check_file, @check_interval)
    state |> check_file() |> noreply()
  end

  def handle_info(_message, state), do: noreply(state)

  @impl GenServer
  def handle_call({:log, line}, _from, state), do: {:reply, :ok, write(state, line), 0}
  def handle_call(:sync, _from, state), do: {:reply, :ok, flush(state)}

  @impl GenServer
  def terminate(_reason, state) do
    _ = :logger.remove_handler(state.id)

    if state.replaced_level,
      do: :logger.update_handler_config(state.replace, :level, state.replaced_level)

    state |> drain() |> flush() |> close()
  end

  # Flush once the mailbox is empty.
  defp noreply(%{buffer_size: 0} = state), do: {:noreply, state}
  defp noreply(state), do: {:noreply, state, 0}

  defp drain(state) do
    receive do
      {:log, line} ->
        state |> write(line) |> drain()

      {:"$gen_call", from, {:log, line}} ->
        GenServer.reply(from, :ok)
        state |> write(line) |> drain()
    after
      0 -> state
    end
  end

  ## Writing and rotation

  defp write(state, line) do
    :atomics.sub(state.atomics, @queued, 1)
    bytes = byte_size(line)
    now = state.clock.()

    state =
      cond do
        period(state.rotation, now) != state.period -> rotate(state, now)
        state.size > 0 and state.size + bytes > state.max_size -> rotate(state, now)
        true -> state
      end

    state = %{
      state
      | buffer: [state.buffer, line],
        buffer_size: state.buffer_size + bytes,
        buffer_count: state.buffer_count + 1,
        size: state.size + bytes
    }

    if state.buffer_size >= @flush_bytes, do: flush(state), else: state
  end

  defp rotate(state, now) do
    state |> flush() |> close() |> open(:next, now) |> cleanup()
  end

  defp flush(state) do
    state = state |> ensure_open() |> add_dropped_notice()

    cond do
      state.buffer_size == 0 ->
        state

      state.fd == nil ->
        drop_buffer(state)

      true ->
        case :file.write(state.fd, state.buffer) do
          :ok ->
            %{state | buffer: [], buffer_size: 0, buffer_count: 0, failing: nil}

          {:error, reason} ->
            state
            |> report("cannot write log file #{state.path}: #{:file.format_error(reason)}")
            |> drop_buffer()
            |> close()
            |> retry_later()
        end
    end
  end

  defp drop_buffer(state) do
    :atomics.add(state.atomics, @dropped, state.buffer_count)
    %{state | buffer: [], buffer_size: 0, buffer_count: 0}
  end

  defp add_dropped_notice(%{fd: nil} = state), do: state

  defp add_dropped_notice(state) do
    case :atomics.exchange(state.atomics, @dropped, 0) do
      0 ->
        state

      count ->
        event = %{
          level: :warning,
          msg: {:string, "#{count} log events dropped: log writer overloaded or file unwritable"},
          meta: %{time: :logger.timestamp()}
        }

        formatter =
          case :logger.get_handler_config(state.id) do
            {:ok, %{formatter: formatter}} -> formatter
            _ -> Logger.Formatter.new(colors: [enabled: false])
          end

        line = format(event, formatter)
        %{state | buffer: [line | state.buffer], buffer_size: state.buffer_size + byte_size(line)}
    end
  end

  defp ensure_open(%{fd: nil} = state) do
    if System.monotonic_time(:millisecond) >= state.retry_at,
      do: open(state, :resume, state.clock.()),
      else: state
  end

  defp ensure_open(state), do: state

  # Reopens the file if it was deleted or renamed, for example by logrotate.
  defp check_file(%{fd: nil} = state), do: state

  defp check_file(state) do
    case File.stat(state.path) do
      {:ok, %{inode: inode}} when inode == state.inode -> state
      _ -> state |> flush() |> close() |> open(:resume, state.clock.())
    end
  end

  defp close(%{fd: nil} = state), do: state

  defp close(state) do
    _ = :file.close(state.fd)
    %{state | fd: nil}
  end

  defp open(state, mode, now) do
    case open_file(state, mode, now) do
      {:ok, state} ->
        %{state | failing: nil}

      {:error, path, reason} ->
        state
        |> report("cannot open log file #{path}: #{:file.format_error(reason)}")
        |> Map.merge(%{size: 0, period: period(state.rotation, now)})
        |> retry_later()
    end
  end

  defp retry_later(state),
    do: %{state | retry_at: System.monotonic_time(:millisecond) + @retry_interval}

  # Errors go to stderr, once until the next success, since the log
  # itself is what is failing.
  defp report(%{failing: message} = state, message), do: state

  defp report(state, message) do
    IO.puts(:stderr, "sovite: " <> message)
    %{state | failing: message}
  end

  # :resume continues the newest file for the current date if it is not
  # full. :next always starts a new one.
  defp open_file(state, mode, now) do
    date = Calendar.strftime(NaiveDateTime.from_erl!(now), state.date_format)
    last = state |> numbers(date) |> Enum.max(fn -> 0 end)

    n =
      if mode == :resume and last > 0 and file_size(state, date, last) < state.max_size,
        do: last,
        else: last + 1

    path = Path.join(state.directory, file_name(state.file_name, date, n))

    with :ok <- File.mkdir_p(state.directory),
         {:ok, fd} <- :file.open(path, [:append, :raw, :binary]),
         {:ok, stat} <- stat_or_close(path, fd) do
      # Logs contain addresses, so keep them from other users.
      if stat.size == 0, do: File.chmod(path, 0o640)
      update_symlink(state, path)

      {:ok,
       %{
         state
         | fd: fd,
           path: path,
           inode: stat.inode,
           size: stat.size,
           period: period(state.rotation, now)
       }}
    else
      {:error, reason} -> {:error, path, reason}
    end
  end

  defp stat_or_close(path, fd) do
    with {:error, reason} <- File.stat(path) do
      _ = :file.close(fd)
      {:error, reason}
    end
  end

  defp period(:never, _now), do: nil
  defp period(:hourly, {date, {hour, _, _}}), do: {date, hour}
  defp period(:daily, {date, _time}), do: date
  defp period(:weekly, {date, _time}), do: :calendar.iso_week_number(date)
  defp period(:monthly, {{year, month, _}, _time}), do: {year, month}

  defp file_name(pattern, date, n) do
    pattern |> String.replace("{n}", Integer.to_string(n)) |> String.replace("{date}", date)
  end

  defp file_size(state, date, n) do
    case File.stat(Path.join(state.directory, file_name(state.file_name, date, n))) do
      {:ok, %{size: size}} -> size
      {:error, _} -> 0
    end
  end

  # Numbers of the existing files for `date`.
  defp numbers(state, date) do
    regex = pattern_regex(state.file_name, Regex.escape(date))

    case File.ls(state.directory) do
      {:ok, names} ->
        for name <- names, [_, n] <- [Regex.run(regex, name)], do: String.to_integer(n)

      {:error, _} ->
        []
    end
  end

  # The pattern as a regex that captures {n}. `date_regex` replaces {date}.
  defp pattern_regex(pattern, date_regex) do
    body =
      ~r/\{date\}|\{n\}/
      |> Regex.split(pattern, include_captures: true)
      |> Enum.map_join(fn
        "{date}" -> date_regex
        "{n}" -> "(\\d+)"
        literal -> Regex.escape(literal)
      end)

    Regex.compile!("\\A" <> body <> "\\z")
  end

  # Deletes the oldest files beyond max_files, counting the current one.
  defp cleanup(%{max_files: 0} = state), do: state

  defp cleanup(state) do
    regex = pattern_regex(state.file_name, ".*")

    with {:ok, names} <- File.ls(state.directory) do
      names
      |> Enum.flat_map(&old_file(state, regex, &1))
      |> Enum.sort(:desc)
      |> Enum.drop(state.max_files - 1)
      |> Enum.each(fn {_mtime, _n, path} -> File.rm(path) end)
    end

    state
  end

  defp old_file(state, regex, name) do
    path = Path.join(state.directory, name)

    with [_, n] <- Regex.run(regex, name),
         true <- path != state.path,
         {:ok, %{type: :regular, mtime: mtime}} <- File.lstat(path, time: :posix) do
      [{mtime, String.to_integer(n), path}]
    else
      _ -> []
    end
  end

  defp update_symlink(%{symlink: nil}, _path), do: :ok

  defp update_symlink(state, path) do
    link = Path.join(state.directory, state.symlink)
    temporary = Path.join(state.directory, ".#{state.symlink}.tmp")
    _ = File.rm(temporary)

    # Renaming over the old link swaps it atomically.
    with :ok <- File.ln_s(Path.basename(path), temporary),
         :ok <- File.rename(temporary, link) do
      :ok
    else
      {:error, reason} ->
        IO.puts(
          :stderr,
          "sovite: cannot update log symlink #{link}: #{:file.format_error(reason)}"
        )
    end
  end
end
