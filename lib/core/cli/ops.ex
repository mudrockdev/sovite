defmodule Sovite.Core.CLI.Ops do
  @moduledoc false
  # The sovitectl commands for running the MTA: the queue, the
  # configuration, routing, status, message traces, and log reports.
  #
  # Reading the queue and the logs works on the files, whether or not the
  # MTA runs. Changing the queue, reloading, and status go through the
  # admin API (Sovite.Core.CLI.API), since the running queue manager owns
  # the queue.

  import Sovite.Core.CLI.Helpers

  alias Sovite.Core.CLI.API
  alias Sovite.Core.Config.Settings
  alias Sovite.Core.Repo.Tables.DomainCache

  alias Sovite.Core.{Config, LogReader}
  alias Sovite.Core.MTA.{LogReport, QueueInfo, RouteInfo, Routing, Trace}

  @commands ~w(queue config route status trace report)

  @usage """
    queue list [QUEUE]               List queued messages (QUEUE: incoming, active, deferred, hold, corrupt)
    queue show ID                    Show a message's envelope, recipients, and headers
    queue flush [ID...]              Retry deferred messages now: all, or those given
    queue hold ID...                 Put messages on hold
    queue release ID...              Release held messages
    queue delete ID...               Delete messages, without notifying anyone
    queue requeue ID...              Route messages again and retry them now
                                     (IDs may be "-": read them from standard input, one per line)
    config show [-n] [PATH]          Print every setting with its value; -n: only those set in the file
    config diff [PATH]               Print the settings PATH would change in the running server
    config diff OLD NEW              Print the settings that differ between two config files
    config reload                    Reload the config file in the running server
    route ADDRESS [SENDER]           Show how ADDRESS is rewritten, expanded, and routed
    status                           Show the running server's status
    trace ID [LOG...]                Follow a message (queue ID or Message-ID) through the logs.
                                     LOG: log files, or "-" for standard input; default: [log] directory
    report [--top N] [--date DATE] [LOG...]
                                     Summarize the logs, like pflogsumm. DATE: YYYY-MM-DD, today, yesterday
  """

  @actions ~w(hold release delete requeue)

  def commands, do: @commands
  def usage, do: @usage

  ## Queue

  def run(["queue", "list"], path), do: with_config(path, &list_queue(&1, QueueInfo.queues()))

  def run(["queue", "list", queue], path) do
    case Enum.find(QueueInfo.queues(), &(Atom.to_string(&1) == queue)) do
      nil -> fail("unknown queue #{inspect(queue)}")
      queue -> with_config(path, &list_queue(&1, [queue]))
    end
  end

  def run(["queue", "show", id], path), do: with_config(path, &show_message(&1, id))

  def run(["queue", "flush"], path) do
    with_config(path, fn config ->
      config |> API.request(:post, "/api/queue/flush") |> api_result("flushed the queue")
    end)
  end

  def run(["queue", "flush" | ids], path), do: each_message(path, "retry", ids, "retrying")

  def run(["queue", action | ids], path) when action in @actions and ids != [],
    do: each_message(path, action, ids, past(action))

  ## Configuration

  def run(["config", "show"], path), do: config_show(path, false)
  def run(["config", "show", "-n"], path), do: config_show(path, true)
  def run(["config", "show", "-n", file], _path), do: config_show(file, true)
  def run(["config", "show", file], _path), do: config_show(file, false)

  def run(["config", "diff"], path), do: config_diff_running(path)
  def run(["config", "diff", file], _path), do: config_diff_running(file)

  def run(["config", "diff", old, new], _path) do
    with {:ok, old_settings} <- settings(old),
         {:ok, new_settings} <- settings(new) do
      print_diff(Settings.diff(old_settings, new_settings))
    end
  end

  def run(["config", "reload"], path) do
    with_config(path, &reload_result(API.request(&1, :post, "/api/config/reload"), path))
  end

  ## Routing, status, logs

  def run(["route", address], path), do: route(path, address, "")
  def run(["route", address, sender], path), do: route(path, address, sender)

  def run(["status"], path),
    do: with_config(path, &status_result(API.request(&1, :get, "/api/status")))

  def run(["trace", id | files], path) do
    with_config(path, fn config ->
      case log_files(config, files) do
        [] -> fail("no log files: give them, or set [log] directory")
        files -> print_trace(config, Trace.run(id, files))
      end
    end)
  end

  def run(["report" | args], path) do
    with {:ok, opts, files} <- report_args(args, []),
         do: with_config(path, &report(&1, files, opts))
  end

  def run(_argv, _path), do: :usage

  defp reload_result({:ok, 200, _body}, path), do: done("reloaded #{path}")

  defp reload_result({:ok, 422, %{"errors" => errors}}, path) do
    for error <- errors, do: IO.puts(:stderr, "#{path}: #{error}")
    fail("the configuration was not reloaded")
  end

  defp reload_result({:ok, 409, %{"keys" => keys}}, _path),
    do: fail("not reloaded: these settings need a restart: #{Enum.join(keys, ", ")}")

  defp reload_result(other, _path), do: api_result(other, nil)

  defp status_result({:ok, 200, status}), do: print_status(status)

  defp status_result({:error, text}) do
    IO.puts(:stderr, text)
    # Like LSB init scripts: not running.
    3
  end

  defp status_result(other), do: api_result(other, nil)

  defp report(config, files, opts) do
    case log_files(config, files) do
      [] ->
        fail("no log files: give them, or set [log] directory")

      files ->
        files |> LogReader.stream() |> LogReport.build(opts) |> LogReport.format() |> IO.write()
        0
    end
  end

  ## Queue helpers

  defp list_queue(config, queues) do
    case QueueInfo.list(config.queue.directory, queues: queues) do
      [] ->
        done("Mail queue is empty")

      messages ->
        IO.puts("-Queue ID-     -Queue-   --Size-- ----Arrival Time---- -Sender/Recipient-------")
        Enum.each(messages, &print_summary/1)
        kbytes = messages |> Enum.map(&Map.get(&1, :size, 0)) |> Enum.sum() |> div(1024)
        count = length(messages)
        done("-- #{kbytes} Kbytes in #{count} message#{if count == 1, do: "", else: "s"}.")
    end
  end

  defp print_summary(%{error: error} = message),
    do: IO.puts("#{pad(message.queue_id, 15)}#{pad(message.queue, 10)}  (unreadable: #{error})\n")

  defp print_summary(message) do
    sender = if message.sender == "", do: "MAILER-DAEMON", else: message.sender

    IO.puts(
      pad(message.queue_id, 15) <>
        pad(message.queue, 8) <>
        String.pad_leading(Integer.to_string(message.size), 10) <>
        " " <> pad(arrival(message.received_at), 21) <> sender
    )

    if message.reason, do: IO.puts(indent("(#{message.reason})"))
    if message.release_at, do: IO.puts(indent("(on hold until #{message.release_at})"))
    for rcpt <- message.pending, do: IO.puts(indent(rcpt))
    IO.puts("")
  end

  defp arrival(nil), do: "-"

  defp arrival(time) do
    case DateTime.from_iso8601(time) do
      {:ok, time, _} -> Calendar.strftime(time, "%a %b %d %H:%M:%S")
      _ -> time
    end
  end

  defp indent(text), do: String.duplicate(" ", 55) <> text
  defp pad(text, width), do: String.pad_trailing(to_string(text), width)

  defp show_message(config, id) do
    case QueueInfo.show(config.queue.directory, id) do
      {:ok, message} -> print_message(message)
      {:error, :not_found} -> fail("no such message: #{id}")
      {:error, reason} -> fail("cannot read #{id}: #{inspect(reason)}")
    end
  end

  defp print_message(message) do
    for {name, value} <- message_fields(message),
        value not in [nil, ""],
        do: IO.puts(String.pad_trailing(name <> ":", 16) <> to_string(value))

    IO.puts("\nRecipients:")
    Enum.each(message.recipient_status, &print_recipient/1)
    IO.puts("\nHeaders:")
    IO.write(message.headers)
    0
  end

  defp print_recipient(rcpt) do
    code = if rcpt.code, do: " " <> rcpt.code, else: ""
    IO.puts("  #{rcpt.address}  #{rcpt.status}#{code}")
    remote = if rcpt.remote, do: " (#{rcpt.remote})", else: ""
    if rcpt.reply, do: IO.puts("    #{rcpt.reply}#{remote}")
  end

  defp message_fields(message) do
    [
      {"Queue ID", message.queue_id},
      {"Queue", message.queue},
      {"Size", message.size},
      {"Received", message.received_at},
      {"Session", message.session_id},
      {"Client", message.client},
      {"HELO", message.helo},
      {"Protocol", message.protocol},
      {"User", message.user},
      {"Sender", sender(message.sender)},
      {"Message-ID", message.message_id},
      {"Subject", message.subject},
      {"Body", message.body_type},
      {"Priority", nonzero(message.priority)},
      {"REQUIRETLS", yes(message.requiretls)},
      {"SMTPUTF8", yes(message.smtputf8)},
      {"ENVID", message.envid},
      {"RET", message.ret},
      {"Deliver by", message.deliver_by},
      {"Release at", message.release_at},
      {"Content filter", message.content_filter},
      {"Attempts", message.attempts},
      {"Next attempt", message.next_attempt}
    ]
  end

  defp sender(""), do: "<>"
  defp sender(sender), do: sender

  defp nonzero(0), do: nil
  defp nonzero(n), do: n

  defp yes(true), do: "yes"
  defp yes(_), do: nil

  defp each_message(path, action, ids, verb) do
    with_config(path, fn config ->
      ids
      |> expand_ids()
      |> Enum.map(&message_action(config, &1, action, verb))
      |> Enum.max(fn -> 0 end)
    end)
  end

  defp message_action(config, id, action, verb) do
    case API.request(config, :post, "/api/queue/#{URI.encode(id)}/#{action}") do
      {:ok, 200, _body} -> done("#{id}: #{verb}")
      {:ok, 404, _body} -> fail("#{id}: no such message")
      other -> api_result(other, nil)
    end
  end

  defp expand_ids(ids) do
    Enum.flat_map(ids, fn
      "-" -> IO.stream(:stdio, :line) |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))
      id -> [id]
    end)
  end

  defp past("hold"), do: "held"
  defp past("release"), do: "released"
  defp past("delete"), do: "deleted"
  defp past("requeue"), do: "requeued"

  defp api_result({:ok, 200, _body}, message), do: done(message)
  defp api_result({:ok, _status, %{"error" => error}}, _message), do: fail(error)
  defp api_result({:ok, status, _body}, _message), do: fail("the admin API returned #{status}")
  defp api_result({:error, text}, _message), do: fail(text)

  ## Configuration helpers

  defp config_show(file, only_set) do
    with {:ok, settings} <- settings(file) do
      settings = if only_set, do: Enum.reject(settings, &elem(&1, 2)), else: settings
      IO.write(Settings.format(settings))
      0
    end
  end

  # Settings of a file that must also be valid.
  defp settings(file) do
    case Config.load(file) do
      {:ok, config} ->
        {:ok, Settings.list(config.raw)}

      {:error, errors} ->
        print_config_errors(file, errors)
        1
    end
  end

  defp config_diff_running(file) do
    with {:ok, new} <- settings(file),
         {:ok, config} <- Config.load(file) do
      case API.request(config, :get, "/api/config") do
        {:ok, 200, %{"settings" => running}} -> print_diff(Settings.diff(decode(running), new))
        other -> api_result(other, nil)
      end
    end
  end

  defp decode(settings), do: for([key, value, default] <- settings, do: {key, value, default})

  defp print_diff([]), do: done("no differences")

  defp print_diff(changes) do
    for {key, old, new} <- changes do
      if old, do: IO.puts("- #{key} = #{old}")
      if new, do: IO.puts("+ #{key} = #{new}")
    end

    0
  end

  ## Routing, status, logs helpers

  defp route(path, address, sender) do
    with_repo_config(path, fn config, repo ->
      # The domains in the database, as the server sees them.
      {:ok, cache} = DomainCache.start_link(repo: repo)

      try do
        config
        |> Routing.new(repo)
        |> RouteInfo.resolve(address, sender)
        |> RouteInfo.format()
        |> IO.write()
      after
        GenServer.stop(cache)
      end

      0
    end)
  end

  defp print_status(status) do
    lines =
      [
        "sovite #{status["version"]} on #{status["hostname"]}",
        "up #{uptime(status["uptime"])}, since #{status["started_at"]}",
        "config: #{status["config_path"] || "(none)"}" <> last_reload(status["last_reload"]),
        parts(status["stack"]),
        if(status["draining"], do: "draining: shutting down")
      ] ++ mta_status(status)

    IO.puts(lines |> Enum.filter(& &1) |> Enum.join("\n"))
    0
  end

  defp parts(nil), do: nil

  defp parts(stack) do
    on = for part <- ~w(mta filter mailbox), stack[part], do: part
    "parts: " <> if(on == [], do: "none", else: Enum.join(on, ", "))
  end

  # The queue and the listeners, when the node runs the MTA.
  defp mta_status(%{"queue" => queue} = status) when is_map(queue) do
    [
      "queue: " <>
        Enum.map_join(QueueInfo.queues(), ", ", &"#{queue[Atom.to_string(&1)] || 0} #{&1}"),
      "deliveries: #{status["deliveries"]["running"]} running, #{status["deliveries"]["ready"]} waiting",
      "listeners:"
      | for(l <- status["listeners"], do: "  #{l["id"]}: #{l["connections"]} connections")
    ]
  end

  defp mta_status(_status), do: []

  defp last_reload(nil), do: ""
  defp last_reload(%{"at" => at, "result" => "ok"}), do: ", reloaded #{at}"
  defp last_reload(%{"at" => at, "result" => error}), do: ", reload failed #{at}: #{error}"

  defp uptime(seconds) when seconds >= 86_400,
    do: "#{div(seconds, 86_400)}d #{uptime(rem(seconds, 86_400))}"

  defp uptime(seconds) when seconds >= 3600,
    do: "#{div(seconds, 3600)}h #{div(rem(seconds, 3600), 60)}m"

  defp uptime(seconds), do: "#{div(seconds, 60)}m #{rem(seconds, 60)}s"

  defp log_files(_config, [_ | _] = files), do: files
  defp log_files(%{log: %{directory: nil}}, []), do: []
  defp log_files(%{log: log}, []), do: LogReader.files(log.directory, log.file_name)

  defp print_trace(_config, %{entries: []}), do: fail("no log lines found")

  defp print_trace(config, trace) do
    Enum.each(trace.entries, &IO.puts(&1.line))

    for id <- trace.queue_ids, queue = QueueInfo.locate(config.queue.directory, id) do
      IO.puts("\n#{id} is still in the #{queue} queue: sovitectl queue show #{id}")
    end

    0
  end

  defp report_args(["--top", n | rest], opts) do
    case Integer.parse(n) do
      {n, ""} when n > 0 -> report_args(rest, Keyword.put(opts, :top, n))
      _ -> fail("--top needs a positive number")
    end
  end

  defp report_args(["--date", date | rest], opts) do
    case report_date(date) do
      {:ok, date} -> report_args(rest, Keyword.put(opts, :date, date))
      :error -> fail("--date needs YYYY-MM-DD, today, or yesterday")
    end
  end

  defp report_args(files, opts), do: {:ok, opts, files}

  defp report_date("today"), do: {:ok, Date.utc_today()}
  defp report_date("yesterday"), do: {:ok, Date.add(Date.utc_today(), -1)}

  defp report_date(date) do
    case Date.from_iso8601(date) do
      {:ok, date} -> {:ok, date}
      {:error, _} -> :error
    end
  end

  ## Config loading

  defp with_config(path, fun) do
    case Config.load(path) do
      {:ok, config} ->
        fun.(config)

      {:error, errors} ->
        print_config_errors(path, errors)
        1
    end
  end

  defp with_repo_config(path, fun) do
    with_config(path, fn config -> with_repo(path, &fun.(config, &1)) end)
  end
end
