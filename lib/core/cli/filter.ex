defmodule Sovite.Core.CLI.Filter do
  @moduledoc false
  # sovitectl commands for the filter: thresholds of addresses and
  # domains, and scanning a message with the rules.

  import Sovite.Core.CLI.Helpers

  alias Sovite.Analyzer
  alias Sovite.Core.Config
  alias Sovite.Core.Filter.{Actions, Checks, RuleFiles}
  alias Sovite.Core.Repo.Tables.FilterThresholds
  alias Sovite.Rules
  alias Sovite.Rules.Actions, as: RuleActions
  alias Sovite.Rules.Maps

  @usage """
    filter threshold list            List the filter thresholds of addresses and domains
    filter threshold set PATTERN ACTION SCORE|off
                                     Take ACTION for mail to PATTERN (address or @domain) from SCORE.
                                     ACTION: reject, soft_reject, quarantine, rewrite_subject,
                                     add_header, greylist
    filter threshold delete PATTERN [ACTION]
    filter threshold show ADDRESS    The thresholds that apply to mail for ADDRESS
    filter scan [--ip IP] [--helo NAME] [--from ADDRESS] [--checks] [FILE]
                                     Scan a message (FILE or standard input) with the rules of [filter].
                                     With an envelope or --checks, also run SPF, DKIM, ARC, DMARC,
                                     DNS lists, and reverse DNS
  """

  def usage, do: @usage
  def commands, do: ["filter"]

  def run(["filter", "threshold", "list"], path), do: with_repo(path, &list/1)

  def run(["filter", "threshold", "set", pattern, action, score], path) do
    with {:ok, action} <- action(action),
         {:ok, score} <- score(score) do
      with_repo(
        path,
        &result(
          FilterThresholds.set(&1, pattern, action, score),
          "#{pattern}: #{action} #{describe(score)}"
        )
      )
    end
  end

  def run(["filter", "threshold", "delete", pattern | action], path)
      when length(action) <= 1 do
    with {:ok, action} <- optional_action(action) do
      with_repo(
        path,
        &result(
          FilterThresholds.delete(&1, pattern, action),
          "deleted #{pattern}",
          "no such threshold"
        )
      )
    end
  end

  def run(["filter", "threshold", "show", address], path),
    do: with_config(path, fn config -> with_repo(path, &show(config, &1, address)) end)

  def run(["filter", "scan" | args], path) do
    switches = [ip: :string, helo: :string, from: :string, checks: :boolean]

    case OptionParser.parse(args, strict: switches) do
      {opts, file, []} when length(file) <= 1 ->
        with {:ok, message} <- read_message(file),
             do: with_config(path, &scan(&1, message, opts))

      _ ->
        :usage
    end
  end

  def run(_argv, _path), do: :usage

  defp with_config(path, fun) do
    case Config.load(path) do
      {:ok, config} ->
        fun.(config)

      {:error, errors} ->
        print_config_errors(path, errors)
        1
    end
  end

  # Fixed table: never create atoms from the command line.
  defp action(name) do
    case RuleActions.parse(name) do
      {:ok, action} when action != :no_action ->
        {:ok, action}

      _ ->
        fail(
          "unknown action #{inspect(name)}: use #{Enum.map_join(RuleActions.actions(), ", ", &Atom.to_string/1)}"
        )
    end
  end

  defp optional_action([]), do: {:ok, nil}
  defp optional_action([name]), do: action(name)

  defp score("off"), do: {:ok, nil}

  defp score(text) do
    case Float.parse(text) do
      {score, ""} -> {:ok, score}
      _ -> fail("#{inspect(text)} is not a score: use a number, or off")
    end
  end

  defp describe(nil), do: "off"
  defp describe(score), do: "from #{score}"

  defp list(repo) do
    for threshold <- FilterThresholds.list(repo),
        do: IO.puts("#{threshold.pattern}  #{threshold.action}  #{describe(threshold.score)}")

    0
  end

  defp show(config, repo, address) do
    case Actions.thresholds(config, repo, address) do
      {:ok, thresholds} -> show(thresholds)
      {:error, {:database, message}} -> fail("database: #{message}")
    end
  end

  defp show(thresholds) do
    for action <- RuleActions.actions() do
      score = Map.get(thresholds, action)
      IO.puts("#{action}  #{describe(if is_number(score), do: score)}")
    end

    0
  end

  # Bytes as they are: a message need not be UTF-8.
  defp read_message([]) do
    case IO.binread(:stdio, :eof) do
      message when is_binary(message) -> {:ok, message}
      :eof -> {:ok, ""}
      {:error, reason} -> fail("cannot read standard input: #{inspect(reason)}")
    end
  end

  defp read_message([file]) do
    case File.read(file) do
      {:ok, message} -> {:ok, message}
      {:error, reason} -> fail("cannot read #{file}: #{:file.format_error(reason)}")
    end
  end

  defp scan(config, message, opts) do
    # Scans report through telemetry.
    {:ok, _} = Application.ensure_all_started(:telemetry)
    envelope = Map.new(Keyword.take(opts, [:ip, :helo, :from]))

    case RuleFiles.load(config.filter.rules, RuleFiles.flags()) do
      {:ok, rules} ->
        checks =
          if envelope != %{} or opts[:checks],
            do: Checks.run(message, envelope, Checks.opts(config, Config.resolver(config))),
            else: %{}

        analysis = Analyzer.analyze(message)

        result =
          Rules.scan(rules, analysis,
            raw: message,
            envelope: envelope,
            symbols:
              Checks.symbols(checks) ++ Checks.headers(analysis, envelope, config.server.hostname),
            maps: maps(rules),
            timeout: config.filter.timeout
          )

        print_scan(result, RuleActions.decide(result.score, config.filter.actions))

      {:error, errors} ->
        Enum.each(errors, &IO.puts(:stderr, "error: " <> &1))
        1
    end
  end

  defp maps(rules) do
    for {name, {type, path}} <- Rules.file_maps(rules), into: %{} do
      case File.read(path) do
        {:ok, text} ->
          {name, elem(Maps.parse(type, text), 0)}

        {:error, reason} ->
          IO.puts(
            :stderr,
            "warning: map #{name}: cannot read #{path}: #{:file.format_error(reason)}"
          )

          {name, elem(Maps.new(type, []), 0)}
      end
    end
  end

  defp print_scan(result, action) do
    IO.puts("score: #{result.score}")
    IO.puts("action: #{action}")

    for symbol <- result.symbols do
      options = if symbol.options == [], do: "", else: " [#{Enum.join(symbol.options, ", ")}]"
      IO.puts("  #{symbol.name}  #{symbol.score}#{options}")
    end

    for anomaly <- result.anomalies, do: IO.puts("note: #{inspect(anomaly)}")
    0
  end
end
