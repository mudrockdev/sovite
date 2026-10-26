defmodule Sovite.Core.Filter.Server do
  @moduledoc """
  Keeps the filter's rules and maps loaded: reads them at start, and
  every `[filter] reload_interval`, and when the configuration is
  reloaded, looks for rule and map files that changed, and reads those
  again. A rule set with errors is not taken:
  the one before it stays, and the errors are logged.

  What it loads is kept in `:persistent_term` for `Sovite.Core.Filter`,
  so scans read it without a call.
  """

  use GenServer

  require Logger

  alias Sovite.Core.Filter.RuleFiles
  alias Sovite.Rules
  alias Sovite.Rules.Maps

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc false
  # The state scans read: the rules, the maps of files, the timeout, and
  # this server's name.
  @spec loaded(term()) ::
          %{rules: Rules.t(), maps: map(), timeout: pos_integer(), hostname: String.t()} | nil
  def loaded(instance), do: :persistent_term.get({__MODULE__, instance}, nil)

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    instance = Keyword.fetch!(opts, :instance)

    :ok =
      :telemetry.attach(
        {__MODULE__, instance},
        [:sovite, :config, :reloaded],
        &__MODULE__.config_reloaded/4,
        self()
      )

    state = %{
      instance: instance,
      paths: Keyword.fetch!(opts, :rules),
      flags: Keyword.fetch!(opts, :flags),
      interval: Keyword.fetch!(opts, :reload_interval),
      timeout: Keyword.fetch!(opts, :timeout),
      hostname: Keyword.get(opts, :hostname, "localhost"),
      rules: nil,
      rule_stamps: nil,
      maps: %{},
      map_stamps: %{}
    }

    {:ok, state |> reload() |> schedule()}
  end

  @impl true
  def handle_info(:check, state), do: {:noreply, state |> reload() |> schedule()}
  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    _ = :telemetry.detach({__MODULE__, state.instance})
    _ = :persistent_term.erase({__MODULE__, state.instance})
    :ok
  end

  @doc false
  def config_reloaded(_event, _measurements, _metadata, server), do: send(server, :check)

  defp schedule(state) do
    Process.send_after(self(), :check, state.interval)
    state
  end

  defp reload(state) do
    old = {state.rules, state.maps}
    state = state |> reload_rules() |> reload_maps()

    if {state.rules, state.maps} != old do
      :persistent_term.put({__MODULE__, state.instance}, %{
        rules: state.rules,
        maps: state.maps,
        timeout: state.timeout,
        hostname: state.hostname
      })
    end

    state
  end

  defp reload_rules(state) do
    stamps = rule_stamps(state.paths)
    if stamps == state.rule_stamps, do: state, else: load_rules(%{state | rule_stamps: stamps})
  end

  defp load_rules(state) do
    case RuleFiles.load(state.paths, state.flags) do
      {:ok, rules} ->
        symbols = length(Rules.symbols(rules))
        :telemetry.execute([:sovite, :filter, :rules, :loaded], %{symbols: symbols}, %{})
        if state.rules, do: Logger.info("filter: rules reloaded, #{symbols} symbols")
        %{state | rules: rules}

      {:error, errors} ->
        Logger.error("filter: rules not reloaded:\n  " <> Enum.join(errors, "\n  "))
        %{state | rules: state.rules || empty()}
    end
  end

  defp empty do
    {:ok, rules} = Rules.compile([])
    rules
  end

  # What tells that the rule files changed: the files, their times and
  # sizes.
  defp rule_stamps(paths) do
    case RuleFiles.files(paths) do
      {:ok, files} -> Enum.map(files, &{&1, stamp(&1)})
      {:error, errors} -> {:error, errors}
    end
  end

  defp stamp(path) do
    case File.stat(path, time: :posix) do
      {:ok, stat} -> {stat.mtime, stat.size, stat.inode}
      {:error, reason} -> {:error, reason}
    end
  end

  defp reload_maps(state) do
    files = Rules.file_maps(state.rules)

    Enum.reduce(files, %{state | maps: Map.take(state.maps, Map.keys(files))}, fn
      {name, {type, path}}, state ->
        stamp = stamp(path)

        if state.map_stamps[name] == {type, path, stamp} and Map.has_key?(state.maps, name),
          do: state,
          else: load_map(state, name, type, path, stamp)
    end)
  end

  defp load_map(state, name, type, path, stamp) do
    state = put_in(state.map_stamps[name], {type, path, stamp})

    case File.read(path) do
      {:ok, text} ->
        {map, errors} = Maps.parse(type, text)
        report_map(name, path, map, errors)
        put_in(state.maps[name], map)

      {:error, reason} ->
        Logger.warning("filter: map #{name}: cannot read #{path}: #{:file.format_error(reason)}")
        state
    end
  end

  defp report_map(name, path, map, errors) do
    :telemetry.execute([:sovite, :filter, :map, :loaded], %{entries: Maps.size(map)}, %{
      name: name,
      path: path,
      errors: length(errors)
    })

    if errors != [] do
      lines = for {line, reason} <- Enum.take(errors, 5), do: "#{path}:#{line}: #{reason}"
      more = if length(errors) > 5, do: ["(#{length(errors) - 5} more)"], else: []

      Logger.warning(
        "filter: map #{name}: entries left out:\n  " <> Enum.join(lines ++ more, "\n  ")
      )
    end
  end
end
