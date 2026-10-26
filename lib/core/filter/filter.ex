defmodule Sovite.Core.Filter do
  @moduledoc """
  The filter part of the stack (`[stack] filter`), in place of Rspamd.

  So far it is the rule engine: messages are taken apart by
  `Sovite.Analyzer` and scored by the rules of `[filter] rules`
  (`Sovite.Rules`), which `Sovite.Core.Filter.Server` keeps loaded, and
  reloads with the maps they read when the files change. Sovite's own
  checks count as symbols (`Sovite.Core.Filter.Checks`), and the score
  decides an action (`Sovite.Core.Filter.Actions`). Scanning in the
  MTA's session follows (see `ROADMAP.md`).
  """

  alias Sovite.Analyzer
  alias Sovite.Core.Config
  alias Sovite.Core.Filter.{Checks, RuleFiles, Server}
  alias Sovite.Rules

  @doc """
  The flags rule expressions may use: `is:authenticated` (the sender
  logged in), `is:trusted` (from `[smtp] trusted_networks`), `is:tls`,
  `is:inbound` (for a hosted or local domain), and `is:outbound`.
  """
  @spec flags() :: [String.t()]
  defdelegate flags, to: RuleFiles

  @doc """
  The part's processes: the server that keeps the rules loaded. None when
  the part is off.
  """
  @spec child_specs(Config.t(), term()) :: [Supervisor.child_spec()]
  def child_specs(config, instance) do
    if Config.part?(config, :filter) do
      opts = [
        instance: instance,
        rules: config.filter.rules,
        flags: RuleFiles.flags(),
        hostname: config.server.hostname,
        reload_interval: config.filter.reload_interval,
        timeout: config.filter.timeout
      ]

      [Supervisor.child_spec({Server, opts}, id: Server)]
    else
      []
    end
  end

  @doc """
  Scans a message with the loaded rules. Options are those of
  `Sovite.Rules.scan/3`, but `:maps` and `:timeout`, which come from the
  configuration, and `:checks`, results of Sovite's own checks
  (`Sovite.Core.Filter.Checks`). Their symbols, then those of the header
  checks (`Sovite.HeaderChecks`), come before those of `:symbols`. `{:error, :not_running}` when the part is not.
  """
  @spec scan(term(), binary(), keyword()) :: {:ok, Rules.result()} | {:error, :not_running}
  def scan(instance, message, opts \\ []) when is_binary(message) do
    case Server.loaded(instance) do
      nil ->
        {:error, :not_running}

      loaded ->
        {checks, opts} = Keyword.pop(opts, :checks, %{})
        analysis = Analyzer.analyze(message)
        envelope = Map.new(Keyword.get(opts, :envelope, %{}))

        symbols =
          Checks.symbols(checks) ++
            Checks.headers(analysis, envelope, loaded.hostname) ++
            Keyword.get(opts, :symbols, [])

        opts =
          Keyword.merge(opts,
            raw: message,
            symbols: symbols,
            maps: loaded.maps,
            timeout: loaded.timeout
          )

        {:ok, Rules.scan(loaded.rules, analysis, opts)}
    end
  end
end
