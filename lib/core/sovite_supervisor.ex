defmodule Sovite.Core.Supervisor do
  @moduledoc """
  Root supervisor of the Sovite MTA.

  It loads and validates the configuration before starting anything. With
  an invalid config, the errors are logged and `start_link/1` returns
  `{:error, {:invalid_config, errors}}`, so the MTA never runs with a
  half-valid setup.

  To embed the MTA in another application, add it to that application's
  supervision tree:

      children = [
        {Sovite.Core.Supervisor, config_path: "/etc/sovite/sovite.toml"}
      ]

  ## Options

    * `:config` - an already validated `Sovite.Core.Config` struct.
    * `:config_path` - path to the config file. Ignored when `:config` is
      given. Defaults to `Sovite.Core.Config.default_path/0`.
    * `:name` - the supervisor's registered name. Defaults to this module.
  """

  use Supervisor

  require Logger

  alias Sovite.Core.{Config, Logging, Telemetry}

  @spec start_link(keyword()) :: Supervisor.on_start() | {:error, {:invalid_config, list()}}
  def start_link(opts \\ []) do
    with {:ok, config} <- fetch_config(opts) do
      Supervisor.start_link(__MODULE__, config, name: Keyword.get(opts, :name, __MODULE__))
    end
  end

  @impl true
  def init(%Config{} = config) do
    Config.put(config)
    Logging.configure(config.log)
    Telemetry.attach_logger()

    Logger.info("sovite starting on #{config.server.hostname}")

    # Listeners, the queue manager, and delivery agents are added here as
    # the roadmap phases land.
    children = []

    Supervisor.init(children, strategy: :one_for_one)
  end

  defp fetch_config(opts) do
    case Keyword.fetch(opts, :config) do
      {:ok, %Config{} = config} -> {:ok, config}
      :error -> opts |> Keyword.get_lazy(:config_path, &Config.default_path/0) |> load_config()
    end
  end

  defp load_config(path) do
    with {:error, errors} <- Config.load(path) do
      for error <- errors do
        Logger.error("invalid configuration in #{path}: " <> Exception.message(error))
      end

      {:error, {:invalid_config, errors}}
    end
  end
end
