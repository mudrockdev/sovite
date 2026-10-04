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

  alias Sovite.Core.{Config, Logging, SMTPHandler, Telemetry}
  alias Sovite.Queue.Spool

  @spec start_link(keyword()) ::
          Supervisor.on_start()
          | {:error, {:invalid_config, list()} | {:queue_directory, File.posix()}}
  def start_link(opts \\ []) do
    with {:ok, config} <- fetch_config(opts),
         :ok <- init_queue(config.queue.directory),
         {:ok, pid} <-
           Supervisor.start_link(__MODULE__, config, name: Keyword.get(opts, :name, __MODULE__)) do
      # Logged here, not in init/1, so it reaches the log file.
      Logger.info("sovite started on #{config.server.hostname}")
      {:ok, pid}
    end
  end

  @impl true
  def init(%Config{} = config) do
    Config.put(config)
    Logging.configure(config.log)
    Telemetry.attach_logger()

    # The log file handler comes first so it stops last, after the
    # listeners have closed their sessions. The queue manager and delivery
    # agents are added here as the roadmap phases land.
    children = Logging.child_specs(config.log) ++ Enum.map(config.listener, &listener(&1, config))

    Supervisor.init(children, strategy: :one_for_one)
  end

  defp listener(%{address: address, port: port}, config) do
    smtp = config.smtp

    {Sovite.SMTP.Server,
     id: "smtp/#{:inet.ntoa(address)}:#{port}",
     ip: address,
     port: port,
     max_connections: smtp.max_connections,
     max_connections_per_ip: smtp.max_connections_per_ip,
     hostname: config.server.hostname,
     handler: {SMTPHandler, SMTPHandler.opts(config)},
     max_message_size: smtp.max_message_size,
     max_recipients: smtp.max_recipients,
     max_errors: smtp.max_errors,
     command_timeout: smtp.command_timeout,
     data_timeout: smtp.data_timeout,
     vrfy: smtp.vrfy,
     bare_line_endings: smtp.bare_line_endings}
  end

  defp init_queue(directory) do
    with {:error, reason} <- Spool.init(directory) do
      Logger.error("cannot set up queue directory #{directory}: #{:file.format_error(reason)}")
      {:error, {:queue_directory, reason}}
    end
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
