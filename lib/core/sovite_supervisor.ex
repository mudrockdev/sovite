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
    * `:queue_manager` - extra `Sovite.Core.QueueManager` options, such
      as `:name` (defaults to `Sovite.Core.QueueManager`) or `:resolver`.

  ## Children

  In start order: the log file handler, the database (migrated before
  anything else starts), the cache of the domains in the database, the
  failed-login counter, the certificate store
  and the ACME client (when TLS is configured), the queue manager, the
  DMARC report sender (with `dmarc.reports`), and the listeners. They stop in reverse order, so listeners close first.
  """

  use Supervisor

  require Logger

  alias Sovite.Abuse.Penalty
  alias Sovite.Core.Repo.Tables.DomainCache

  alias Sovite.Core.{
    ACME,
    Config,
    DMARCReports,
    Logging,
    QueueManager,
    Repo,
    SMTPHandler,
    Telemetry
  }

  alias Sovite.Queue.Spool
  alias Sovite.TLS.CertStore

  @cert_store Sovite.Core.CertStore
  @penalty Sovite.Core.AuthPenalty

  @spec start_link(keyword()) ::
          Supervisor.on_start()
          | {:error, {:invalid_config, list()} | {:queue_directory, File.posix()}}
  def start_link(opts \\ []) do
    with {:ok, config} <- fetch_config(opts),
         :ok <- init_queue(config.queue.directory),
         {:ok, pid} <-
           Supervisor.start_link(
             __MODULE__,
             {config, Keyword.get(opts, :queue_manager, [])},
             name: Keyword.get(opts, :name, __MODULE__)
           ) do
      # Logged here, not in init/1, so it reaches the log file.
      Logger.info("sovite started on #{config.server.hostname}")
      {:ok, pid}
    end
  end

  @impl true
  def init({%Config{} = config, manager_opts}) do
    Config.put(config)
    Logging.configure(config.log)
    Telemetry.attach_logger()

    manager_opts = Keyword.put_new(manager_opts, :name, QueueManager)
    repo = Repo.ref(config.database)
    tls = Config.tls_enabled?(config)
    auth = Config.auth_enabled?(config)

    runtime = %{
      queue_manager: manager_opts[:name],
      resolver: manager_opts[:resolver],
      repo: repo,
      penalty: if(auth, do: @penalty),
      cert_store: if(tls, do: @cert_store)
    }

    # Children stop in reverse order: listeners first, so no new mail
    # arrives, then the queue manager, and the log file handler last.
    children =
      Logging.child_specs(config.log) ++
        [
          {Repo, {config.database, elem(repo, 1)}},
          {DomainCache, repo: repo}
        ] ++
        if(auth, do: [penalty_spec(config)], else: []) ++
        if(tls, do: tls_specs(config), else: []) ++
        [{QueueManager, QueueManager.opts(config, repo) ++ manager_opts}] ++
        if(config.dmarc.reports, do: [dmarc_reports_spec(config, runtime)], else: []) ++
        Enum.map(config.listener, &listener(&1, config, runtime))

    Supervisor.init(children, strategy: :one_for_one)
  end

  defp penalty_spec(config) do
    {Penalty,
     name: @penalty,
     max_failures: config.auth.max_failures,
     window: config.auth.failure_window,
     ban_time: config.auth.ban_time}
  end

  defp dmarc_reports_spec(config, runtime) do
    {DMARCReports,
     [
       repo: runtime.repo,
       directory: config.queue.directory,
       hostname: config.server.hostname,
       org_name: config.dmarc.report_org,
       from: config.dmarc.report_from,
       interval: config.dmarc.report_interval,
       queue_manager: runtime.queue_manager
     ] ++ if(runtime.resolver, do: [resolver: runtime.resolver], else: [])}
  end

  defp tls_specs(config) do
    files = Enum.map(config.tls.certificate, &Map.take(&1, [:cert_file, :key_file]))
    acme = config.tls.acme

    # ACME certificates appear only after the first order succeeds.
    acme_files = if acme.enabled, do: [Map.put(ACME.files(acme), :optional, true)], else: []

    tls =
      [min_version: config.tls.min_version] ++
        if(config.tls.ciphers, do: [ciphers: config.tls.ciphers], else: [])

    [
      {CertStore,
       name: @cert_store,
       certificates: files ++ acme_files,
       tls: tls,
       reload_interval: config.tls.reload_interval}
    ] ++ if(acme.enabled, do: [{ACME, config: acme, cert_store: @cert_store}], else: [])
  end

  defp listener(listener, config, runtime) do
    %{address: address, port: port, mode: mode} = listener
    smtp = config.smtp

    handler =
      SMTPHandler.opts(
        config,
        runtime.queue_manager,
        [repo: runtime.repo, penalty: runtime.penalty, require_auth: listener.require_auth] ++
          if(runtime.resolver, do: [resolver: runtime.resolver], else: [])
      )

    {Sovite.SMTP.Server,
     id: "#{mode}/#{:inet.ntoa(address)}:#{port}",
     ip: address,
     port: port,
     max_connections: smtp.max_connections,
     max_connections_per_ip: smtp.max_connections_per_ip,
     hostname: config.server.hostname,
     handler: {SMTPHandler, handler},
     max_message_size: smtp.max_message_size,
     max_recipients: smtp.max_recipients,
     max_errors: smtp.max_errors,
     command_timeout: smtp.command_timeout,
     data_timeout: smtp.data_timeout,
     vrfy: smtp.vrfy,
     bare_line_endings: smtp.bare_line_endings,
     tls: tls_options(runtime.cert_store, listener),
     implicit_tls: mode == :submissions,
     require_tls: listener.require_tls and mode != :submissions,
     auth: listener.auth,
     auth_required: listener.require_auth,
     plaintext_auth: config.auth.plaintext,
     lmtp: mode == :lmtp}
  end

  defp tls_options(nil, _listener), do: nil

  # Read per connection, so reloaded certificates apply to new sessions.
  defp tls_options(store, listener) do
    overrides =
      if(listener.tls_min_version,
        do: [versions: Sovite.TLS.versions(listener.tls_min_version)],
        else: []
      ) ++
        case listener.tls_ciphers do
          nil -> []
          names -> [ciphers: names |> Sovite.TLS.ciphers() |> elem(1)]
        end

    fn ->
      case CertStore.server_options(store) do
        nil -> nil
        opts -> Keyword.merge(opts, overrides)
      end
    end
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
