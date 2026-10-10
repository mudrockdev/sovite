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
  failed-login counter, the certificate store and the ACME client (when
  TLS is configured), the MTA-STS policy cache (with `mta_sts.enabled`),
  the queue manager, the DMARC and TLS report senders (with
  `dmarc.reports` and `tls_rpt.reports`), the listeners, and the
  MTA-STS policy server (with `mta_sts.serve`). They stop in reverse
  order, so listeners close first.

  When DANE is used, a task checks once at startup that the DNS resolver
  validates DNSSEC, and logs a warning if not: DANE then never applies.
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
    MailAuth,
    MTASTS,
    QueueManager,
    Repo,
    SMTPHandler,
    Telemetry,
    TLSReports
  }

  alias Sovite.Queue.Spool
  alias Sovite.TLS.CertStore

  @cert_store Sovite.Core.CertStore
  @penalty Sovite.Core.AuthPenalty
  @mta_sts Sovite.Core.MTASTS

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
    runtime = runtime(config, manager_opts)

    manager_opts =
      [resolver: runtime.resolver, mta_sts: runtime.mta_sts] ++
        Keyword.drop(manager_opts, [:resolver])

    # Children stop in reverse order: listeners first, so no new mail
    # arrives, then the queue manager, and the log file handler last.
    children =
      Logging.child_specs(config.log) ++
        [
          {Repo, {config.database, elem(runtime.repo, 1)}},
          {DomainCache, repo: runtime.repo}
        ] ++
        security_specs(config, runtime) ++
        [{QueueManager, QueueManager.opts(config, runtime.repo) ++ manager_opts}] ++
        report_specs(config, runtime) ++
        Enum.map(config.listener, &listener(&1, config, runtime)) ++
        policy_specs(config, runtime)

    Supervisor.init(children, strategy: :one_for_one)
  end

  defp runtime(config, manager_opts) do
    %{
      queue_manager: manager_opts[:name],
      resolver: manager_opts[:resolver] || Config.resolver(config),
      repo: Repo.ref(config.database),
      penalty: if(Config.auth_enabled?(config), do: @penalty),
      cert_store: if(Config.tls_enabled?(config), do: @cert_store),
      mta_sts: if(config.mta_sts.enabled, do: @mta_sts)
    }
  end

  # The failed-login counter, the certificate store and ACME client, and
  # the MTA-STS policy cache.
  defp security_specs(config, runtime) do
    if(runtime.penalty, do: [penalty_spec(config)], else: []) ++
      if(runtime.cert_store, do: tls_specs(config), else: []) ++
      if(runtime.mta_sts, do: [mta_sts_spec(config, runtime)], else: [])
  end

  defp report_specs(config, runtime) do
    if(config.dmarc.reports, do: [dmarc_reports_spec(config, runtime)], else: []) ++
      if(config.tls_rpt.reports, do: [tls_reports_spec(config, runtime)], else: [])
  end

  # The MTA-STS policy server, and the DNSSEC check.
  defp policy_specs(config, runtime) do
    serve = config.mta_sts.serve and runtime.cert_store != nil

    if(serve, do: [policy_server_spec(config, runtime)], else: []) ++
      if(dnssec_check?(config), do: [dnssec_check_spec(runtime.resolver)], else: [])
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
       queue_manager: runtime.queue_manager,
       resolver: runtime.resolver,
       mail_auth: MailAuth.opts(config, runtime.repo, runtime.resolver)
     ]}
  end

  defp mta_sts_spec(config, runtime) do
    {MTASTS,
     name: runtime.mta_sts,
     repo: runtime.repo,
     resolver: runtime.resolver,
     fetch: [timeout: config.mta_sts.fetch_timeout]}
  end

  defp tls_reports_spec(config, runtime) do
    {TLSReports,
     repo: runtime.repo,
     directory: config.queue.directory,
     hostname: config.server.hostname,
     org_name: config.tls_rpt.report_org,
     from: config.tls_rpt.report_from,
     contact_info: config.tls_rpt.contact_info,
     interval: config.tls_rpt.report_interval,
     queue_manager: runtime.queue_manager,
     resolver: runtime.resolver,
     mail_auth: MailAuth.opts(config, runtime.repo, runtime.resolver)}
  end

  # Serves the same policy for every domain: it names this server's MX
  # host names.
  defp policy_server_spec(config, runtime) do
    mta_sts = config.mta_sts
    policy = Sovite.TLS.MTASTS.policy_text(mta_sts.mode, mta_sts.mx, div(mta_sts.max_age, 1000))
    store = runtime.cert_store

    {Sovite.Listener,
     id: "mta-sts/#{:inet.ntoa(mta_sts.address)}:#{mta_sts.port}",
     ip: mta_sts.address,
     port: mta_sts.port,
     max_connections: 100,
     max_connections_per_ip: 10,
     handler: Sovite.TLS.MTASTS.Server,
     handler_opts: [
       tls: fn -> CertStore.server_options(store) end,
       policy: fn _domain -> {:ok, policy} end
     ]}
  end

  defp dnssec_check?(config) do
    dane = config.delivery.tls == :dane or :dane in Map.values(config.delivery.tls_policy)
    dane and config.dns.dnssec != :off
  end

  defp dnssec_check_spec(resolver) do
    Supervisor.child_spec({Task, fn -> check_dnssec(resolver) end},
      id: :dnssec_check,
      restart: :temporary
    )
  end

  defp check_dnssec(resolver) do
    case Sovite.DNS.validating?(resolver) do
      {:ok, true} ->
        :ok

      {:ok, false} ->
        Logger.warning(
          "the DNS resolver does not validate DNSSEC, or is not on this host: " <>
            "DANE will not be used (see [dns] in the configuration)"
        )

      {:error, reason} ->
        Logger.warning("cannot check whether the DNS resolver validates DNSSEC: #{reason}")
    end
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
        repo: runtime.repo,
        penalty: runtime.penalty,
        require_auth: listener.require_auth,
        resolver: runtime.resolver
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
     lmtp: mode == :lmtp,
     requiretls: smtp.requiretls and mode != :lmtp}
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
