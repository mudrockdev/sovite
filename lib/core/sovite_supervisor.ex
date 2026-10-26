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
    * `:queue_manager` - extra `Sovite.Core.MTA.QueueManager` options, such
      as `:name` (defaults to `Sovite.Core.MTA.QueueManager`) or `:resolver`.

  ## Children

  In start order: the log file handler, the database (migrated before
  anything else starts), the cache of the domains in the database, the
  failed-login counter, the rate limiter, the caches of screened clients
  and suspended users, the greylist cleaner (with `greylist.enabled`),
  the certificate store and the ACME client (when TLS is configured),
  the MTA-STS policy cache (with `mta_sts.enabled`), the queue manager, the DMARC and TLS report senders (with
  `dmarc.reports` and `tls_rpt.reports`), the listeners, and the
  MTA-STS policy server (with `mta_sts.serve`). They stop in reverse
  order, so listeners close first.

  When DANE is used, a task checks once at startup that the DNS resolver
  validates DNSSEC, and logs a warning if not: DANE then never applies.

  Then, when enabled: the metrics (`Sovite.Core.Metrics`), the trace
  exporter (`Sovite.Core.Tracing`), the admin API listener
  (`Sovite.Core.Web`, the UI and admin API), the systemd watchdog, and last
  `Sovite.Core.Control`, which reloads the configuration on `SIGHUP` and
  drains the server when it stops.

  ## Parts of the stack

  The MTA's children (everything above but the log file handler, the
  database, the certificate store and ACME client, the cluster's
  membership and shared state, the metrics, the trace exporter, the
  admin API, the watchdog, and `Sovite.Core.Control`) start only with
  `stack.mta`. The filter and mailbox parts have nothing to start yet.

  ## Reloading

  `Sovite.Core.Control.reload/1` reads the config file again. Children
  whose options did not change keep running. Listeners take new options
  for new connections without closing their socket, when only their
  handler, PROXY protocol, or per-IP limit options changed; otherwise
  they are drained first. The queue manager takes its new options in
  place. Other children are restarted with theirs. Every child starts
  from the current configuration, so one that crashes after a reload
  comes back with the new options. Database and queue directory changes
  need a restart.

  ## Socket activation

  Under systemd socket activation (`Sovite.Systemd.listen_fds/1`), a
  listener whose address and port match an inherited socket uses it
  instead of opening its own.
  """

  use Supervisor

  require Logger

  alias Sovite.Abuse.{Cache, Penalty, RateLimit}
  alias Sovite.Core.Repo.Tables.DomainCache

  alias Sovite.Core.{
    ACME,
    Cluster,
    Config,
    Control,
    Logging,
    Metrics,
    Repo,
    Telemetry,
    Tracing,
    Web
  }

  alias Sovite.Core.MTA.{
    DMARCReports,
    Greylist,
    IPPools,
    MailAuth,
    MTASTS,
    Outbound,
    QueueManager,
    SMTPHandler,
    TLSReports
  }

  alias Sovite.Queue.Spool
  alias Sovite.TLS.CertStore

  @cert_store Sovite.Core.CertStore
  @penalty Sovite.Core.AuthPenalty
  @mta_sts Sovite.Core.MTA.MTASTS
  @rate_limit Sovite.Core.RateLimit
  @screen_cache Sovite.Core.ScreenCache
  @suspensions Sovite.Core.Suspensions

  @spec start_link(keyword()) ::
          Supervisor.on_start()
          | {:error, {:invalid_config, list()} | {:queue_directory, File.posix()}}
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)

    with {:ok, config} <- fetch_config(opts),
         :ok <- init_queue(config.queue.directory),
         {:ok, pid} <-
           Supervisor.start_link(
             __MODULE__,
             %{
               config: config,
               manager_opts: Keyword.get(opts, :queue_manager, []),
               config_path: if(Keyword.has_key?(opts, :config), do: nil, else: config_path(opts)),
               name: name,
               instance: make_ref(),
               module: __MODULE__
             },
             name: name
           ) do
      # Logged here, not in init/1, so it reaches the log file.
      Logger.info("sovite started on #{config.server.hostname}")
      {:ok, pid}
    end
  end

  @impl true
  def init(%{config: config} = args) do
    Config.put(config, args.instance)
    Logging.configure(config.log)
    Telemetry.attach_logger()

    args =
      args
      |> Map.put_new_lazy(:started_at, fn -> System.os_time(:second) end)
      |> Map.put_new_lazy(:names, fn ->
        %{
          control: name(args.name, Control),
          metrics: name(args.name, Metrics),
          tracing: name(args.name, Tracing),
          web: name(args.name, Web),
          web_penalty: name(args.name, Web.Penalty)
        }
      end)

    runtime = runtime(config, Map.put(args, :supervisor, self()))
    specs = children(config, runtime)
    put_specs(runtime.instance, specs)
    Supervisor.init(Enum.map(specs, &indirect(&1, runtime.instance)), strategy: :one_for_one)
  end

  @doc false
  # The runtime values the child specs are built from. `args` are those
  # of init/1, or Control's on reload.
  def runtime(config, args) do
    manager_opts = Keyword.put_new(args.manager_opts, :name, QueueManager)

    Map.merge(
      %{
        args: args,
        supervisor: args.supervisor,
        instance: args.instance,
        config_path: args.config_path,
        manager_opts: manager_opts,
        resolver: manager_opts[:resolver] || Config.resolver(config),
        repo: Repo.ref(config.database),
        cert_store: if(Config.tls_enabled?(config), do: @cert_store),
        outbound: Outbound.opts(config, @rate_limit, @suspensions),
        control: args.names.control,
        metrics: if(config.metrics.enabled and config.admin.enabled, do: args.names.metrics),
        tracing: if(config.tracing.enabled, do: args.names.tracing),
        started_at: args.started_at,
        inherited: inherited_sockets()
      },
      mta_runtime(Config.part?(config, :mta), config, manager_opts)
    )
  end

  # The MTA's processes, nil on a node that does not run it.
  defp mta_runtime(false, _config, _manager_opts) do
    %{
      mta: false,
      queue_manager: nil,
      penalty: nil,
      mta_sts: nil,
      rate_limit: nil,
      suspensions: nil,
      ip_pools: nil
    }
  end

  defp mta_runtime(true, config, manager_opts) do
    %{
      mta: true,
      queue_manager: manager_opts[:name],
      penalty: if(Config.auth_enabled?(config), do: @penalty),
      mta_sts: if(config.mta_sts.enabled, do: @mta_sts),
      rate_limit: @rate_limit,
      suspensions: @suspensions,
      ip_pools: if(config.ip_pool != [], do: IPPools)
    }
  end

  # Per instance, so supervisors started with `name: nil` (tests) do not
  # share process names.
  defp name(nil, module), do: :"#{module}.#{System.unique_integer([:positive])}"
  defp name(__MODULE__, module), do: module
  defp name(supervisor, module), do: Module.concat(supervisor, module)

  @doc false
  # The child specs for `config`, in start order. Children stop in
  # reverse order: Control first, which drains the listeners and the
  # queue manager, then the listeners, so no new mail arrives, then the
  # queue manager, and the log file handler last.
  def children(config, runtime) do
    manager_opts =
      [resolver: runtime.resolver, mta_sts: runtime.mta_sts, outbound: runtime.outbound] ++
        Keyword.drop(runtime.manager_opts, [:resolver])

    (Logging.child_specs(config.log) ++
       [{Repo, {config.database, elem(runtime.repo, 1)}}] ++
       mta_only(runtime, [{DomainCache, repo: runtime.repo}]) ++
       pool_specs(config, runtime) ++
       security_specs(config, runtime) ++
       mta_only(runtime, [{QueueManager, QueueManager.opts(config, runtime.repo) ++ manager_opts}]) ++
       Cluster.child_specs(config, runtime) ++
       mta_only(runtime, report_specs(config, runtime)) ++
       mta_only(runtime, Enum.map(config.listener, &listener(&1, config, runtime))) ++
       mta_only(runtime, policy_specs(config, runtime)) ++
       operations_specs(config, runtime) ++
       [{Control, runtime: runtime, config: config}])
    |> Enum.map(&Supervisor.child_spec(&1, []))
  end

  # The MTA's children start only when this node runs the MTA ([stack]).
  defp mta_only(%{mta: true}, specs), do: specs
  defp mta_only(_runtime, _specs), do: []

  ## Indirect starts

  # Each child starts through start_child/2, which looks its spec up by
  # ID, so a child restarted after a reload gets the reloaded spec.
  defp indirect(spec, instance) do
    {module, _function, _args} = spec.start

    spec
    |> Map.put(:start, {__MODULE__, :start_child, [instance, spec.id]})
    |> Map.put_new(:modules, [module])
  end

  @doc false
  def start_child(instance, id) do
    {module, function, args} = instance |> specs() |> Map.fetch!(id) |> Map.fetch!(:start)
    apply(module, function, args)
  end

  @doc false
  # The current child specs of a supervisor instance, by ID.
  def specs(instance), do: :persistent_term.get({__MODULE__, instance}, %{})

  @doc false
  def put_specs(instance, specs),
    do: :persistent_term.put({__MODULE__, instance}, Map.new(specs, &{&1.id, &1}))

  @doc false
  def erase_specs(instance), do: :persistent_term.erase({__MODULE__, instance})

  @doc false
  def indirect_spec(spec, instance), do: indirect(spec, instance)

  # Metrics, traces, the admin API, and the systemd watchdog.
  defp operations_specs(config, runtime) do
    manager = runtime.queue_manager

    metrics = %{
      name: runtime.metrics,
      queue_manager: manager,
      directory: config.queue.directory,
      supervisor: runtime.supervisor,
      started_at: runtime.started_at
    }

    if(runtime.metrics, do: [Metrics.child_spec(metrics)], else: []) ++
      if(runtime.tracing,
        do: [Tracing.child_spec(config.tracing, runtime.tracing, config.server.hostname)],
        else: []
      ) ++
      Web.child_specs(config, runtime) ++
      [{Sovite.Systemd.Watchdog, check: watchdog_check(manager)}]
  end

  # Without the MTA, there is no queue manager that could hang.
  defp watchdog_check(nil), do: fn -> true end
  defp watchdog_check(manager), do: fn -> is_map(QueueManager.stats(manager)) end

  # The failed-login counter, the anti-abuse processes, the certificate
  # store and ACME client, and the MTA-STS policy cache.
  defp security_specs(config, runtime) do
    if(runtime.penalty, do: [penalty_spec(config)], else: []) ++
      mta_only(runtime, abuse_specs(config, runtime)) ++
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

  defp pool_specs(config, runtime) do
    case IPPools.opts(config, IPPools, runtime.repo) do
      nil -> []
      opts -> [{IPPools, opts}]
    end
  end

  defp abuse_specs(config, runtime) do
    # In a cluster, counts go to the other nodes, by the wall clock.
    rate_limit =
      if config.cluster.enabled,
        do: [name: @rate_limit, replicate: true, clock: &Cluster.clock/0],
        else: [name: @rate_limit]

    [
      {RateLimit, rate_limit},
      {Cache, name: @screen_cache},
      {Cache, name: @suspensions}
    ] ++ if(config.greylist.enabled, do: [{Greylist, repo: runtime.repo}], else: [])
  end

  defp penalty_spec(config) do
    {Penalty,
     name: @penalty,
     max_failures: config.auth.max_failures,
     window: config.auth.failure_window,
     ban_time: config.auth.ban_time,
     replicate: config.cluster.enabled}
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
        resolver: runtime.resolver,
        screen: listener.screen,
        screen_cache: @screen_cache,
        rate_limit: @rate_limit,
        outbound: runtime.outbound,
        content_filter: listener.content_filter,
        reinjection: listener.reinjection,
        milters: listener.milters
      )

    {
      Sovite.SMTP.Server,
      [
        id: "#{mode}/#{:inet.ntoa(address)}:#{port}",
        ip: address,
        port: port
      ] ++
        inherited(runtime, address, port) ++
        [
          max_connections: smtp.max_connections,
          max_connections_per_ip: smtp.max_connections_per_ip,
          proxy_protocol: listener.proxy_protocol,
          proxy_networks: smtp.proxy_networks,
          proxy_timeout: smtp.proxy_timeout,
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
          requiretls: smtp.requiretls and mode != :lmtp,
          smtputf8: smtp.smtputf8,
          chunking: smtp.chunking,
          binarymime: smtp.binarymime,
          dsn: smtp.dsn,
          etrn: smtp.etrn and mode == :smtp,
          mt_priority: smtp.mt_priority,
          deliverby: smtp.deliverby,
          rrvs: smtp.rrvs,
          # RFC 4865 §3: only on submission ports.
          future_release:
            if(config.submission.future_release and mode in [:submission, :submissions],
              do: div(config.submission.max_future_release, 1000)
            ),
          tarpit_after: smtp.tarpit_after,
          tarpit_delay: smtp.tarpit_delay,
          forbid_unauth_pipelining: smtp.forbid_unauth_pipelining and mode != :lmtp,
          xclient_networks: smtp.xclient_networks,
          xforward_networks: smtp.xforward_networks
        ]
    }
  end

  ## Socket activation

  # The sockets systemd passed, by address. Read once: the environment
  # variables are removed, so programs Sovite runs do not see them.
  defp inherited_sockets do
    case :persistent_term.get({__MODULE__, :inherited}, nil) do
      nil ->
        sockets =
          for {_name, fd} <- Sovite.Systemd.listen_fds(unset: true),
              {:ok, {ip, port}} <- [Sovite.Systemd.socket_address(fd)],
              into: %{},
              do: {{Sovite.Net.normalize(ip), port}, fd}

        :persistent_term.put({__MODULE__, :inherited}, sockets)
        sockets

      sockets ->
        sockets
    end
  end

  defp inherited(runtime, address, port) do
    case Map.fetch(runtime.inherited, {address, port}) do
      {:ok, fd} -> [fd: fd]
      :error -> []
    end
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
      :error -> opts |> config_path() |> load_config()
    end
  end

  defp config_path(opts), do: Keyword.get_lazy(opts, :config_path, &Config.default_path/0)

  defp load_config(path) do
    with {:error, errors} <- Config.load(path) do
      for error <- errors do
        Logger.error("invalid configuration in #{path}: " <> Exception.message(error))
      end

      {:error, {:invalid_config, errors}}
    end
  end
end
