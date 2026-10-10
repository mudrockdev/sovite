defmodule Sovite.Core.SMTPHandler do
  @moduledoc """
  The MTA's `Sovite.SMTP.Server.Handler`: relay control, restrictions,
  authentication, recipient checks and expansion, and durable spooling.

  Recipients are checked at `RCPT` time:

  1. `<Postmaster>`, and `postmaster@` and `abuse@` any hosted domain, are
     always accepted (RFC 5321 §4.5.1, RFC 2142). A bare `<Postmaster>` is
     queued as `postmaster@<server.hostname>`.
  2. Domains this server handles (local, aliased, hosted, and relay; see
     `Sovite.Core.Routing`): the recipient is
     expanded (`Sovite.Core.Recipients.expand/2`); one that no alias
     matched must be a known user (`Sovite.Core.Recipients.check/2`),
     otherwise `550 5.1.1`.
  3. Any other destination, including address literals: accepted only from
     `smtp.trusted_networks` or after `AUTH`, otherwise `554 5.7.1 Relay
     access denied`. The default config trusts no one, so it is never an
     open relay.

  Domains are compared case-insensitively. Address tricks such as
  `user%remote@local` or source routes do not relay: only the domain of
  the parsed mailbox counts.

  The anti-abuse checks (`Sovite.Core.Screen`: the postscreen-like
  client score, rate limits, greylisting, and suspended users) run
  first at each stage.

  The restriction chains (`Sovite.Core.Restrictions`) run at connect,
  `EHLO`, `MAIL`, `RCPT`, `DATA`, and at the end of the data, after the
  built-in checks of each stage; they can reject, but never permit what
  relay control or recipient validation refuses. Policy servers in them
  (`Sovite.Core.PolicyService`) may also add header fields, redirect or
  copy the message, or send it to a content filter.

  The listener's milters (`Sovite.Core.Milters`) see each stage last,
  and change the message at the end of the data.

  ## Rewriting

  The sender is rewritten at `MAIL` (`Sovite.Core.Rewrite.sender/2`) and
  each recipient at `RCPT`, before expansion. `routing.always_bcc` and
  the BCC maps add recipients at `DATA`. Mail from trusted networks and
  authenticated clients also gets its header addresses rewritten.

  ## Authentication

  `AUTH` runs against the configured backend (`auth.backend`), see
  `Sovite.SASL.Server` and `Sovite.SASL.Dovecot`. Failed logins are
  counted per client address (per /64 for IPv6) in a
  `Sovite.Abuse.Penalty`; a banned address gets `454 4.7.0` to `AUTH`, and
  is turned away at connect on listeners that require authentication.
  Each failure is answered after `auth.failure_delay`, to slow down
  guessing.

  An authenticated client may only use the sender addresses its login
  maps to, see `Sovite.Core.SenderCheck`.

  ## Submission fixes

  Messages from authenticated clients are fixed up as RFC 6409 §8 allows:
  a missing `Date:` or `Message-ID:` is added, and the header fields in
  `submission.strip_headers` are removed.

  ## Email authentication

  Mail from outside is checked with SPF, DKIM, ARC, and DMARC, mail from
  users is DKIM signed, and forwarded mail is ARC sealed, see
  `Sovite.Core.MailAuth`.

  With `srs.enabled`, mail from outside that an alias forwards to another
  domain gets an SRS sender address (`Sovite.SRS`) for that delivery, so
  SPF passes at the destination. Bounces to those addresses are accepted
  for the original sender at `RCPT`, and invalid or expired ones are
  refused with `550 5.1.1`.

  ## REQUIRETLS

  With `smtp.requiretls` (the default), `REQUIRETLS` (RFC 8689) is
  offered over TLS. A message sent with it is queued with
  `requiretls`, so `Sovite.Core.Delivery` relays it only over verified
  TLS.

  ## Loops

  A message with more than `smtp.max_hops` `Received:` fields is refused
  at the end of the data with `554 5.4.6` (RFC 5321 §6.3): it is most
  likely going round in circles.

  ## Proxies and content filters

  A client that used `XCLIENT` (from `smtp.xclient_networks`) is
  treated as the client it named: its `LOGIN` counts as authenticated,
  and its `NAME` as its verified reverse DNS name.

  On a listener with a content filter, messages are queued for the
  filter (`Sovite.Core.QueueManager`). A `reinjection` listener is
  where filters send them back: email authentication is skipped there,
  as it ran when the message first arrived. `XFORWARD` attributes from
  the filter (`smtp.xforward_networks`) are kept as the message's
  original client.

  ## Queueing

  The message is accepted with `250` only after `Sovite.Queue.Spool`
  has made it durable. A `Received:` header is added at the top. The
  queue manager given as `:queue_manager` is then told about it. A
  message a restriction put on hold goes to the hold queue instead; one
  it discarded is accepted and dropped.

  ## Telemetry

    * `[:sovite, :smtp, :message, :discarded]` and `[:sovite, :smtp,
      :message, :held]` - `%{}`, `%{session_id, queue_id, reason}`
    * `[:sovite, :routing, :expansion_error]` - `%{}`, `%{session_id,
      recipient, reason}`
  """

  @behaviour Sovite.SMTP.Server.Handler

  require Logger

  alias Sovite.Abuse.{Penalty, ReverseDNS}

  alias Sovite.Core.{
    Config,
    Logging,
    MailAuth,
    Milters,
    Outbound,
    PolicyService,
    QueueManager,
    Recipients,
    Restrictions,
    Rewrite,
    Router,
    Routing,
    Screen,
    SenderCheck
  }

  alias Sovite.Core.Repo.Tables.{AccessRules, Users}

  alias Sovite.{AuthResults, SASL, SRS}
  alias Sovite.Message.{Date, Headers, MessageID, Received, Trace}
  alias Sovite.Milter.Headers, as: MilterHeaders
  alias Sovite.Net
  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.SMTP.Reply

  # Header sections larger than this are passed through unchanged.
  @max_header_section 1024 * 1024

  @doc """
  Handler options from the running configuration.

    * `queue_manager` - the `Sovite.Core.QueueManager` to notify about new
      messages, if any.
    * `runtime` - `:repo` (a `Sovite.Core.Repo` reference), `:milters`
      (the names of the listener's milters), `:penalty`
      (the name of the `Sovite.Abuse.Penalty` for failed logins),
      `:require_auth` (the listener requires authentication),
      `:resolver` (for restrictions that look up domains), and the
      `Sovite.Core.Screen` options `:screen`, `:screen_cache`,
      `:rate_limit`, and `:outbound`, and the listener's
      `:content_filter` and `:reinjection`.
  """
  @spec opts(Config.t(), GenServer.server() | nil, keyword()) :: map()
  def opts(config, queue_manager \\ nil, runtime \\ []) do
    repo = runtime[:repo]
    resolver = Keyword.get_lazy(runtime, :resolver, fn -> Config.resolver(config) end)

    %{
      queue_manager: queue_manager,
      hostname: config.server.hostname,
      queue_directory: config.queue.directory,
      routing: Routing.new(config, repo),
      local_recipients:
        config.domains.local_recipients && MapSet.new(config.domains.local_recipients),
      trusted_networks: config.smtp.trusted_networks,
      max_hops: config.smtp.max_hops,
      restrictions: config.restrictions,
      access: access_tables(repo),
      resolver: resolver,
      repo: repo,
      penalty: runtime[:penalty],
      require_auth: Keyword.get(runtime, :require_auth, false),
      auth: auth_opts(config, repo),
      failure_delay: config.auth.failure_delay,
      sender_check: config.auth.sender_check,
      senders:
        Map.new(config.auth.senders, fn {login, patterns} ->
          {String.downcase(login), patterns}
        end),
      strip_headers: config.submission.strip_headers,
      mail_auth: MailAuth.opts(config, repo, resolver),
      srs: config.srs,
      screen: Screen.opts(config, runtime),
      own_names: Enum.uniq([String.downcase(config.server.hostname) | config.domains.local]),
      reverse_dns: Restrictions.reverse_dns?(config.restrictions),
      content_filter: runtime[:content_filter],
      reinjection: Keyword.get(runtime, :reinjection, false),
      milter_configs: Milters.opts(config, Keyword.get(runtime, :milters, [])),
      policy: policy_opts(config.policy)
    }
  end

  defp policy_opts(policy) do
    {:ok, default} = Sovite.Policy.parse_action(policy.default_action)
    %{timeout: policy.timeout, default_action: default}
  end

  # The access rule tables, by kind, for the restriction chains.
  defp access_tables(nil), do: %{}

  defp access_tables(repo) do
    Map.new([:client, :helo, :sender, :recipient], fn kind ->
      {kind, [{"access_rules", {AccessRules, %{repo: repo, kind: kind}}}]}
    end)
  end

  defp auth_opts(%{auth: %{backend: :dovecot} = auth} = config, _repo) do
    socket =
      case auth.dovecot.socket do
        "/" <> _ = path ->
          path

        address ->
          [host, port] = String.split(address, ":", parts: 2)
          {host, String.to_integer(port)}
      end

    %{
      kind: :dovecot,
      mechanisms: Config.auth_mechanisms(config),
      opts: [socket: socket, timeout: auth.dovecot.timeout]
    }
  end

  defp auth_opts(%{auth: auth} = config, repo) do
    backend =
      case auth.backend do
        :database -> {Users, repo: repo}
        :file -> {SASL.Backend.Static, file: auth.file.path}
        :ldap -> {SASL.Backend.LDAP, ldap_opts(auth.ldap)}
      end

    token_backend =
      if auth.oauth.introspection_url do
        {SASL.Backend.Introspection,
         [url: auth.oauth.introspection_url, username_claim: auth.oauth.username_claim] ++
           compact(
             client_id: auth.oauth.client_id,
             client_secret: auth.oauth.client_secret,
             required_scope: auth.oauth.required_scope
           )}
      end

    mechanisms = Config.auth_mechanisms(config)

    %{
      kind: :sasl,
      mechanisms: mechanisms,
      opts: [backend: backend, token_backend: token_backend, mechanisms: mechanisms]
    }
  end

  defp ldap_opts(ldap) do
    [servers: ldap.servers, security: ldap.security, filter: ldap.filter, timeout: ldap.timeout] ++
      compact(
        port: ldap.port,
        base: ldap.base,
        dn_template: ldap.dn_template,
        bind_dn: ldap.bind_dn,
        bind_password: ldap.bind_password
      )
  end

  defp compact(keyword), do: Enum.reject(keyword, fn {_key, value} -> is_nil(value) end)

  @impl true
  def init(connection, opts) do
    Logger.metadata(
      session_id: connection.session_id,
      remote_ip: Logging.format_ip(connection.remote_ip)
    )

    state =
      Map.merge(opts, %{
        connection: connection,
        trusted: Net.in_networks?(connection.remote_ip, opts.trusted_networks),
        tls: Map.get(connection, :tls),
        # Set by XCLIENT.
        identity: Map.get(connection, :login),
        sasl: nil,
        mechanism: nil,
        helo: nil,
        esmtp: false,
        lmtp: false,
        sender: nil,
        envelope_sender: nil,
        expansions: [],
        session_action: nil,
        action: nil,
        writer: nil,
        queue_id: nil,
        header: nil,
        spf: nil,
        auth_work: nil,
        prefix: [],
        score: Screen.new(),
        client_dns: nil,
        milters: nil,
        transactions: 0,
        next_id: nil,
        size: nil,
        effects: [],
        session_effects: [],
        received: nil,
        header_fields: nil,
        header_end: nil
      })

    if opts.require_auth and banned?(state) do
      {:close,
       Reply.new(
         421,
         "4.7.0",
         "#{opts.hostname} Too many failed logins from your address, try again later"
       ), state}
    else
      with {:ok, state} <- Screen.limit_connection(state),
           do: connect(%{state | client_dns: client_dns(state)})
    end
  end

  defp connect(state) do
    case restrict(state, :connect) do
      {:ok, state} -> screen(%{state | session_action: state.action, action: nil})
      {:reply, reply, state} -> {:close, reply, state}
    end
  end

  defp screen(state) do
    case Screen.connect(state) do
      {:ok, state} ->
        connect_milters(state)

      {:pause, delay, state} ->
        with {:ok, state} <- connect_milters(state), do: {:pause, delay, state}
    end
  end

  defp connect_milters(state) do
    case Milters.connect(state.milter_configs, milter_info(state)) do
      {:ok, milters} -> {:ok, %{state | milters: milters}}
      {:close, reply, milters} -> {:close, reply, %{state | milters: milters}}
    end
  end

  defp milter_info(state) do
    %{
      hostname: state.hostname,
      connection: state.connection,
      client_dns: state.client_dns,
      tls: state.tls,
      identity: state.identity,
      mechanism: state.mechanism,
      queue_id: state.next_id
    }
  end

  # Runs a milter step; its result replaces the session's milters.
  defp milters(state, fun) do
    case fun.(state.milters) do
      {:ok, milters} -> {:ok, %{state | milters: milters}}
      {:reply, reply, milters} -> {:reply, reply, %{state | milters: milters}}
      {:close, reply, milters} -> {:close, reply, %{state | milters: milters}}
    end
  end

  # Looked up once, for the restrictions that need it. A proxy that used
  # XCLIENT has looked it up already.
  defp client_dns(%{connection: %{client_name: name}}) when name != nil, do: {:ok, name}

  defp client_dns(%{connection: %{reverse_name: name}}) when name != nil,
    do: {:unconfirmed, [name]}

  defp client_dns(%{connection: connection}) when is_map_key(connection, :client_name), do: :none

  defp client_dns(%{reverse_dns: true, trusted: false} = state),
    do: ReverseDNS.check(state.resolver, state.connection.remote_ip)

  defp client_dns(_state), do: nil

  @impl true
  def handle_greet(early_input, state), do: Screen.greet(early_input, state)

  @impl true
  def handle_helo(kind, name, state) do
    state = %{state | helo: name, esmtp: kind != :helo, lmtp: kind == :lhlo}

    with {:ok, state} <- Screen.helo(state),
         {:ok, state} <- restrict(state, :helo),
         {:ok, state} <- milters(state, &Milters.helo(&1, name, milter_info(state))) do
      {:ok, %{state | session_action: state.action || state.session_action, action: nil}}
    end
  end

  @impl true
  def handle_tls(info, state), do: %{state | tls: info, helo: nil, esmtp: false}

  @impl true
  def handle_mail(sender, params, state) do
    state = %{
      state
      | sender: sender,
        envelope_sender: nil,
        expansions: [],
        action: nil,
        spf: nil,
        effects: [],
        size: params.size,
        transactions: state.transactions + 1,
        next_id: ID.generate()
    }

    with {:ok, state} <- Screen.mail(sender, state),
         {:ok, state} <- check_sender(sender, state),
         {:ok, state} <- restrict(state, :mail),
         {:ok, state} <- check_spf(sender, state),
         {:ok, state} <- rewrite_sender(sender, state) do
      milters(state, &Milters.mail(&1, sender, params, milter_info(state)))
    end
  end

  defp check_spf(sender, state) do
    if inbound?(state) do
      case MailAuth.check_spf(state.mail_auth, state.connection.remote_ip, state.helo, sender) do
        {:ok, spf} -> {:ok, %{state | spf: spf}}
        {:reject, reply, spf} -> {:reply, reply, %{state | spf: spf}}
      end
    else
      {:ok, state}
    end
  end

  # Mail from clients that are neither trusted nor authenticated. Over
  # LMTP the client is the MTA that already checked the mail, and on a
  # re-injection listener Sovite itself did.
  defp inbound?(state),
    do: not state.trusted and state.identity == nil and not state.lmtp and not state.reinjection

  defp check_sender(sender, %{identity: identity, sender_check: true} = state)
       when identity != nil do
    case allowed_sender?(identity, sender, state) do
      true ->
        {:ok, state}

      false ->
        text = "<#{sender}>: Sender address rejected: not owned by user #{identity}"
        {:reply, Reply.new(553, "5.7.1", text), state}

      :error ->
        {:reply, Reply.new(451, "4.3.0", "Temporary lookup failure"), state}
    end
  end

  defp check_sender(_sender, state), do: {:ok, state}

  defp allowed_sender?(identity, sender, state) do
    configured = Map.get(state.senders, String.downcase(identity), [])

    stored =
      if state.repo,
        do: Users.senders(state.repo, identity),
        else: []

    SenderCheck.allowed?(identity, sender, configured ++ stored)
  rescue
    error ->
      Logger.error("cannot read sender logins: #{Exception.message(error)}")
      :error
  end

  defp rewrite_sender(sender, state) do
    case Rewrite.sender(state.routing, sender) do
      {:ok, rewritten} -> {:ok, %{state | envelope_sender: rewritten}}
      {:error, _table} -> {:reply, temporary_failure(), state}
    end
  end

  @impl true
  def handle_rcpt(recipient, state) do
    with {:ok, checked} <- check_rcpt(recipient, state) do
      # A refused recipient must not stay among the expansions.
      with {:ok, checked} <- Screen.rcpt(recipient, checked),
           {:ok, checked} <- milters(checked, &Milters.rcpt(&1, recipient)) do
        {:ok, checked}
      else
        {:reply, reply, checked} -> {:reply, reply, %{state | milters: checked.milters}}
        {:close, reply, checked} -> {:close, reply, %{state | milters: checked.milters}}
      end
    end
  end

  defp check_rcpt(recipient, state) do
    case srs_reverse(recipient, state) do
      nil ->
        check_recipient(recipient, state)

      {:ok, original} ->
        with {:ok, state} <- restrict(state, :rcpt, recipient: recipient),
             do: {:ok, %{state | expansions: state.expansions ++ [original]}}

      {:error, _reason} ->
        {:reply, Reply.new(550, "5.1.1", "<#{recipient}>: Invalid or expired SRS address"), state}
    end
  end

  # A bounce to an SRS address this server made: back to the original
  # sender.
  defp srs_reverse(recipient, %{srs: %{enabled: true} = srs}) do
    with {:ok, {_local, domain}} <- Sovite.Validators.split_mailbox(recipient),
         true <- String.downcase(domain, :ascii) == srs.domain,
         true <- SRS.srs?(recipient) do
      SRS.reverse(recipient, secrets: srs.secrets, max_age: srs.max_age)
    else
      _ -> nil
    end
  end

  defp srs_reverse(_recipient, _state), do: nil

  defp check_recipient(recipient, state) do
    case classify(recipient, state) do
      :remote when not state.trusted and state.identity == nil ->
        {:reply, Reply.new(554, "5.7.1", "<#{recipient}>: Relay access denied"), state}

      class ->
        with {:ok, state} <- restrict(state, :rcpt, recipient: recipient) do
          accept_recipient(recipient, class, state)
        end
    end
  end

  defp accept_recipient(recipient, class, state) do
    address = queued_address(recipient, state)

    with {:ok, rewritten} <- Rewrite.recipient(state.routing, address),
         {:ok, finals} <- expand(state, rewritten),
         :ok <- validate(state, class, rewritten, finals) do
      {:ok, %{state | expansions: state.expansions ++ finals}}
    else
      {:error, _table} -> {:reply, temporary_failure(), state}
      {:reject, reply} -> {:reply, reply, state}
    end
  end

  defp expand(state, address) do
    case Recipients.expand(state.routing, address) do
      {:ok, finals} ->
        {:ok, finals}

      {:error, _kind, reason} ->
        :telemetry.execute([:sovite, :routing, :expansion_error], %{}, %{
          session_id: state.connection.session_id,
          recipient: address,
          reason: reason
        })

        {:reject, Reply.new(451, "4.3.0", "<#{address}>: Temporary lookup failure")}
    end
  end

  # Only an address that no alias matched must be a known user; aliased
  # ones are checked at delivery, so one broken alias destination does
  # not refuse the whole alias.
  defp validate(_state, :postmaster, _address, _finals), do: :ok
  defp validate(_state, _class, address, [final]) when final != address, do: :ok
  defp validate(_state, _class, _address, [_, _ | _]), do: :ok

  defp validate(state, _class, address, _finals) do
    case Recipients.check(state.routing, address) do
      {:ok, _class} -> :ok
      {:reject, status, text} -> {:reject, Reply.new(550, status, text)}
      {:error, _text} -> {:reject, temporary_failure()}
    end
  end

  defp temporary_failure, do: Reply.new(451, "4.3.0", "Temporary lookup failure")

  ## Restrictions

  # Runs the chain for `stage`. A HOLD or DISCARD is kept in
  # `state.action`, for the message.
  defp restrict(state, stage, extra \\ []) do
    checks = Map.get(state.restrictions, stage, [])

    if checks == [] do
      {:ok, state}
    else
      {verdict, effects} = Restrictions.check(checks, stage, restriction_context(state, extra))
      state = add_effects(state, stage, effects)

      case verdict do
        :ok -> {:ok, state}
        {:reject, reply} -> {:reply, reply, state}
        action -> {:ok, %{state | action: stronger(state.action, action)}}
      end
    end
  end

  # Effects at connect and EHLO hold for the session, the others for
  # the message.
  defp add_effects(state, _stage, []), do: state

  defp add_effects(state, stage, effects) when stage in [:connect, :helo],
    do: %{state | session_effects: state.session_effects ++ effects}

  defp add_effects(state, _stage, effects), do: %{state | effects: state.effects ++ effects}

  defp stronger({:discard, _} = discard, _action), do: discard
  defp stronger(_current, action), do: action

  defp restriction_context(state, extra) do
    Map.merge(
      %{
        client_ip: state.connection.remote_ip,
        helo: state.helo,
        sender: state.sender,
        recipient: nil,
        trusted: state.trusted,
        authenticated: state.identity != nil,
        access: state.access,
        resolver: state.resolver,
        delimiter: state.routing.delimiter,
        own_names: state.own_names,
        client_dns: state.client_dns,
        esmtp: state.esmtp,
        policy: state.policy,
        policy_request: fn -> policy_request(state) end
      },
      Map.new(extra)
    )
  end

  defp policy_request(state) do
    PolicyService.request(%{
      connection: state.connection,
      tls: state.tls,
      client_dns: state.client_dns,
      helo: state.helo,
      esmtp: state.esmtp,
      lmtp: state.lmtp,
      queue_id: state.queue_id,
      instance: "#{state.connection.session_id}.#{state.transactions}",
      recipient_count: if(state.writer, do: length(state.expansions), else: 0),
      identity: state.identity,
      mechanism: state.mechanism,
      size: state.size
    })
  end

  ## AUTH

  @impl true
  def auth_mechanisms(state), do: state.auth.mechanisms

  @impl true
  def handle_auth(mechanism, initial, state) do
    if banned?(state) do
      reply = Reply.new(454, "4.7.0", "Too many failed logins from your address, try again later")
      auth_event(:failure, state, mechanism, nil, :banned)
      {:error, reply, state}
    else
      state = %{state | mechanism: mechanism}

      result =
        case state.auth.kind do
          :sasl -> SASL.Server.start(mechanism, initial, state.auth.opts)
          :dovecot -> SASL.Dovecot.start(mechanism, initial, dovecot_opts(state))
        end

      auth_result(result, state)
    end
  end

  @impl true
  def handle_auth_response(response, state) do
    result =
      case state.auth.kind do
        :sasl -> SASL.Server.step(state.sasl, response)
        :dovecot -> SASL.Dovecot.step(state.sasl, response)
      end

    auth_result(result, state)
  end

  @impl true
  def handle_auth_abort(state) do
    if state.auth.kind == :dovecot and state.sasl, do: SASL.Dovecot.abort(state.sasl)
    %{state | sasl: nil}
  end

  defp dovecot_opts(state) do
    connection = state.connection

    client = %{
      remote_ip: connection.remote_ip,
      remote_port: Map.get(connection, :remote_port),
      local_ip: Map.get(connection, :local_ip),
      local_port: Map.get(connection, :local_port),
      secured: state.tls != nil
    }

    state.auth.opts ++ [client: client]
  end

  defp auth_result({:ok, identity}, state) do
    auth_event(:success, state, state.mechanism, identity, nil)
    {:ok, identity, %{state | identity: identity, sasl: nil}}
  end

  defp auth_result({:challenge, data, sasl}, state), do: {:challenge, data, %{state | sasl: sasl}}

  defp auth_result({:error, :temporary, username}, state) do
    auth_event(:failure, state, state.mechanism, username, :temporary)
    {:error, Reply.new(454, "4.7.0", "Temporary authentication failure"), %{state | sasl: nil}}
  end

  defp auth_result({:error, :unsupported_mechanism, _username}, state),
    do:
      {:error, Reply.new(504, "5.5.4", "Unrecognized authentication type"), %{state | sasl: nil}}

  defp auth_result({:error, reason, username}, state) do
    auth_event(:failure, state, state.mechanism, username, reason)
    if state.penalty, do: Penalty.failure(state.penalty, penalty_key(state.connection.remote_ip))
    if state.failure_delay > 0, do: Process.sleep(state.failure_delay)

    {:error, Reply.new(535, "5.7.8", "Authentication credentials invalid"), %{state | sasl: nil}}
  end

  defp banned?(%{penalty: nil}), do: false
  defp banned?(state), do: Penalty.banned?(state.penalty, penalty_key(state.connection.remote_ip))

  @doc false
  defdelegate penalty_key(ip), to: Screen, as: :address_key

  defp auth_event(result, state, mechanism, username, reason) do
    :telemetry.execute([:sovite, :auth, result], %{}, %{
      session_id: state.connection.session_id,
      remote_ip: state.connection.remote_ip,
      mechanism: mechanism,
      username: username,
      reason: reason
    })
  end

  ## Data

  @impl true
  def handle_data(transaction, state) do
    with {:ok, state} <- restrict(state, :data),
         {:ok, recipients} <- envelope_recipients(state),
         {:ok, state} <- milters(state, &Milters.data(&1, milter_info(state))) do
      open_message(transaction, recipients, state)
    end
  end

  # The expanded recipients and the BCC addresses, themselves expanded.
  defp envelope_recipients(state) do
    sender = state.envelope_sender || state.sender || ""

    with {:ok, bcc} <- Recipients.bcc(state.routing, sender, state.expansions),
         {:ok, bcc} <- expand_all(state, bcc) do
      {:ok, Enum.uniq_by(state.expansions ++ bcc, &String.downcase/1)}
    else
      {:error, _reason} -> {:reply, temporary_failure(), state}
      {:reject, reply} -> {:reply, reply, state}
    end
  end

  defp expand_all(state, addresses) do
    Enum.reduce_while(addresses, {:ok, []}, fn address, {:ok, acc} ->
      case expand(state, address) do
        {:ok, finals} -> {:cont, {:ok, acc ++ finals}}
        error -> {:halt, error}
      end
    end)
  end

  defp open_message(transaction, recipients, state) do
    queue_id = state.next_id || ID.generate()
    received_at = DateTime.utc_now()

    protocol =
      Received.protocol(
        lmtp: state.lmtp,
        esmtp: state.esmtp,
        tls: state.tls != nil,
        auth: state.identity != nil
      )

    sender = state.envelope_sender || transaction.sender
    # A content filter's XFORWARD names the original client.
    xforward = Map.get(transaction, :xforward, %{})

    envelope = %Envelope{
      queue_id: queue_id,
      sender: sender,
      srs_sender: srs_sender(sender, recipients, state),
      recipients: recipients,
      received_at: received_at,
      session_id: state.connection.session_id,
      remote_ip: xforward[:addr] || state.connection.remote_ip,
      helo: if(xforward[:addr], do: xforward[:helo], else: state.helo),
      protocol: protocol,
      body_type: transaction.params.body,
      auth_user: state.identity,
      content_filter: state.content_filter,
      requiretls: Map.get(transaction.params, :requiretls, false)
    }

    received =
      Received.build(%{
        helo: state.helo,
        remote_ip: state.connection.remote_ip,
        by: state.hostname,
        protocol: protocol,
        id: queue_id,
        for: if(match?([_], transaction.recipients), do: hd(transaction.recipients)),
        date: received_at,
        tls: state.tls && Sovite.TLS.describe(state.tls)
      })

    with {:ok, writer} <- Spool.open(state.queue_directory, envelope),
         {:ok, writer} <- Spool.write(writer, received) do
      Logger.metadata(queue_id: queue_id)
      # The header section is held back to count hops, and to be fixed or
      # rewritten.
      {:ok, %{state | writer: writer, queue_id: queue_id, header: "", received: received}}
    else
      {:error, reason} -> queue_error(state, reason)
    end
  end

  # The sender for forwarding mail from outside to other domains.
  defp srs_sender(sender, recipients, %{srs: %{enabled: true} = srs} = state) when sender != "" do
    if inbound?(state) and remote?(sender, state) and Enum.any?(recipients, &remote?(&1, state)) do
      case SRS.forward(sender, srs.domain, secrets: srs.secrets) do
        {:ok, address} -> address
        {:error, _reason} -> nil
      end
    end
  end

  defp srs_sender(_sender, _recipients, _state), do: nil

  defp remote?(address, state) do
    case Sovite.Validators.split_mailbox(address) do
      {:ok, {_local, domain}} ->
        Routing.class(state.routing, String.downcase(domain, :ascii)) == :remote

      {:error, _} ->
        false
    end
  end

  defp auth_context(state) do
    %{
      session_id: state.connection.session_id,
      queue_id: state.queue_id,
      ip: state.connection.remote_ip,
      helo: state.helo,
      sender: state.sender || "",
      recipients: state.expansions,
      inbound: inbound?(state),
      forwarded: Enum.any?(state.expansions, &remote?(&1, state)),
      spf: state.spf
    }
  end

  defp header_rewriting?(state),
    do: (state.trusted or state.identity != nil) and Rewrite.rewrites_headers?(state.routing)

  @impl true
  def handle_data_chunk(chunk, %{header: nil} = state) do
    with {:ok, state} <-
           write(%{state | auth_work: MailAuth.update(state.auth_work, chunk)}, chunk),
         do: milter_content(state, &Milters.body(&1, chunk))
  end

  def handle_data_chunk(chunk, state) do
    buffer = state.header <> IO.iodata_to_binary(chunk)

    case Headers.split(buffer) do
      {:ok, header, body} ->
        with {:ok, header, state} <- checked_header(header, state),
             state = %{state | header: nil, auth_work: MailAuth.update(state.auth_work, body)},
             {:ok, state} <- write(state, [header, "\r\n", body]),
             {:ok, state} <- milter_header(state) do
          milter_content(state, &Milters.body(&1, body))
        end

      :more when byte_size(buffer) > @max_header_section ->
        with {:ok, state} <- write(%{state | header: nil}, buffer),
             {:ok, state} <- milter_content(state, &Milters.header(&1, [], milter_info(state))),
             do: milter_content(state, &Milters.body(&1, buffer))

      :more ->
        {:ok, %{state | header: buffer}}
    end
  end

  defp milter_header(state) do
    fields = Headers.parse(state.received) ++ state.header_fields
    milter_content(state, &Milters.header(&1, fields, milter_info(state)))
  end

  # A milter that refuses the message ends it: the rest of the data is
  # discarded.
  defp milter_content(%{milters: nil} = state, _fun), do: {:ok, state}

  defp milter_content(state, fun) do
    case milters(state, fun) do
      {:ok, state} -> {:ok, state}
      {_reply_or_close, reply, state} -> {:reply, reply, abort(state)}
    end
  end

  defp write(state, data) do
    case Spool.write(state.writer, data) do
      {:ok, writer} ->
        {:ok, %{state | writer: writer}}

      {:error, reason} ->
        Spool.abort(state.writer)
        queue_error(%{state | writer: nil}, reason)
    end
  end

  # Refuses a looping message, fixes the header section if needed, and
  # plans the authentication checks.
  defp checked_header(header, state) do
    received = Headers.parse(header)

    if Trace.hops(received) > state.max_hops do
      {:reply, Reply.new(554, "5.4.6", "Too many hops"), abort(state)}
    else
      fields = fix_header(received, state)
      header = if fields == received, do: header, else: Headers.encode(fields)

      state = %{
        state
        | header_fields: fields,
          header_end: byte_size(state.received) + IO.iodata_length(header)
      }

      work =
        unless state.reinjection,
          do: MailAuth.start(state.mail_auth, received, fields, auth_context(state))

      {:ok, header, %{state | auth_work: work}}
    end
  end

  # Forged results for this server go; then the RFC 6409 §8.1-8.3 fixes,
  # and address rewriting.
  defp fix_header(fields, state) do
    fields = AuthResults.strip(fields, state.mail_auth.authserv_id)

    fields =
      if state.identity,
        do: submission_fixes(fields, state),
        else: fields

    if header_rewriting?(state),
      do: Rewrite.header_fields(state.routing, fields),
      else: fields
  end

  defp submission_fixes(fields, state) do
    fields = Headers.delete(fields, state.strip_headers)

    fields =
      if Headers.has?(fields, "date"),
        do: fields,
        else: Headers.append(fields, "Date", Date.format(DateTime.utc_now()))

    if Headers.has?(fields, "message-id"),
      do: fields,
      else: Headers.append(fields, "Message-ID", MessageID.generate(state.hostname))
  end

  @impl true
  def handle_data_end(transaction, %{header: header} = state) when is_binary(header) do
    # The message ended inside the header section: it has no body.
    header =
      if header == "" or String.ends_with?(header, "\r\n"), do: header, else: header <> "\r\n"

    with {:ok, header, state} <- checked_header(header, state),
         {:ok, state} <- write(%{state | header: nil}, header),
         {:ok, state} <- milter_header(state) do
      handle_data_end(transaction, state)
    end
  end

  def handle_data_end(_transaction, state) do
    {prefix, verdict} = MailAuth.finish(state.auth_work, auth_context(state))
    state = %{state | auth_work: nil, prefix: prefix}

    case verdict do
      {:reject, reply} ->
        finish({:reject, reply}, state)

      verdict ->
        action = if verdict == :accept, do: state.action, else: stronger(state.action, verdict)
        checks = Map.get(state.restrictions, :end_of_data, [])

        {restriction, effects} =
          Restrictions.check(checks, :end_of_data, restriction_context(state, []))

        state = add_effects(state, :end_of_data, effects)
        action = if restriction == :ok, do: action, else: stronger(action, restriction)
        {verdict, changes, milters} = Milters.end_of_message(state.milters, milter_info(state))
        state = %{state | milters: milters}

        case verdict do
          :ok -> apply_changes(action || state.session_action, changes, state)
          {:hold, _} = hold -> apply_changes(stronger(action, hold), changes, state)
          other -> finish(other, state)
        end
    end
  end

  # What policy servers and milters asked for: the message is written
  # again when its envelope or content changes.
  defp apply_changes({:reject, _} = action, _changes, state), do: finish(action, state)

  defp apply_changes(action, changes, state) do
    effects = state.session_effects ++ state.effects
    {envelope, size} = Spool.info(state.writer)
    changed = changed_envelope(envelope, effects, changes, state)
    content = changed_content(changes, size, state)
    prepend = for {:prepend, header} <- effects, do: [header, "\r\n"]
    state = %{state | prefix: [prepend | state.prefix]}

    cond do
      changed == envelope and content == nil ->
        finish(action, state)

      changed.recipients == [] ->
        finish({:discard, "no recipients left"}, state)

      true ->
        replace(action, changed, content, state)
    end
  end

  defp replace(action, changed, content, state) do
    case Spool.replace(state.writer, changed, content || [{:copy, 0, :all}]) do
      {:ok, writer} ->
        finish(action, %{state | writer: writer, expansions: changed.recipients})

      {:error, reason} ->
        queue_error(%{state | writer: nil}, reason)
    end
  end

  defp changed_envelope(envelope, effects, changes, state) do
    recipients =
      Enum.reduce(effects ++ changes, envelope.recipients, fn
        {:redirect, address}, _recipients ->
          expand_one(state, address)

        {:bcc, address}, recipients ->
          recipients ++ expand_one(state, address)

        {:add_recipient, address, _args}, recipients ->
          recipients ++ expand_one(state, address)

        {:delete_recipient, address}, recipients ->
          Enum.reject(recipients, &same_address?(&1, address))

        _other, recipients ->
          recipients
      end)
      |> Enum.uniq_by(&String.downcase/1)

    sender =
      Enum.reduce(changes, envelope.sender, fn
        {:change_sender, address, _args}, _sender -> address
        _other, sender -> sender
      end)

    filter =
      Enum.reduce(effects, envelope.content_filter, fn
        {:filter, spec}, filter -> if valid_filter?(spec), do: spec, else: filter
        _other, filter -> filter
      end)

    %{envelope | recipients: recipients, sender: sender, content_filter: filter}
  end

  defp expand_one(state, address) do
    case expand(state, address) do
      {:ok, finals} -> finals
      {:reject, _reply} -> [address]
    end
  end

  defp same_address?(a, b), do: String.downcase(a) == String.downcase(b)

  defp valid_filter?(spec) do
    if match?({:deliver, _}, Router.filter(spec)) do
      true
    else
      Logger.warning("ignoring invalid content filter #{inspect(spec)} from a policy server")
      false
    end
  end

  @header_changes [:add_header, :insert_header, :change_header, :delete_header]

  # The message put together again with the milters' changes, or nil when
  # there are none. Without the header fields (a header section too large
  # to hold back), there is nothing to change.
  defp changed_content(_changes, _size, %{header_fields: nil}), do: nil

  defp changed_content(changes, size, state) do
    header_changes = Enum.filter(changes, &(elem(&1, 0) in @header_changes))
    body = for {:replace_body, body} <- changes, do: body

    if header_changes == [] and body == [] do
      nil
    else
      fields = Headers.parse(state.received) ++ state.header_fields
      head = fields |> MilterHeaders.apply(header_changes) |> Headers.encode()

      case body do
        [] -> [{:data, head}, {:copy, state.header_end || size, :all}]
        body -> [{:data, head}, {:data, ["\r\n", List.last(body)]}]
      end
    end
  end

  defp finish({:reject, reply}, state) do
    state = abort(state)
    {:reply, reply, %{state | action: nil}}
  end

  defp finish({:discard, reason}, state) do
    queue_id = state.queue_id
    state = abort(state)
    message_event(:discarded, state, queue_id, reason)
    {:reply, Reply.new(250, "2.0.0", "Ok: discarded as #{queue_id}"), %{state | action: nil}}
  end

  defp finish(action, state) do
    case Spool.commit(state.writer, state.prefix) do
      {:ok, _path, _size} ->
        state = %{state | writer: nil, action: nil, prefix: []}
        Logger.metadata(queue_id: nil)
        Outbound.sent(state.screen.outbound, state.identity, length(state.expansions))
        release(action, state)
        {:reply, Reply.new(250, "2.0.0", "Ok: queued as #{state.queue_id}"), state}

      {:error, reason} ->
        queue_error(%{state | writer: nil}, reason)
    end
  end

  defp release({:hold, reason}, state) do
    case Spool.move(state.queue_directory, state.queue_id, :incoming, :hold) do
      :ok ->
        message_event(:held, state, state.queue_id, reason)

      {:error, error} ->
        Logger.error("cannot hold message: #{:file.format_error(error)}",
          queue_id: state.queue_id
        )

        notify(state)
    end
  end

  defp release(_action, state), do: notify(state)

  defp notify(state) do
    if state.queue_manager, do: QueueManager.notify(state.queue_manager, state.queue_id)
  end

  defp message_event(event, state, queue_id, reason) do
    :telemetry.execute([:sovite, :smtp, :message, event], %{}, %{
      session_id: state.connection.session_id,
      queue_id: queue_id,
      reason: reason
    })
  end

  @impl true
  def handle_data_abort(_reason, state), do: abort(state)

  @impl true
  def handle_rset(state), do: %{abort(state) | expansions: [], action: nil, effects: []}

  @impl true
  def handle_vrfy(argument, state) do
    address = argument |> String.trim_leading("<") |> String.trim_trailing(">")

    with {:local, normalized} <- classify(address, state),
         true <- state.local_recipients != nil do
      if MapSet.member?(state.local_recipients, normalized),
        do: {:reply, Reply.new(250, "2.1.5", "<#{address}>"), state},
        else: {:reply, Reply.new(550, "5.1.1", "<#{address}>: User unknown"), state}
    else
      _ -> {:ok, state}
    end
  end

  @impl true
  def terminate(_reason, state) do
    state = handle_auth_abort(state)
    state = abort(state)
    Milters.close(state.milters)
  end

  # The milters forget the transaction too.
  defp abort(%{writer: nil} = state),
    do: %{state | header: nil, auth_work: nil, prefix: [], milters: Milters.abort(state.milters)}

  defp abort(state) do
    Spool.abort(state.writer)
    Logger.metadata(queue_id: nil)

    %{
      state
      | writer: nil,
        header: nil,
        auth_work: nil,
        prefix: [],
        milters: Milters.abort(state.milters)
    }
  end

  defp queue_error(state, reason) do
    Logger.error("cannot write queue file: #{:file.format_error(reason)}")
    {:reply, Reply.new(451, "4.3.0", "Error: queue file write error"), state}
  end

  ## Recipient classification

  defp classify(recipient, state) do
    case Sovite.Validators.split_mailbox(recipient) do
      {:ok, {local_part, domain}} ->
        domain = String.downcase(domain, :ascii)
        class = Routing.class(state.routing, domain)
        postmaster = String.downcase(local_part, :ascii) in ["postmaster", "abuse"]

        cond do
          class in [:local, :aliased, :hosted] and postmaster -> :postmaster
          class == :local -> {:local, String.downcase(recipient, :ascii)}
          class == :remote -> :remote
          true -> class
        end

      # Only a bare "Postmaster" gets this far without a domain.
      {:error, _} ->
        if String.downcase(recipient, :ascii) == "postmaster", do: :postmaster, else: :remote
    end
  end

  defp queued_address(recipient, state) do
    if String.downcase(recipient, :ascii) == "postmaster",
      do: "postmaster@" <> state.hostname,
      else: recipient
  end
end
