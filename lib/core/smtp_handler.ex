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

  The restriction chains (`Sovite.Core.Restrictions`) run at connect,
  `EHLO`, `MAIL`, `RCPT`, `DATA`, and at the end of the data, after the
  built-in checks of each stage; they can reject, but never permit what
  relay control or recipient validation refuses.

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

  ## Loops

  A message with more than `smtp.max_hops` `Received:` fields is refused
  at the end of the data with `554 5.4.6` (RFC 5321 §6.3): it is most
  likely going round in circles.

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

  alias Sovite.Abuse.Penalty

  alias Sovite.Core.{
    Config,
    Logging,
    MailAuth,
    QueueManager,
    Recipients,
    Restrictions,
    Rewrite,
    Routing,
    SenderCheck
  }

  alias Sovite.Core.Repo.Tables.{AccessRules, Users}

  alias Sovite.{AuthResults, SASL, SRS}
  alias Sovite.Message.{Date, Headers, MessageID, Received, Trace}
  alias Sovite.Net
  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.SMTP.Reply

  # Header sections larger than this are passed through unchanged.
  @max_header_section 1024 * 1024

  @doc """
  Handler options from the running configuration.

    * `queue_manager` - the `Sovite.Core.QueueManager` to notify about new
      messages, if any.
    * `runtime` - `:repo` (a `Sovite.Core.Repo` reference), `:penalty`
      (the name of the `Sovite.Abuse.Penalty` for failed logins),
      `:require_auth` (the listener requires authentication), and
      `:resolver` (for restrictions that look up domains).
  """
  @spec opts(Config.t(), GenServer.server() | nil, keyword()) :: map()
  def opts(config, queue_manager \\ nil, runtime \\ []) do
    repo = runtime[:repo]
    resolver = Keyword.get_lazy(runtime, :resolver, &Sovite.DNS.default_resolver/0)

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
      srs: config.srs
    }
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
        identity: nil,
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
        prefix: []
      })

    if opts.require_auth and banned?(state) do
      {:close,
       Reply.new(
         421,
         "4.7.0",
         "#{opts.hostname} Too many failed logins from your address, try again later"
       ), state}
    else
      case restrict(state, :connect) do
        {:ok, state} -> {:ok, %{state | session_action: state.action, action: nil}}
        {:reply, reply, state} -> {:close, reply, state}
      end
    end
  end

  @impl true
  def handle_helo(kind, name, state) do
    state = %{state | helo: name, esmtp: kind != :helo, lmtp: kind == :lhlo}

    case restrict(state, :helo) do
      {:ok, state} ->
        {:ok, %{state | session_action: state.action || state.session_action, action: nil}}

      reply ->
        reply
    end
  end

  @impl true
  def handle_tls(info, state), do: %{state | tls: info, helo: nil, esmtp: false}

  @impl true
  def handle_mail(sender, _params, state) do
    state = %{state | sender: sender, envelope_sender: nil, expansions: [], action: nil, spf: nil}

    with {:ok, state} <- check_sender(sender, state),
         {:ok, state} <- restrict(state, :mail),
         {:ok, state} <- check_spf(sender, state) do
      rewrite_sender(sender, state)
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
  # LMTP the client is the MTA that already checked the mail.
  defp inbound?(state), do: not state.trusted and state.identity == nil and not state.lmtp

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
      case Restrictions.run(checks, stage, restriction_context(state, extra)) do
        :ok -> {:ok, state}
        {:reject, reply} -> {:reply, reply, state}
        action -> {:ok, %{state | action: stronger(state.action, action)}}
      end
    end
  end

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
        delimiter: state.routing.delimiter
      },
      Map.new(extra)
    )
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
  # IPv6 clients usually control a whole /64, so count failures per /64.
  def penalty_key({a, b, c, d, _, _, _, _}), do: {a, b, c, d, 0, 0, 0, 0}
  def penalty_key(ip), do: ip

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
         {:ok, recipients} <- envelope_recipients(state) do
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
    queue_id = ID.generate()
    received_at = DateTime.utc_now()

    protocol =
      Received.protocol(
        lmtp: state.lmtp,
        esmtp: state.esmtp,
        tls: state.tls != nil,
        auth: state.identity != nil
      )

    sender = state.envelope_sender || transaction.sender

    envelope = %Envelope{
      queue_id: queue_id,
      sender: sender,
      srs_sender: srs_sender(sender, recipients, state),
      recipients: recipients,
      received_at: received_at,
      session_id: state.connection.session_id,
      remote_ip: state.connection.remote_ip,
      helo: state.helo,
      protocol: protocol,
      body_type: transaction.params.body
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
      {:ok, %{state | writer: writer, queue_id: queue_id, header: ""}}
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
  def handle_data_chunk(chunk, %{header: nil} = state),
    do: write(%{state | auth_work: MailAuth.update(state.auth_work, chunk)}, chunk)

  def handle_data_chunk(chunk, state) do
    buffer = state.header <> IO.iodata_to_binary(chunk)

    case Headers.split(buffer) do
      {:ok, header, body} ->
        with {:ok, header, state} <- checked_header(header, state) do
          state = %{state | header: nil, auth_work: MailAuth.update(state.auth_work, body)}
          write(state, [header, "\r\n", body])
        end

      :more when byte_size(buffer) > @max_header_section ->
        write(%{state | header: nil}, buffer)

      :more ->
        {:ok, %{state | header: buffer}}
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
      work = MailAuth.start(state.mail_auth, received, fields, auth_context(state))
      header = if fields == received, do: header, else: Headers.encode(fields)
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
         do: handle_data_end(transaction, state)
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

        action =
          case Restrictions.run(checks, :end_of_data, restriction_context(state, [])) do
            :ok -> action
            restriction -> stronger(action, restriction)
          end

        finish(action || state.session_action, state)
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
  def handle_rset(state), do: %{abort(state) | expansions: [], action: nil}

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
    abort(state)
  end

  defp abort(%{writer: nil} = state), do: %{state | header: nil, auth_work: nil, prefix: []}

  defp abort(state) do
    Spool.abort(state.writer)
    Logger.metadata(queue_id: nil)
    %{state | writer: nil, header: nil, auth_work: nil, prefix: []}
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
