defmodule Sovite.Core.SMTPHandler do
  @moduledoc """
  The MTA's `Sovite.SMTP.Server.Handler`: relay control, authentication,
  recipient checks, and durable spooling.

  Recipients are checked at `RCPT` time:

  1. `<Postmaster>`, and `postmaster@` and `abuse@` any local domain, are
     always accepted (RFC 5321 §4.5.1, RFC 2142), even when
     `domains.local_recipients` does not list them. A bare `<Postmaster>`
     is queued as `postmaster@<server.hostname>`.
  2. Local domains (`domains.local`): accepted if `domains.local_recipients`
     is unset or lists the address, otherwise `550 5.1.1`.
  3. Relay domains (`domains.relay`): accepted.
  4. Any other destination, including address literals: accepted only from
     `smtp.trusted_networks` or after `AUTH`, otherwise `554 5.7.1 Relay
     access denied`. The default config trusts no one, so it is never an
     open relay.

  Domains are compared case-insensitively. Address tricks such as
  `user%remote@local` or source routes do not relay: only the domain of
  the parsed mailbox counts.

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

  The message is accepted with `250` only after `Sovite.Queue.Spool`
  has made it durable. A `Received:` header is added at the top. The
  queue manager given as `:queue_manager` is then told about it.
  """

  @behaviour Sovite.SMTP.Server.Handler

  require Logger

  alias Sovite.Abuse.Penalty
  alias Sovite.Core.{Config, Logging, QueueManager, SenderCheck, Users}
  alias Sovite.Message.{Date, Headers, MessageID, Received}
  alias Sovite.Net
  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.SASL
  alias Sovite.SMTP.Reply

  # Header sections larger than this are passed through unchanged.
  @max_header_section 1024 * 1024

  @doc """
  Handler options from the running configuration.

    * `queue_manager` - the `Sovite.Core.QueueManager` to notify about new
      messages, if any.
    * `runtime` - `:repo` (a `Sovite.Core.Repo` reference), `:penalty`
      (the name of the `Sovite.Abuse.Penalty` for failed logins), and
      `:require_auth` (the listener requires authentication).
  """
  @spec opts(Config.t(), GenServer.server() | nil, keyword()) :: map()
  def opts(config, queue_manager \\ nil, runtime \\ []) do
    repo = runtime[:repo]

    %{
      queue_manager: queue_manager,
      hostname: config.server.hostname,
      queue_directory: config.queue.directory,
      local_domains: MapSet.new(config.domains.local),
      relay_domains: MapSet.new(config.domains.relay),
      local_recipients:
        config.domains.local_recipients && MapSet.new(config.domains.local_recipients),
      trusted_networks: config.smtp.trusted_networks,
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
      strip_headers: config.submission.strip_headers
    }
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
        writer: nil,
        queue_id: nil,
        header: nil
      })

    if opts.require_auth and banned?(state),
      do:
        {:close,
         Reply.new(
           421,
           "4.7.0",
           "#{opts.hostname} Too many failed logins from your address, try again later"
         ), state},
      else: {:ok, state}
  end

  @impl true
  def handle_helo(kind, name, state), do: {:ok, %{state | helo: name, esmtp: kind == :ehlo}}

  @impl true
  def handle_tls(info, state), do: %{state | tls: info, helo: nil, esmtp: false}

  @impl true
  def handle_mail(sender, _params, %{identity: identity, sender_check: true} = state)
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

  def handle_mail(_sender, _params, state), do: {:ok, state}

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

  @impl true
  def handle_rcpt(recipient, state) do
    case classify(recipient, state) do
      :postmaster -> {:ok, state}
      {:local, address} -> check_local(address, recipient, state)
      :relay -> {:ok, state}
      :remote when state.trusted or state.identity != nil -> {:ok, state}
      :remote -> {:reply, Reply.new(554, "5.7.1", "<#{recipient}>: Relay access denied"), state}
    end
  end

  defp check_local(address, recipient, state) do
    if state.local_recipients == nil or MapSet.member?(state.local_recipients, address),
      do: {:ok, state},
      else:
        {:reply,
         Reply.new(550, "5.1.1", "<#{recipient}>: Recipient address rejected: User unknown"),
         state}
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
    queue_id = ID.generate()
    recipients = transaction.recipients |> Enum.map(&queued_address(&1, state)) |> Enum.uniq()
    received_at = DateTime.utc_now()

    protocol =
      Received.protocol(esmtp: state.esmtp, tls: state.tls != nil, auth: state.identity != nil)

    envelope = %Envelope{
      queue_id: queue_id,
      sender: transaction.sender,
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
        for: if(match?([_], recipients), do: hd(recipients)),
        date: received_at,
        tls: state.tls && Sovite.TLS.describe(state.tls)
      })

    with {:ok, writer} <- Spool.open(state.queue_directory, envelope),
         {:ok, writer} <- Spool.write(writer, received) do
      Logger.metadata(queue_id: queue_id)
      # Submitted messages get their header section fixed, so hold it back.
      header = if state.identity, do: ""
      {:ok, %{state | writer: writer, queue_id: queue_id, header: header}}
    else
      {:error, reason} -> queue_error(state, reason)
    end
  end

  @impl true
  def handle_data_chunk(chunk, %{header: nil} = state), do: write(state, chunk)

  def handle_data_chunk(chunk, state) do
    buffer = state.header <> IO.iodata_to_binary(chunk)

    case Headers.split(buffer) do
      {:ok, header, body} ->
        write(%{state | header: nil}, [fix_header(header, state), "\r\n", body])

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

  # RFC 6409 §8.1-8.3.
  defp fix_header(header, state) do
    fields = header |> Headers.parse() |> Headers.delete(state.strip_headers)

    fields =
      if Headers.has?(fields, "date"),
        do: fields,
        else: Headers.append(fields, "Date", Date.format(DateTime.utc_now()))

    fields =
      if Headers.has?(fields, "message-id"),
        do: fields,
        else: Headers.append(fields, "Message-ID", MessageID.generate(state.hostname))

    Headers.encode(fields)
  end

  @impl true
  def handle_data_end(transaction, %{header: header} = state) when is_binary(header) do
    # The message ended inside the header section: it has no body.
    header =
      if header == "" or String.ends_with?(header, "\r\n"), do: header, else: header <> "\r\n"

    case write(%{state | header: nil}, fix_header(header, state)) do
      {:ok, state} -> handle_data_end(transaction, state)
      error -> error
    end
  end

  def handle_data_end(_transaction, state) do
    case Spool.commit(state.writer) do
      {:ok, _path, _size} ->
        state = %{state | writer: nil}
        Logger.metadata(queue_id: nil)
        if state.queue_manager, do: QueueManager.notify(state.queue_manager, state.queue_id)
        {:reply, Reply.new(250, "2.0.0", "Ok: queued as #{state.queue_id}"), state}

      {:error, reason} ->
        queue_error(%{state | writer: nil}, reason)
    end
  end

  @impl true
  def handle_data_abort(_reason, state), do: abort(state)

  @impl true
  def handle_rset(state), do: abort(state)

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

  defp abort(%{writer: nil} = state), do: %{state | header: nil}

  defp abort(state) do
    Spool.abort(state.writer)
    Logger.metadata(queue_id: nil)
    %{state | writer: nil, header: nil}
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
        local = MapSet.member?(state.local_domains, domain)

        cond do
          local and String.downcase(local_part, :ascii) in ["postmaster", "abuse"] -> :postmaster
          local -> {:local, String.downcase(recipient, :ascii)}
          MapSet.member?(state.relay_domains, domain) -> :relay
          true -> :remote
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
