defmodule Sovite.Core.Delivery do
  @moduledoc """
  Delivers one job (a message to a group of recipients with the same
  destination). Runs in a task started by `Sovite.Core.QueueManager`.

  The destination's transport (see `Sovite.Core.Router`) decides how:

    * `:smtp` - to another server, described below.
    * `:lmtp` - to a mailbox server such as Dovecot over LMTP
      (RFC 2033), on a Unix socket or a host. Each recipient gets its
      own status code after the data. LMTP connections are reused like
      SMTP ones.
    * `:local` and `:mailbox` - into a Maildir folder, from the
      `maildir.local` or `maildir.mailbox` template.
    * `:pipe` - to the command of a `[pipe.<name>]` config section, once
      per recipient, through `Sovite.Pipe`.

  These four are final deliveries. A recipient that a `Delivered-To:`
  field of the message already names is a mail loop and fails with
  `5.4.6` (RFC 9228). Maildir and pipe deliveries get `Return-Path:` and
  `Delivered-To:` fields at the top (RFC 5321 §4.4); an LMTP server adds
  its own.

  ## SMTP

  For each SMTP job it:

    1. Finds the destination's addresses: MX hosts in preference order
       (`Sovite.DNS.MX`), then each host's addresses in the configured IP
       version order, at most `delivery.max_addresses` in total.
    2. Tries them in turn until one accepts a connection and completes
       the `EHLO`. A failure to connect, a rejected greeting, or a
       connection lost before the end of the data moves on to the next
       address (RFC 5321 §4.5.4.1).
    3. Runs the transaction and turns each recipient's reply into a
       result: 2xx delivered, 4xx deferred, 5xx failed.

  A connection that ends in a clean state is handed back with the result,
  and the queue manager may give the worker another job for the same
  destination to send over it.

  A server that greets with this server's own host name is a mail loop,
  and the job fails with `5.4.6`.

  ## TLS

  Each destination has a TLS level, from `delivery.tls_policy` or else
  `delivery.tls`:

    * `:none` - never use TLS.
    * `:may` - opportunistic TLS (RFC 7435): `STARTTLS` when offered,
      without checking the certificate. If the handshake fails, the
      address is tried again without TLS.
    * `:encrypt` - TLS is required; the certificate is not checked.
    * `:verify` - TLS is required, and the certificate must be valid for
      the MX (or relay) host name, from a trusted CA.
    * `:dane` (the default) - DANE (RFC 7672): when DNSSEC authenticated
      the host's MX and address records and it has TLSA records, TLS is
      required and the certificate must match them; otherwise as `:may`.
      A failed TLSA lookup skips the host.

  With `:may` and `:dane`, mail to a domain's MX hosts also follows the
  domain's MTA-STS policy (RFC 8461, see `Sovite.Core.MTASTS`), for
  hosts where DANE does not apply: DANE wins (RFC 8461 §2). In
  `enforce` mode, only MX hosts the policy lists are used, with TLS and
  a certificate valid for the host name from a trusted CA. In `testing`
  mode, delivery is opportunistic and problems are only reported.

  When TLS is required and fails, the address is skipped with `4.7.4`
  (not offered) or `4.7.5` (handshake or certificate failure). Relay
  hosts on port 465 get implicit TLS.

  A message received with `REQUIRETLS` (RFC 8689) is only sent over TLS
  verified with DANE or an MTA-STS policy (testing mode counts as
  enforce), or for relay hosts with a trusted certificate, and only to
  servers that offer `REQUIRETLS`; otherwise it fails with `5.7.30`. A
  message with `TLS-Required: No` ignores the DANE and MTA-STS policies.

  With `tls_rpt.reports`, each session to an MX host is recorded for
  TLS-RPT (RFC 8460): the policy that applied and whether TLS worked.

  When the destination has credentials (see `Sovite.Core.Router`), the
  client authenticates to the next hop, but only over TLS. With a source
  address for the address family, the connection is made from it.
  """

  import Sovite.Core.Delivery.Transaction,
    only: [
      all: 3,
      all: 4,
      connect_error: 3,
      details: 4,
      format_reason: 1,
      remote_name: 2,
      stage_text: 1,
      transaction: 3
    ]

  alias Sovite.Core.Delivery.{LMTP, Local, TLSPolicy}
  alias Sovite.Core.Router
  alias Sovite.DNS.MX
  alias Sovite.Message.{Headers, Received, Trace}
  alias Sovite.Queue.{Record, Spool}
  alias Sovite.SMTP.{Client, Reply}
  alias Sovite.TLS

  @typedoc "Work for one delivery: built by the queue manager."
  @type job :: %{
          queue_id: String.t(),
          destination: Router.destination(),
          recipients: [String.t(), ...],
          sender: String.t(),
          body_type: :"7bit" | :"8bitmime" | nil,
          path: Path.t(),
          message_offset: non_neg_integer(),
          message_size: non_neg_integer(),
          prefix: binary(),
          requiretls: boolean()
        }

  @type result :: {String.t(), Record.status(), Record.details()}

  @typedoc """
  Worker options:

    * `:maildir` - `%{local: template, mailbox: template}`, Maildir path
      templates with `{user}`, `{domain}`, and `{address}`, or `nil`.
    * `:pipes` - pipe commands by name, from the `[pipe]` config section.
    * `:delimiter` - the address extension delimiter.
    * `:tmp_dir` - where pipe deliveries write the message for the
      command to read.

    * `:hostname` - this server's name, for `EHLO` and loop detection.
    * `:resolver` - a `Sovite.DNS` resolver.
    * `:port` - SMTP port for MX deliveries. 25 except in tests.
    * `:families` - `[:aaaa, :a]` and similar, see `Sovite.DNS.MX.resolve/3`.
    * `:max_addresses` - addresses to try per job.
    * `:client` - options for `Sovite.SMTP.Client.connect/3`.
    * `:tls` - `%{default, policy, cacerts}`: the default level, a map of
      destination (domain, relay host, or address literal) to level, and
      the CAs for `:verify` (`nil` for the system's).
    * `:mta_sts` - the `Sovite.Core.MTASTS` server, or `nil` to ignore
      MTA-STS policies.
    * `:tls_reports` - the `Sovite.Core.Repo` reference to record TLS-RPT
      outcomes in, or `nil`.
  """
  @type opts :: %{
          hostname: String.t(),
          resolver: Sovite.DNS.resolver(),
          port: :inet.port_number(),
          families: [:a | :aaaa, ...],
          max_addresses: pos_integer(),
          client: keyword(),
          tls: %{
            default: tls_level(),
            policy: %{String.t() => tls_level()},
            cacerts: [binary()] | nil
          },
          maildir: %{optional(:local | :mailbox) => String.t() | nil},
          pipes: %{String.t() => map()},
          delimiter: String.t(),
          tmp_dir: Path.t(),
          mta_sts: GenServer.server() | nil,
          tls_reports: Sovite.Core.Repo.t() | nil
        }

  @type tls_level :: :none | :may | :encrypt | :verify | :dane

  @typedoc "An open connection and the host it goes to, for reuse."
  @type connection :: {Client.t(), String.t()}

  @doc """
  Runs `job`, reusing `connection` if given. Returns one result per
  recipient and the connection, if it can carry another message.
  """
  @spec run(job(), connection() | nil, opts()) :: {[result()], connection() | nil}
  def run(job, connection, opts) do
    started = System.monotonic_time()
    relay = Router.name(job.destination)

    :telemetry.execute(
      [:sovite, :smtp, :client, :delivery, :start],
      %{system_time: System.system_time()},
      %{queue_id: job.queue_id, relay: relay}
    )

    {results, remote, connection} = deliver(job, connection, opts)
    duration = System.monotonic_time() - started

    tls =
      with {client, _host} <- connection, %{} = info <- Client.tls(client), do: TLS.describe(info)

    for {recipient, status, details} <- results do
      :telemetry.execute(
        [:sovite, :smtp, :client, :delivery, :stop],
        %{duration: duration},
        %{
          queue_id: job.queue_id,
          relay: remote || relay,
          recipient: recipient,
          status: status,
          reply: details.reply,
          tls: tls
        }
      )
    end

    {results, connection}
  end

  defp deliver(%{destination: %{transport: :smtp}} = job, connection, opts),
    do: smtp(job, connection, opts)

  defp deliver(job, connection, opts) do
    case loops(job) do
      {:ok, []} ->
        final(job, connection, opts)

      {:ok, looping} ->
        failed = details("5.4.6", "mail forwarding loop", nil, false)

        results =
          Enum.map(looping, &{&1, :failed, %{failed | reply: "mail forwarding loop for #{&1}"}})

        case job.recipients -- looping do
          [] ->
            {results, nil, connection}

          rest ->
            {more, remote, connection} = final(%{job | recipients: rest}, connection, opts)
            {results ++ more, remote, connection}
        end

      {:error, reason} ->
        text = "cannot read queue file: #{:file.format_error(reason)}"
        {all(job, "4.3.0", text), nil, connection}
    end
  end

  defp final(%{destination: %{transport: :lmtp}} = job, connection, opts),
    do: LMTP.deliver(job, connection, opts)

  defp final(job, _connection, opts), do: {Local.deliver(job, opts), nil, nil}

  # Recipients that a Delivered-To: field already names.
  defp loops(job) do
    with {:ok, header} <-
           Spool.read_headers(job.path, job.message_offset, job.message_size, prefix: job.prefix) do
      fields = Headers.parse(header)
      {:ok, Enum.filter(job.recipients, &Trace.delivered_to?(fields, &1))}
    end
  end

  # A REQUIRETLS message needs a connection verified for it.
  defp smtp(%{requiretls: true} = job, {client, _host}, opts) do
    Client.quit(client)
    smtp(job, nil, opts)
  end

  defp smtp(job, {client, host}, opts) do
    case transaction(job, client, host) do
      # The cached connection went away; start over with a fresh one.
      {:retry, _error} -> smtp(job, nil, opts)
      {results, remote, connection} -> {results, remote, connection}
    end
  end

  defp smtp(job, nil, opts) do
    ctx = TLSPolicy.context(job, opts)

    case addresses(job.destination, ctx.dnssec, opts) do
      {:ok, addresses} ->
        job
        |> try_addresses(Enum.take(addresses, opts.max_addresses), nil, ctx, opts)
        |> keep_connection(ctx)

      {:error, status, text} ->
        {all(job, status, text), nil, nil}
    end
  end

  # A connection made while ignoring the TLS policies must not carry
  # other messages.
  defp keep_connection({results, remote, {client, _host}}, %{tls_optional: true}) do
    Client.quit(client)
    {results, remote, nil}
  end

  defp keep_connection(result, _job), do: result

  defp try_addresses(job, [], last_error, _ctx, _opts) do
    {status, text} = last_error || {"4.4.1", "No mail host could be reached"}
    {all(job, status, text), nil, nil}
  end

  defp try_addresses(job, [{host, ip, port, secure} | rest], _last_error, ctx, opts) do
    remote = remote_name(host, ip)
    opts = %{opts | client: source_option(opts.client, job.destination, ip)}

    result =
      case TLSPolicy.plan(ctx, host, port, secure, opts) do
        {:ok, plan, report} ->
          opened = open(ip, port, remote, plan, opts)
          TLSPolicy.record(ctx, report, plan, {host, ip}, opened, opts)

          with {:ok, client} <- opened,
               {:ok, client} <- relay_auth(client, job.destination.auth, remote),
               {:ok, client} <- requiretls(job, client, remote) do
            connected(job, client, remote, opts)
          end

        {:retry, error, report} ->
          TLSPolicy.record(ctx, report, nil, {host, ip}, {:retry, error}, opts)
          {:retry, error}
      end

    case result do
      {:retry, error} -> try_addresses(job, rest, error, ctx, opts)
      result -> result
    end
  end

  # RFC 8689 §4.2.1: the next server must support REQUIRETLS too.
  defp requiretls(%{requiretls: true}, client, remote) do
    if Map.has_key?(Client.extensions(client), "REQUIRETLS") do
      {:ok, client}
    else
      Client.quit(client)
      {:retry, {"5.7.30", "REQUIRETLS support required, but host #{remote} does not offer it"}}
    end
  end

  defp requiretls(_job, client, _remote), do: {:ok, client}

  # Connect from the destination's source address for this family, if any.
  defp source_option(client, %{source: source}, ip) do
    family = if tuple_size(ip) == 4, do: :ipv4, else: :ipv6
    client = Keyword.delete(client, :local_address)

    case Map.fetch(source || %{}, family) do
      {:ok, local} -> Keyword.put(client, :local_address, local)
      :error -> client
    end
  end

  # Port 465 is implicit TLS (RFC 8314); elsewhere STARTTLS per plan.
  defp open(ip, 465, remote, plan, opts) do
    ssl =
      case plan do
        {_kind, _label, ssl} -> ssl
        {:may, ssl} -> ssl
        :none -> TLS.client_options([])
      end

    case Client.connect(ip, 465, Keyword.put(opts.client, :tls, ssl)) do
      {:ok, client} -> {:ok, client}
      {:error, error} -> {:retry, connect_error(remote, 465, error)}
    end
  end

  defp open(ip, port, remote, plan, opts) do
    case Client.connect(ip, port, opts.client) do
      {:ok, client} -> starttls(client, plan, {ip, port, remote}, opts)
      {:error, error} -> {:retry, connect_error(remote, port, error)}
    end
  end

  defp starttls(client, :none, _address, _opts), do: {:ok, client}

  defp starttls(client, {:may, ssl}, {ip, port, remote}, opts) do
    case Client.starttls(client, ssl) do
      {:ok, client} ->
        {:ok, client}

      {:error, client, _not_offered_or_refused} ->
        {:ok, client}

      # Opportunistic TLS must not make delivery fail: try again in
      # plaintext. With TLS 1.3 a rejected handshake can also surface at
      # the EHLO that follows it.
      {:error, {_stage, _reason}} ->
        open(ip, port, remote, :none, opts)
    end
  end

  defp starttls(client, {:required, label, ssl}, {_ip, _port, remote}, _opts) do
    case Client.starttls(client, ssl) do
      {:ok, client} ->
        {:ok, client}

      {:error, client, :not_offered} ->
        Client.quit(client)
        {:retry, {"4.7.4", "TLS is required, but was not offered by host #{remote}"}}

      {:error, client, {:refused, reply}} ->
        Client.quit(client)

        {:retry,
         {"4.7.4",
          "TLS is required, but host #{remote} refused to start TLS: #{Reply.to_string(reply)}"}}

      {:error, {:starttls, {:tls, reason}}} ->
        {:retry,
         {"4.7.5", "TLS (#{label}) with host #{remote} failed: #{TLS.format_error(reason)}"}}

      {:error, {stage, reason}} ->
        {:retry,
         {"4.4.2",
          "lost connection with #{remote} #{stage_text(stage)} (#{format_reason(reason)})"}}
    end
  end

  defp relay_auth(client, nil, _remote), do: {:ok, client}

  defp relay_auth(client, credentials, remote) do
    if Client.tls(client) == nil do
      Client.quit(client)
      {:retry, {"4.7.0", "will not send credentials to #{remote} without TLS"}}
    else
      case Client.authenticate(client, credentials) do
        {:ok, client} ->
          {:ok, client}

        {:error, client, reason} ->
          Client.quit(client)
          {:retry, {"4.7.8", "authentication failed at #{remote}: #{auth_error(reason)}"}}

        {:error, {stage, reason}} ->
          {:retry,
           {"4.4.2",
            "lost connection with #{remote} #{stage_text(stage)} (#{format_reason(reason)})"}}
      end
    end
  end

  defp auth_error({:rejected, reply}), do: Reply.to_string(reply)
  defp auth_error(:no_mechanism), do: "no supported mechanism offered"
  defp auth_error({:sasl, reason}), do: inspect(reason)

  defp connected(job, client, remote, opts) do
    if loop?(client, opts.hostname) do
      Client.quit(client)
      text = "mail for #{Router.name(job.destination)} loops back to myself"
      {all(job, "5.4.6", text, remote), remote, nil}
    else
      transaction(job, client, remote)
    end
  end

  defp loop?(client, hostname) do
    name = Client.server_name(client)
    is_binary(name) and String.downcase(name, :ascii) == String.downcase(hostname, :ascii)
  end

  ## Addresses

  # {host, ip, port, secure}: secure when DNSSEC authenticated the host's
  # MX and address records, so DANE may apply.
  defp addresses(%{nexthop: nexthop}, dnssec, opts), do: addresses(nexthop, dnssec, opts)
  defp addresses({:mx, domain}, dnssec, opts), do: mx_addresses(domain, opts.port, dnssec, opts)

  defp addresses({:host, %{mx: true, host: host, port: port}}, dnssec, opts),
    do: relay_errors(mx_addresses(host, port, dnssec, opts), host)

  defp addresses({:host, %{mx: false, host: host, port: port}}, dnssec, opts) do
    result =
      if dnssec,
        do: MX.secure_addresses(opts.resolver, host, opts.families),
        else:
          with(
            {:ok, ips} <- MX.addresses(opts.resolver, host, opts.families),
            do: {:ok, ips, false}
          )

    case result do
      {:ok, [_ | _] = ips, secure} -> {:ok, Enum.map(ips, &{host, &1, port, secure})}
      {:ok, [], _} -> {:error, "4.4.4", "relay host #{host} has no address"}
      {:error, reason} -> {:error, "4.4.3", "cannot resolve relay host #{host}: #{reason}"}
    end
  end

  defp addresses({:literal, ip}, _dnssec, opts),
    do: {:ok, [{Received.address_literal(ip), ip, opts.port, false}]}

  defp mx_addresses(domain, port, dnssec, opts) do
    resolved =
      MX.resolve_secure(opts.resolver, domain,
        exclude: [opts.hostname],
        families: opts.families,
        dnssec: dnssec
      )

    case resolved do
      {:ok, hosts} ->
        {:ok, for({host, ips, secure} <- hosts, ip <- ips, do: {host, ip, port, secure})}

      {:error, :null_mx} ->
        {:error, "5.1.10", "domain #{domain} does not accept mail (null MX)"}

      {:error, :nxdomain} ->
        {:error, "5.1.2", "Host or domain name not found: #{domain}"}

      {:error, :no_hosts} ->
        {:error, "5.4.4", "domain #{domain} has no mail host"}

      {:error, :no_addresses} ->
        {:error, "5.4.4", "no mail host for #{domain} has an address"}

      {:error, :loops_back} ->
        {:error, "5.4.6", "mail for #{domain} loops back to myself"}

      {:error, {:temporary, reason}} ->
        {:error, "4.4.3", "Host or domain name lookup failed for #{domain}: #{reason}"}
    end
  end

  # A broken relay host is a configuration problem: keep the mail.
  defp relay_errors({:error, <<"5", rest::binary>>, text}, host),
    do: {:error, "4" <> rest, "relay host #{host}: #{text}"}

  defp relay_errors(result, _host), do: result
end
