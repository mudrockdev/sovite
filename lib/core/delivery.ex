defmodule Sovite.Core.Delivery do
  @moduledoc """
  Delivers one job (a message to a group of recipients with the same
  destination) over SMTP. Runs in a task started by
  `Sovite.Core.QueueManager`.

  For each job it:

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
    * `:dane` - DANE (RFC 7672): when the host has DNSSEC-authenticated
      TLSA records, TLS is required and the certificate must match them;
      otherwise as `:may`. A failed TLSA lookup skips the host.

  When TLS is required and fails, the address is skipped with `4.7.4`
  (not offered) or `4.7.5` (handshake or certificate failure). Relay
  hosts on port 465 get implicit TLS.

  When the destination has credentials (see `Sovite.Core.Router`), the
  client authenticates to the next hop, but only over TLS. With a source
  address for the address family, the connection is made from it.
  """

  alias Sovite.Core.Router
  alias Sovite.DNS.MX
  alias Sovite.Message.Received
  alias Sovite.Queue.{Record, Spool}
  alias Sovite.SMTP.{Client, Reply}
  alias Sovite.TLS
  alias Sovite.TLS.DANE

  @typedoc "Work for one delivery: built by the queue manager."
  @type job :: %{
          queue_id: String.t(),
          destination: Router.destination(),
          recipients: [String.t(), ...],
          sender: String.t(),
          body_type: :"7bit" | :"8bitmime" | nil,
          path: Path.t(),
          message_offset: non_neg_integer(),
          message_size: non_neg_integer()
        }

  @type result :: {String.t(), Record.status(), Record.details()}

  @typedoc """
  Worker options:

    * `:hostname` - this server's name, for `EHLO` and loop detection.
    * `:resolver` - a `Sovite.DNS` resolver.
    * `:port` - SMTP port for MX deliveries. 25 except in tests.
    * `:families` - `[:aaaa, :a]` and similar, see `Sovite.DNS.MX.resolve/3`.
    * `:max_addresses` - addresses to try per job.
    * `:client` - options for `Sovite.SMTP.Client.connect/3`.
    * `:tls` - `%{default, policy, cacerts}`: the default level, a map of
      destination (domain, relay host, or address literal) to level, and
      the CAs for `:verify` (`nil` for the system's).
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
          }
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

  defp deliver(job, {client, host}, opts) do
    case transaction(job, client, host) do
      # The cached connection went away; start over with a fresh one.
      {:retry, _error} -> deliver(job, nil, opts)
      {results, remote, connection} -> {results, remote, connection}
    end
  end

  defp deliver(job, nil, opts) do
    case addresses(job.destination, opts) do
      {:ok, addresses} ->
        try_addresses(job, Enum.take(addresses, opts.max_addresses), nil, opts)

      {:error, status, text} ->
        {all(job, status, text), nil, nil}
    end
  end

  defp try_addresses(job, [], last_error, _opts) do
    {status, text} = last_error || {"4.4.1", "No mail host could be reached"}
    {all(job, status, text), nil, nil}
  end

  defp try_addresses(job, [{host, ip, port} | rest], _last_error, opts) do
    remote = remote_name(host, ip)
    opts = %{opts | client: source_option(opts.client, job.destination, ip)}

    result =
      with {:ok, plan} <- tls_plan(job.destination.nexthop, host, port, opts),
           {:ok, client} <- open(ip, port, remote, plan, opts),
           {:ok, client} <- relay_auth(client, job.destination.auth, remote) do
        connected(job, client, remote, opts)
      end

    case result do
      {:retry, error} -> try_addresses(job, rest, error, opts)
      result -> result
    end
  end

  # Connect from the destination's source address for this family, if any.
  defp source_option(client, %{source: source}, ip) do
    family = if tuple_size(ip) == 4, do: :ipv4, else: :ipv6
    client = Keyword.delete(client, :local_address)

    case Map.fetch(source || %{}, family) do
      {:ok, local} -> Keyword.put(client, :local_address, local)
      :error -> client
    end
  end

  ## TLS

  defp tls_plan(destination, host, port, opts) do
    literal = String.starts_with?(host, "[")
    plan(tls_level(destination, opts.tls), host, literal, port, opts)
  end

  defp plan(:none, _host, _literal, _port, _opts), do: {:ok, :none}

  defp plan(:may, host, literal, _port, _opts),
    do: {:ok, {:may, TLS.client_options(hostname: sni(host, literal))}}

  defp plan(:encrypt, host, literal, _port, _opts),
    do: {:ok, {:required, "encrypt", TLS.client_options(hostname: sni(host, literal))}}

  defp plan(:verify, host, true, _port, _opts),
    do: {:retry, {"4.7.5", "cannot verify a certificate for address literal #{host}"}}

  defp plan(:verify, host, false, _port, opts) do
    cacerts = opts.tls.cacerts || :public_key.cacerts_get()

    {:ok,
     {:required, "verify", TLS.client_options(verify: :peer, hostname: host, cacerts: cacerts)}}
  end

  # DANE needs a host name to look up TLSA records for.
  defp plan(:dane, _host, true, _port, _opts), do: {:ok, {:may, TLS.client_options([])}}
  defp plan(:dane, host, false, port, opts), do: dane_plan(host, port, opts)

  defp sni(_host, true), do: nil
  defp sni(host, false), do: host

  defp tls_level(destination, tls) do
    key =
      case destination do
        {:mx, domain} -> domain
        {:host, %{host: host}} -> host
        {:literal, ip} -> Received.address_literal(ip)
      end

    Map.get(tls.policy, key, tls.default)
  end

  defp dane_plan(host, port, opts) do
    case Sovite.DNS.lookup_secure(opts.resolver, "_#{port}._tcp.#{host}", :tlsa) do
      {:ok, records, true} ->
        case DANE.usable(records) do
          [] -> {:ok, {:may, TLS.client_options(hostname: host)}}
          usable -> {:ok, {:required, "dane", DANE.client_options(usable, host)}}
        end

      {:ok, _records, false} ->
        {:ok, {:may, TLS.client_options(hostname: host)}}

      {:error, :nxdomain} ->
        {:ok, {:may, TLS.client_options(hostname: host)}}

      # RFC 7672 §2.2: a host whose TLSA lookup fails must not be used.
      {:error, reason} ->
        {:retry, {"4.7.5", "TLSA lookup for #{host} failed: #{reason}"}}
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

  defp transaction(job, client, remote) do
    body = Spool.stream_message(job.path, job.message_offset, job.message_size)
    opts = [size: job.message_size, body_type: job.body_type]

    case Client.deliver(client, job.sender, job.recipients, body, opts) do
      {:ok, client, replies} ->
        results =
          Enum.map(replies, fn {rcpt, stage, reply} ->
            reply_result(rcpt, stage, reply, remote)
          end)

        {results, remote, {client, remote}}

      {:error, client, refusal} ->
        {status, text} = refusal_error(refusal, remote)
        {all(job, status, text, remote), remote, {client, remote}}

      {:error, {:data_end, reason}} ->
        text =
          "lost connection with #{remote} while sending end of data (#{format_reason(reason)}); " <>
            "the message may be delivered more than once"

        {all(job, "4.4.2", text, remote), remote, nil}

      {:error, {stage, reason}} ->
        {:retry,
         {"4.4.2",
          "lost connection with #{remote} #{stage_text(stage)} (#{format_reason(reason)})"}}
    end
  end

  ## Addresses

  defp addresses(%{nexthop: nexthop}, opts), do: addresses(nexthop, opts)
  defp addresses({:mx, domain}, opts), do: mx_addresses(domain, opts.port, opts)

  defp addresses({:host, %{mx: true, host: host, port: port}}, opts),
    do: relay_errors(mx_addresses(host, port, opts), host)

  defp addresses({:host, %{mx: false, host: host, port: port}}, opts) do
    case MX.addresses(opts.resolver, host, opts.families) do
      {:ok, [_ | _] = ips} -> {:ok, Enum.map(ips, &{host, &1, port})}
      {:ok, []} -> {:error, "4.4.4", "relay host #{host} has no address"}
      {:error, reason} -> {:error, "4.4.3", "cannot resolve relay host #{host}: #{reason}"}
    end
  end

  defp addresses({:literal, ip}, opts),
    do: {:ok, [{Received.address_literal(ip), ip, opts.port}]}

  defp mx_addresses(domain, port, opts) do
    case MX.resolve(opts.resolver, domain, exclude: [opts.hostname], families: opts.families) do
      {:ok, hosts} ->
        {:ok, for({host, ips} <- hosts, ip <- ips, do: {host, ip, port})}

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

  ## Results

  defp reply_result(rcpt, stage, reply, remote) do
    status =
      cond do
        stage == :data_end and reply.code in 200..299 -> :delivered
        reply.code >= 500 -> :failed
        true -> :deferred
      end

    {rcpt, status, details(Reply.status(reply), Reply.to_string(reply), remote, true)}
  end

  defp all(job, status, text, remote \\ nil) do
    result = if String.starts_with?(status, "5"), do: :failed, else: :deferred
    details = details(status, text, remote, false)
    Enum.map(job.recipients, &{&1, result, details})
  end

  defp details(status, reply, remote, smtp),
    do: %{status: status, reply: reply, remote: remote, smtp: smtp, at: DateTime.utc_now()}

  defp refusal_error({:message_too_large, limit}, remote),
    do: {"5.3.4", "message size exceeds the limit of #{limit} bytes of #{remote}"}

  defp refusal_error(:eight_bit_not_supported, remote),
    do: {"5.6.3", "8-bit message, but #{remote} does not support 8BITMIME"}

  defp refusal_error({:invalid_address, address}, _remote),
    do: {"5.1.3", "invalid address #{inspect(address)}"}

  defp connect_error(remote, port, {:connect, reason}),
    do: {"4.4.1", "connect to #{remote}:#{port}: #{format_reason(reason)}"}

  defp connect_error(remote, _port, {:tls, {:tls, reason}}),
    do: {"4.7.5", "TLS with host #{remote} failed: #{TLS.format_error(reason)}"}

  defp connect_error(remote, _port, {stage, %Reply{} = reply})
       when stage in [:greeting, :ehlo, :helo],
       do: {"4.4.1", "host #{remote} refused to talk to me: #{Reply.to_string(reply)}"}

  defp connect_error(remote, _port, {stage, reason}),
    do:
      {"4.4.2", "lost connection with #{remote} #{stage_text(stage)} (#{format_reason(reason)})"}

  defp stage_text(:greeting), do: "while receiving the initial greeting"
  defp stage_text(:ehlo), do: "while sending EHLO"
  defp stage_text(:helo), do: "while sending HELO"
  defp stage_text(:mail), do: "while sending MAIL FROM"
  defp stage_text(:rcpt), do: "while sending RCPT TO"
  defp stage_text(:data), do: "while sending DATA"
  defp stage_text(:data_end), do: "while sending end of data"
  defp stage_text(:rset), do: "while sending RSET"
  defp stage_text(:starttls), do: "while sending STARTTLS"
  defp stage_text(:auth), do: "while authenticating"
  defp stage_text(stage), do: "at #{stage}"

  defp format_reason(:timeout), do: "timeout"
  defp format_reason(:closed), do: "connection closed"
  defp format_reason(:econnrefused), do: "Connection refused"

  defp format_reason(reason) when is_atom(reason),
    do: reason |> :inet.format_error() |> to_string()

  defp format_reason(reason), do: inspect(reason)

  defp remote_name(host, ip) do
    literal = Received.address_literal(ip)
    if host == literal, do: literal, else: host <> literal
  end
end
