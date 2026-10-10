defmodule Sovite.Core.Delivery.TLSPolicy do
  @moduledoc false
  # How an SMTP delivery uses TLS, for Sovite.Core.Delivery: the
  # configured level, the recipient domain's DANE and MTA-STS policies,
  # REQUIRETLS and TLS-Required: No (RFC 8689), and the TLS-RPT record
  # of each session (RFC 8460).

  alias Sovite.Core.MTASTS
  alias Sovite.Core.Repo.Tables.TLSReportEntries
  alias Sovite.Message.{Headers, Received}
  alias Sovite.Queue.Spool
  alias Sovite.SMTP.Client
  alias Sovite.TLS
  alias Sovite.TLS.{DANE, MTASTS.Policy}

  @typedoc """
  How to connect: no TLS, opportunistic TLS, or required TLS with a
  label for errors.
  """
  @type plan :: :none | {:may, keyword()} | {:required, String.t(), keyword()}

  @typedoc "What a session is reported as, for TLS-RPT."
  @type report :: %{
          type: :tlsa | :sts | :no_policy_found,
          policy: String.t() | nil,
          ref: reference(),
          failure: {atom(), String.t()} | nil
        }

  ## Per job

  @doc false
  # The level and policies for a job. MTA-STS and TLS-RPT apply to
  # deliveries to a domain's MX hosts, not to relay hosts.
  def context(job, opts) do
    requiretls = Map.get(job, :requiretls, false)
    level = level(job.destination.nexthop, opts.tls)
    domain = policy_domain(job.destination.nexthop)
    optional = not requiretls and tls_optional?(job, level, domain, opts)

    # TLS-Required: No asks to ignore the recipient's policies.
    level = if optional and level == :dane, do: :may, else: level
    sts = sts(domain, level, optional, opts)

    %{
      level: level,
      domain: domain,
      relay: match?({:host, _}, job.destination.nexthop),
      sts: sts.policy,
      sts_failure: sts.failure,
      requiretls: requiretls,
      tls_optional: optional,
      dnssec: level == :dane
    }
  end

  defp policy_domain({:mx, domain}), do: domain
  defp policy_domain(_nexthop), do: nil

  defp sts(domain, level, false, %{mta_sts: server})
       when is_binary(domain) and server != nil and level in [:may, :dane],
       do: MTASTS.policy(server, domain)

  defp sts(_domain, _level, _optional, _opts), do: %{policy: nil, failure: nil}

  # RFC 8689 §5. The header is only read when there are policies to
  # ignore.
  defp tls_optional?(job, level, domain, opts) do
    if level == :dane or (domain != nil and opts[:mta_sts] != nil),
      do: tls_required_no?(job),
      else: false
  end

  defp tls_required_no?(job) do
    case Spool.read_headers(job.path, job.message_offset, job.message_size, prefix: job.prefix) do
      {:ok, header} ->
        header
        |> Headers.parse()
        |> Enum.any?(fn {name, raw} -> name == "tls-required" and field_value(raw) == "no" end)

      {:error, _} ->
        false
    end
  end

  defp field_value(raw) do
    [_name, value] = String.split(raw, ":", parts: 2)
    value |> String.replace(~r/\r\n[ \t]/, " ") |> String.trim() |> String.downcase(:ascii)
  end

  defp level(nexthop, tls) do
    key =
      case nexthop do
        {:mx, domain} -> domain
        {:host, %{host: host}} -> host
        {:literal, ip} -> Received.address_literal(ip)
      end

    Map.get(tls.policy, key, tls.default)
  end

  ## Per host

  @doc false
  # The plan for one host, whose address lookups DNSSEC authenticated if
  # `secure`. DANE wins over MTA-STS (RFC 8461 §2).
  @spec plan(map(), String.t(), :inet.port_number(), boolean(), map()) ::
          {:ok, plan(), report()} | {:retry, {String.t(), String.t()}, report() | nil}
  def plan(ctx, host, port, secure, opts) do
    report = %{type: :no_policy_found, policy: nil, ref: make_ref(), failure: nil}

    report =
      if ctx.sts_failure, do: %{report | type: :sts, failure: ctx.sts_failure}, else: report

    literal = String.starts_with?(host, "[")

    cond do
      literal -> literal_plan(ctx, host, report)
      ctx.level == :dane and secure -> dane_plan(ctx, host, port, report, opts)
      true -> host_plan(ctx, host, report, opts)
    end
  end

  defp literal_plan(%{requiretls: true}, host, _report),
    do: {:retry, {"5.7.30", "REQUIRETLS needs a verified host, not address literal #{host}"}, nil}

  defp literal_plan(ctx, host, report) do
    case ctx.level do
      :none ->
        {:ok, :none, report}

      :encrypt ->
        {:ok, {:required, "encrypt", TLS.client_options([])}, report}

      :verify ->
        {:retry, {"4.7.5", "cannot verify a certificate for address literal #{host}"}, nil}

      _may_or_dane ->
        {:ok, {:may, TLS.client_options([])}, report}
    end
  end

  defp dane_plan(ctx, host, port, report, opts) do
    case Sovite.DNS.lookup_secure(opts.resolver, "_#{port}._tcp.#{host}", :tlsa) do
      {:ok, records, true} ->
        case DANE.usable(records) do
          [] ->
            host_plan(ctx, host, report, opts)

          usable ->
            ssl = DANE.client_options(usable, host)
            report = %{report | type: :tlsa, policy: tlsa_text(usable), failure: nil}
            {:ok, {:required, "dane", reporting(ssl, report, true)}, report}
        end

      {:ok, _records, false} ->
        host_plan(ctx, host, report, opts)

      {:error, :nxdomain} ->
        host_plan(ctx, host, report, opts)

      # RFC 7672 §2.2: a host whose TLSA lookup fails must not be used.
      {:error, reason} ->
        report = %{
          report
          | type: :tlsa,
            failure: {:dnssec_invalid, "TLSA lookup failed: #{reason}"}
        }

        {:retry, {"4.7.5", "TLSA lookup for #{host} failed: #{reason}"}, report}
    end
  end

  defp host_plan(%{sts: %Policy{} = policy} = ctx, host, report, opts) do
    report = %{report | type: :sts, policy: policy.text}
    matches = Sovite.TLS.MTASTS.match?(policy, host)
    verify = verify_options(host, opts)

    cond do
      # RFC 8689 §4.2.1: with REQUIRETLS, testing mode is enforced too.
      matches and (policy.mode == :enforce or ctx.requiretls) ->
        {:ok, {:required, "mta-sts", reporting(verify, report, true)}, report}

      matches ->
        {:ok, {:may, reporting(verify, report, false)}, report}

      policy.mode == :enforce or ctx.requiretls ->
        {:retry,
         {"4.7.5", "MX host #{host} is not allowed by the MTA-STS policy of #{ctx.domain}"}, nil}

      true ->
        failure = {:validation_failure, "MX host #{host} is not in the MTA-STS policy"}
        {:ok, {:may, TLS.client_options(hostname: host)}, %{report | failure: failure}}
    end
  end

  defp host_plan(ctx, host, report, opts) do
    case {ctx.level, ctx.requiretls} do
      {:none, true} ->
        {:retry, {"5.7.30", "REQUIRETLS, but TLS is turned off for #{host}"}, nil}

      {:none, false} ->
        {:ok, :none, report}

      {level, requiretls} when level == :verify or (requiretls and ctx.relay) ->
        {:ok, {:required, "verify", reporting(verify_options(host, opts), report, true)}, report}

      {_level, true} ->
        {:retry, {"5.7.30", "REQUIRETLS, but #{host} is not covered by a DANE or MTA-STS policy"},
         nil}

      {:encrypt, false} ->
        {:ok, {:required, "encrypt", TLS.client_options(hostname: host)}, report}

      {_may_or_dane, false} ->
        {:ok, {:may, TLS.client_options(hostname: host)}, report}
    end
  end

  defp verify_options(host, opts) do
    cacerts = opts.tls.cacerts || :public_key.cacerts_get()
    TLS.client_options(verify: :peer, hostname: host, cacerts: cacerts)
  end

  # Certificate problems are sent to this process, for TLS-RPT.
  defp reporting(ssl, report, enforce),
    do: TLS.report_verify(ssl, {self(), report.ref}, enforce: enforce)

  # RFC 8460 §4.4: TLSA records in presentation format.
  defp tlsa_text(records) do
    Enum.map_join(records, "\n", fn {usage, selector, matching, data} ->
      "#{usage} #{selector} #{matching} #{Base.encode16(data, case: :lower)}"
    end)
  end

  ## Outcomes

  @doc false
  # Records the TLS outcome of a session attempt for TLS-RPT: `result` is
  # what connecting and starting TLS gave. Attempts that never reached
  # the server, and those without TLS by choice, are not recorded.
  def record(ctx, report, plan, {host, ip}, result, opts) do
    reasons = if report, do: drain(report.ref, []), else: []

    with %{} <- report,
         domain when is_binary(domain) <- ctx.domain,
         repo when repo != nil <- opts[:tls_reports],
         {:ok, outcome, helo} <- outcome(report, plan, result, reasons) do
      {result_type, reason} = if outcome == :success, do: {nil, nil}, else: outcome

      TLSReportEntries.add(repo, %{
        policy_domain: domain,
        policy_type: report.type,
        policy: report.policy,
        mx_host: host,
        receiving_ip: ip |> :inet.ntoa() |> to_string(),
        receiving_helo: helo,
        sending_ip: sending_ip(opts.client),
        result_type: result_type,
        failure_reason: reason
      })
    end

    :ok
  end

  defp drain(ref, acc) do
    receive do
      {:tls_verify, ^ref, reason} -> drain(ref, [reason | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp outcome(report, plan, {:ok, client}, reasons) do
    helo = Client.server_name(client)

    cond do
      plan == :none ->
        :skip

      report.failure ->
        {:ok, report.failure, helo}

      Client.tls(client) == nil and Map.has_key?(Client.extensions(client), "STARTTLS") ->
        {:ok, {:validation_failure, "TLS handshake failed"}, helo}

      Client.tls(client) == nil ->
        {:ok, {:starttls_not_supported, "STARTTLS not offered"}, helo}

      reasons != [] ->
        {:ok, certificate_failure(hd(reasons)), helo}

      true ->
        {:ok, :success, helo}
    end
  end

  defp outcome(%{failure: {_, _} = failure}, nil, {:retry, _error}, _reasons),
    do: {:ok, failure, nil}

  defp outcome(_report, _plan, {:retry, {"4.7.4", text}}, _reasons),
    do: {:ok, {:starttls_not_supported, text}, nil}

  defp outcome(_report, _plan, {:retry, {"4.7.5", text}}, [reason | _]),
    do: {:ok, {elem(certificate_failure(reason), 0), text}, nil}

  defp outcome(_report, _plan, {:retry, {"4.7.5", text}}, []),
    do: {:ok, {:validation_failure, text}, nil}

  # Connection failures: no TLS session took place.
  defp outcome(_report, _plan, _result, _reasons), do: :skip

  defp certificate_failure(:hostname_check_failed),
    do: {:certificate_host_mismatch, "certificate not valid for the host name"}

  defp certificate_failure(:cert_expired), do: {:certificate_expired, "certificate expired"}

  defp certificate_failure(reason) when reason in [:unknown_ca, :selfsigned_peer],
    do: {:certificate_not_trusted, "certificate not issued by a trusted CA"}

  defp certificate_failure(:dane_mismatch),
    do: {:validation_failure, "certificate does not match the TLSA records"}

  defp certificate_failure(reason), do: {:validation_failure, "certificate: #{inspect(reason)}"}

  defp sending_ip(client) do
    case Keyword.get(client, :local_address) do
      nil -> nil
      ip -> ip |> :inet.ntoa() |> to_string()
    end
  end
end
