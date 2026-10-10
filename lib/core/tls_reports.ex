defmodule Sovite.Core.TLSReports do
  @moduledoc """
  Sends TLS-RPT reports (RFC 8460), when `tls_rpt.reports` is on.

  `Sovite.Core.Delivery` stores the TLS outcome of every session to a
  domain's MX hosts: which policy applied (DANE TLSA records, an MTA-STS
  policy, or none) and whether TLS worked, or why not. Every
  `tls_rpt.report_interval`, the outcomes are grouped by recipient
  domain into one report each (`Sovite.TLS.TLSRPT`), for the domains
  that ask for reports with a `_smtp._tls` TXT record. The gzipped JSON
  report goes to each `mailto:` destination as mail from
  `tls_rpt.report_from`, DKIM signed when that domain has keys, and is
  posted to each `https:` destination. Reported outcomes are then
  deleted, as are those of domains that do not ask for reports.

  ## Options

    * `:repo` - the `Sovite.Core.Repo` reference. Required.
    * `:directory` - the queue directory. Required.
    * `:hostname`, `:org_name`, `:from`, `:contact_info` - this server,
      the organization named in reports, their sender address, and how
      to reach it. Required.
    * `:interval` - milliseconds between reports. Required.
    * `:queue_manager` - told about each queued report, if given.
    * `:resolver` - for the `_smtp._tls` records. Defaults to
      `Sovite.DNS.default_resolver/0`.
    * `:mail_auth` - `Sovite.Core.MailAuth` options, to sign report
      mail. Not signed without.
    * `:post` - options for `Sovite.TLS.TLSRPT.post/3`.

  ## Telemetry

    * `[:sovite, :tls_rpt, :report, :sent]` - `%{sessions}`, `%{domain,
      report_id, queue_id, to, urls}`
    * `[:sovite, :tls_rpt, :report, :skipped]` - `%{sessions}`, `%{domain,
      reason}`
    * `[:sovite, :tls_rpt, :report, :post_failed]` - `%{}`, `%{domain,
      url, reason}`
  """

  use GenServer

  require Logger

  alias Sovite.Core.{MailAuth, QueueManager}
  alias Sovite.Core.Repo.Tables.TLSReportEntries
  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.TLS.{MTASTS, TLSRPT}

  @doc false
  def child_spec(opts), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}

  @doc "Starts the report sender."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @impl true
  def init(opts) do
    state =
      opts
      |> Map.new()
      |> Map.put_new_lazy(:resolver, &Sovite.DNS.default_resolver/0)
      |> Map.put_new(:queue_manager, nil)
      |> Map.put_new(:mail_auth, nil)
      |> Map.put_new(:post, [])

    schedule(state)
    {:ok, state}
  end

  defp schedule(state), do: Process.send_after(self(), :report, state.interval)

  @impl true
  def handle_info(:report, state) do
    run(state, DateTime.utc_now())
    schedule(state)
    {:noreply, state}
  end

  @doc """
  Reports every outcome stored before `until`, one report per domain.
  Returns the queue IDs of the queued report mails.
  """
  @spec run(map(), DateTime.t()) :: [String.t()]
  def run(opts, until) do
    opts.repo
    |> TLSReportEntries.domains(until)
    |> Enum.flat_map(fn domain ->
      entries = TLSReportEntries.list(opts.repo, domain, until)
      result = report(opts, domain, entries, until)
      TLSReportEntries.delete(opts.repo, domain, until)
      result
    end)
  rescue
    error ->
      Logger.error("cannot send TLS reports: #{Exception.message(error)}")
      []
  end

  defp report(opts, domain, entries, until) do
    case TLSRPT.discover(opts.resolver, domain) do
      {:ok, uris} ->
        report_id = ID.generate()
        begin = entries |> hd() |> Map.fetch!(:inserted_at)
        json = TLSRPT.report(document(opts, domain, entries, report_id, begin, until))
        gzip = :zlib.gzip(json)
        name = TLSRPT.filename(opts.hostname, domain, begin, until, report_id)
        {addresses, urls} = destinations(uris)
        posted = Enum.filter(urls, &post(opts, domain, &1, gzip))

        queued =
          if addresses == [],
            do: [],
            else: enqueue(opts, domain, report_id, addresses, name, gzip)

        :telemetry.execute([:sovite, :tls_rpt, :report, :sent], %{sessions: length(entries)}, %{
          domain: domain,
          report_id: report_id,
          queue_id: List.first(queued),
          to: addresses,
          urls: posted
        })

        queued

      {:error, reason} ->
        :telemetry.execute(
          [:sovite, :tls_rpt, :report, :skipped],
          %{sessions: length(entries)},
          %{domain: domain, reason: skip_reason(reason)}
        )

        []
    end
  end

  defp skip_reason(:no_record), do: "no TLS-RPT record"
  defp skip_reason({:dns, reason}), do: "TLS-RPT record lookup failed: #{reason}"
  defp skip_reason(reason), do: "unusable TLS-RPT record: #{reason}"

  # mailto: addresses, and https: URLs.
  defp destinations(uris) do
    {mailto, https} = Enum.split_with(uris, &String.starts_with?(String.downcase(&1), "mailto:"))

    addresses =
      mailto
      |> Enum.flat_map(fn "mailto:" <> rest ->
        address = rest |> String.split("?", parts: 2) |> hd() |> URI.decode()
        if Sovite.Validators.mailbox?(address), do: [address], else: []
      end)
      |> Enum.uniq_by(&String.downcase/1)

    {addresses, https}
  end

  defp post(opts, domain, url, gzip) do
    case TLSRPT.post(url, gzip, opts.post) do
      :ok ->
        true

      {:error, reason} ->
        :telemetry.execute([:sovite, :tls_rpt, :report, :post_failed], %{}, %{
          domain: domain,
          url: url,
          reason: inspect(reason)
        })

        false
    end
  end

  defp document(opts, domain, entries, report_id, begin, until) do
    %{
      organization_name: opts.org_name,
      contact_info: opts.contact_info,
      report_id: report_id,
      begin: begin,
      end: until,
      policies:
        entries
        |> Enum.group_by(&policy_key/1)
        |> Enum.map(fn {key, sessions} -> policy(domain, key, sessions) end)
        |> Enum.sort_by(&{&1.type, &1.mx_host})
    }
  end

  # TLSA policies are per MX host; an MTA-STS policy covers the domain.
  defp policy_key(%{policy_type: :tlsa} = entry), do: {:tlsa, entry.policy, entry.mx_host}
  defp policy_key(entry), do: {entry.policy_type, entry.policy, nil}

  defp policy(domain, {type, text, mx_host}, sessions) do
    {failed, successful} = Enum.split_with(sessions, & &1.result_type)

    %{
      type: type,
      domain: domain,
      string: policy_lines(text),
      mx_host: mx_hosts(type, text, mx_host),
      successful: length(successful),
      failed: length(failed),
      failures:
        failed
        |> Enum.group_by(
          &{&1.result_type, &1.sending_ip, &1.mx_host, &1.receiving_helo, &1.receiving_ip,
           &1.failure_reason}
        )
        |> Enum.map(fn {{result_type, sending_ip, mx, helo, receiving_ip, reason}, group} ->
          %{
            result_type: result_type,
            sending_mta_ip: ip(sending_ip),
            receiving_mx_hostname: mx,
            receiving_mx_helo: helo,
            receiving_ip: ip(receiving_ip),
            count: length(group),
            additional_information: reason
          }
        end)
        |> Enum.sort_by(&{-&1.count, &1.receiving_mx_hostname})
    }
  end

  defp policy_lines(nil), do: []
  defp policy_lines(text), do: String.split(text, ["\r\n", "\n"], trim: true)

  defp mx_hosts(:tlsa, _text, mx_host), do: [mx_host]

  defp mx_hosts(:sts, text, _mx_host) when is_binary(text) do
    case MTASTS.parse_policy(text) do
      {:ok, policy} -> policy.mx
      {:error, _} -> []
    end
  end

  defp mx_hosts(_type, _text, _mx_host), do: []

  defp ip(nil), do: nil

  defp ip(text) do
    case :inet.parse_strict_address(String.to_charlist(text)) do
      {:ok, ip} -> ip
      {:error, _} -> nil
    end
  end

  defp enqueue(opts, domain, report_id, to, name, gzip) do
    envelope = %Envelope{
      queue_id: ID.generate(),
      sender: opts.from,
      recipients: to,
      received_at: DateTime.utc_now(),
      protocol: "local",
      body_type: :"7bit"
    }

    message =
      TLSRPT.message(%{
        from: opts.from,
        to: to,
        domain: domain,
        submitter: opts.hostname,
        report_id: report_id,
        filename: name,
        gzip: gzip,
        hostname: opts.hostname
      })

    prefix =
      if opts[:mail_auth], do: MailAuth.sign_message(opts.mail_auth, opts.from, message), else: []

    with {:ok, writer} <- Spool.open(opts.directory, envelope),
         {:ok, writer} <- Spool.write(writer, message),
         {:ok, _path, _size} <- Spool.commit(writer, prefix) do
      if opts.queue_manager, do: QueueManager.notify(opts.queue_manager, envelope.queue_id)
      [envelope.queue_id]
    else
      {:error, reason} ->
        Logger.error("cannot queue TLS report for #{domain}: #{inspect(reason)}")
        []
    end
  end
end
