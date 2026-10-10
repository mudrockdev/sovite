defmodule Sovite.Core.DMARCReports do
  @moduledoc """
  Sends DMARC aggregate reports (RFC 7489 §7.2), when `dmarc.reports` is
  on.

  `Sovite.Core.MailAuth` stores the DMARC result of every message from
  outside whose policy asks for aggregate reports (`rua=`). Every
  `dmarc.report_interval`, the results are grouped by policy domain into
  one report each, as gzipped XML (`Sovite.DMARC.Report`), and queued as
  mail from `dmarc.report_from` to the domain's `mailto:` destinations.
  Destinations outside the policy domain's organization are used only if
  they agree to receive its reports (RFC 7489 §7.1). Reported results are
  then deleted.

  ## Options

    * `:repo` - the `Sovite.Core.Repo` reference. Required.
    * `:directory` - the queue directory. Required.
    * `:hostname`, `:org_name`, `:from` - this server, the organization
      named in reports, and their sender address. Required.
    * `:interval` - milliseconds between reports. Required.
    * `:queue_manager` - told about each queued report, if given.
    * `:resolver` - for the destination checks. Defaults to
      `Sovite.DNS.default_resolver/0`.
    * `:mail_auth` - `Sovite.Core.MailAuth` options, to DKIM sign the
      report mail with the keys of the `:from` domain. Not signed
      without.

  ## Telemetry

    * `[:sovite, :dmarc, :report, :sent]` - `%{rows, messages}`, `%{domain,
      report_id, queue_id, to}`
    * `[:sovite, :dmarc, :report, :skipped]` - `%{messages}`, `%{domain,
      reason}`
  """

  use GenServer

  require Logger

  alias Sovite.Core.{MailAuth, QueueManager}
  alias Sovite.Core.Repo.Tables.DMARCReportEntries
  alias Sovite.DMARC
  alias Sovite.DMARC.Report
  alias Sovite.Message.{Date, MessageID}
  alias Sovite.Queue.{Envelope, ID, Spool}

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
  Reports every result stored before `until`, one report per policy
  domain. Returns the queue IDs of the queued reports.
  """
  @spec run(map(), DateTime.t()) :: [String.t()]
  def run(opts, until) do
    opts.repo
    |> DMARCReportEntries.domains(until)
    |> Enum.flat_map(fn domain ->
      entries = DMARCReportEntries.list(opts.repo, domain, until)
      result = report(opts, domain, entries, until)
      DMARCReportEntries.delete(opts.repo, domain, until)
      result
    end)
  rescue
    error ->
      Logger.error("cannot send DMARC reports: #{Exception.message(error)}")
      []
  end

  defp report(opts, domain, entries, until) do
    latest = List.last(entries)

    case destinations(opts, domain, latest.rua) do
      [] ->
        skipped(domain, entries, "no authorized destination")
        []

      destinations ->
        report_id = ID.generate()
        begin = entries |> hd() |> Map.fetch!(:inserted_at)
        xml = Report.aggregate(document(opts, latest, entries, report_id, begin, until))
        gzip = :zlib.gzip(xml)
        name = Report.filename(opts.hostname, domain, begin, until, report_id)

        to =
          for {address, max_size} <- destinations,
              max_size == nil or byte_size(gzip) <= max_size,
              do: address

        if to == [] do
          skipped(domain, entries, "report too large for its destinations")
          []
        else
          enqueue(opts, domain, report_id, to, name, gzip, length(entries))
        end
    end
  end

  defp skipped(domain, entries, reason) do
    :telemetry.execute([:sovite, :dmarc, :report, :skipped], %{messages: length(entries)}, %{
      domain: domain,
      reason: reason
    })
  end

  # mailto: URIs whose domain may receive the reports, with their size
  # limits.
  defp destinations(opts, domain, rua) do
    rua
    |> String.split(",", trim: true)
    |> Enum.flat_map(fn uri ->
      with {:ok, address, max_size} <- mailto(uri),
           [_local, rua_domain] <- String.split(address, "@"),
           {:ok, true} <- DMARC.report_authorized?(opts.resolver, domain, rua_domain) do
        [{address, max_size}]
      else
        _ -> []
      end
    end)
    |> Enum.uniq_by(&String.downcase(elem(&1, 0)))
  end

  @units %{"" => 1, "k" => 1024, "m" => 1024 ** 2, "g" => 1024 ** 3, "t" => 1024 ** 4}

  defp mailto(uri) do
    pattern = ~r/\Amailto:([^?!]+)[^!]*(?:!(\d+[kmgt]?))?\z/i

    with [address | size] <- Regex.run(pattern, uri, capture: :all_but_first),
         address = URI.decode(address),
         true <- Sovite.Validators.mailbox?(address) do
      {:ok, address, size_limit(List.first(size, ""))}
    else
      _ -> :error
    end
  end

  defp size_limit(""), do: nil

  defp size_limit(size) do
    {number, unit} = Integer.parse(size)
    number * Map.fetch!(@units, String.downcase(unit))
  end

  defp document(opts, latest, entries, report_id, begin, until) do
    %{
      org_name: opts.org_name,
      email: opts.from,
      extra_contact_info: nil,
      report_id: report_id,
      begin: begin,
      end: until,
      policy: %{
        domain: latest.policy_domain,
        adkim: latest.adkim,
        aspf: latest.aspf,
        p: latest.p,
        sp: latest.sp,
        pct: latest.pct,
        np: latest.np
      },
      records:
        entries
        |> Enum.group_by(&row_key/1)
        |> Enum.map(fn {key, group} -> Map.put(key, :count, length(group)) end)
        |> Enum.sort_by(&{&1.source_ip, -&1.count})
    }
  end

  defp row_key(entry) do
    {:ok, ip} = entry.source_ip |> String.to_charlist() |> :inet.parse_address()

    %{
      source_ip: ip,
      disposition: entry.disposition,
      dkim: entry.dkim,
      spf: entry.spf,
      reasons:
        if(entry.override, do: [%{type: Atom.to_string(entry.override), comment: nil}], else: []),
      header_from: entry.header_from,
      envelope_from: entry.envelope_from,
      envelope_to: entry.envelope_to,
      dkim_auth: Enum.map(entry.signatures, &Map.take(&1, [:domain, :selector, :result])),
      spf_auth:
        if(entry.spf_domain,
          do: [%{domain: entry.spf_domain, scope: entry.spf_scope, result: entry.spf_result}],
          else: []
        )
    }
  end

  defp enqueue(opts, domain, report_id, to, name, gzip, messages) do
    envelope = %Envelope{
      queue_id: ID.generate(),
      sender: opts.from,
      recipients: to,
      received_at: DateTime.utc_now(),
      protocol: "local",
      body_type: :"7bit"
    }

    message = message(opts, domain, report_id, to, name, gzip)

    prefix =
      if opts[:mail_auth], do: MailAuth.sign_message(opts.mail_auth, opts.from, message), else: []

    with {:ok, writer} <- Spool.open(opts.directory, envelope),
         {:ok, writer} <- Spool.write(writer, message),
         {:ok, _path, _size} <- Spool.commit(writer, prefix) do
      if opts.queue_manager, do: QueueManager.notify(opts.queue_manager, envelope.queue_id)

      :telemetry.execute([:sovite, :dmarc, :report, :sent], %{rows: 1, messages: messages}, %{
        domain: domain,
        report_id: report_id,
        queue_id: envelope.queue_id,
        to: to
      })

      [envelope.queue_id]
    else
      {:error, reason} ->
        Logger.error("cannot queue DMARC report for #{domain}: #{inspect(reason)}")
        []
    end
  end

  @doc false
  # The report mail (RFC 7489 §7.2.1.1): a short text and the report as a
  # gzip attachment.
  def message(opts, domain, report_id, to, name, gzip) do
    boundary = "=_" <> Base.encode16(:crypto.strong_rand_bytes(12), case: :lower)

    attachment =
      gzip
      |> Base.encode64()
      |> chunks(76)
      |> Enum.map_join(&(&1 <> "\r\n"))

    [
      "From: <#{opts.from}>\r\n",
      "To: #{Enum.map_join(to, ", ", &"<#{&1}>")}\r\n",
      "Date: #{Date.format(DateTime.utc_now())}\r\n",
      "Message-ID: #{MessageID.generate(opts.hostname)}\r\n",
      "Subject: Report Domain: #{domain} Submitter: #{opts.org_name} Report-ID: <#{report_id}>\r\n",
      "MIME-Version: 1.0\r\n",
      "Content-Type: multipart/mixed; boundary=\"#{boundary}\"\r\n",
      "\r\n",
      "--#{boundary}\r\n",
      "Content-Type: text/plain; charset=us-ascii\r\n",
      "\r\n",
      "This is a DMARC aggregate report for #{domain} from #{opts.org_name}.\r\n",
      "--#{boundary}\r\n",
      "Content-Type: application/gzip; name=\"#{name}\"\r\n",
      "Content-Disposition: attachment; filename=\"#{name}\"\r\n",
      "Content-Transfer-Encoding: base64\r\n",
      "\r\n",
      attachment,
      "--#{boundary}--\r\n"
    ]
  end

  defp chunks(data, size) when byte_size(data) > size,
    do: [
      binary_part(data, 0, size) | chunks(binary_part(data, size, byte_size(data) - size), size)
    ]

  defp chunks(data, _size), do: [data]
end
