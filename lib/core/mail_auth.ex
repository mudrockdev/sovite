defmodule Sovite.Core.MailAuth do
  @moduledoc """
  Email authentication for `Sovite.Core.SMTPHandler`: SPF, DKIM, ARC,
  and DMARC on mail from outside, DKIM signing on mail from users, and
  ARC sealing on mail this server forwards.

  Mail from outside is mail from clients that are neither in
  `smtp.trusted_networks` nor authenticated, except over LMTP, where the
  client is an MTA that has checked the mail already. For it:

    * SPF checks the `MAIL FROM` identity (and the `HELO` identity, with
      `spf.helo`) when the client sends `MAIL`. With `spf.reject_fail`, a
      `fail` is refused with `550 5.7.23`.
    * DKIM signatures and the ARC chain are verified while the body is
      received, and DMARC is evaluated at the end of the data. With
      `dmarc.policy = "enforce"`, a failing message whose policy is
      `reject` is refused with `550 5.7.26`, and one whose policy is
      `quarantine` is put on hold. An unbroken ARC chain sealed last by
      one of `arc.trusted_sealers` overrides the policy, so mailing lists
      and forwarders that seal keep working.
    * The results go into an `Authentication-Results:` field at the top
      of the message (RFC 8601).
    * When the message is forwarded to another domain, it is ARC sealed
      with `arc.seal`.

  Fields claiming to be `Authentication-Results:` of this server
  (`server.authserv_id`) are removed from every message, so users never
  see forged results (RFC 8601 §5).

  Mail from users (trusted or authenticated) is DKIM signed with every
  signing key of the `From:` domain, or of its closest parent domain that
  has one, so a domain with RSA and Ed25519 keys gets both signatures.

  All headers this module adds are passed to `Sovite.Queue.Spool.commit/2`
  as the message prefix: they are computed only once the whole message
  has been received.

  ## Telemetry

    * `[:sovite, :smtp, :message, :authenticated]` - `%{}`, `%{session_id,
      queue_id, spf, dkim, arc, dmarc, disposition}`, once per message from
      outside.
  """

  require Logger

  alias Sovite.{ARC, AuthResults, DKIM, DMARC, SPF}
  alias Sovite.Core.Config
  alias Sovite.Core.Repo.Tables.DMARCReportEntries
  alias Sovite.DKIM.{Body, Verifier}
  alias Sovite.SMTP.Reply

  @typedoc "Options from the configuration, see `opts/3`."
  @type opts :: map()

  @typedoc """
  The SMTP transaction the message came in: the client address and
  `HELO` name, the `MAIL FROM` address, the authentication identity and
  whether the client is trusted, and whether some recipient is
  forwarded to another domain.
  """
  @type context :: %{
          session_id: String.t(),
          queue_id: String.t() | nil,
          ip: :inet.ip_address(),
          helo: String.t() | nil,
          sender: String.t(),
          recipients: [String.t()],
          inbound: boolean(),
          forwarded: boolean(),
          spf: spf() | nil
        }

  @typedoc "SPF results from `MAIL`: the `MAIL FROM` identity and, if checked, `HELO`."
  @type spf :: %{mail_from: SPF.Result.t(), helo: SPF.Result.t() | nil}

  @doc "Options from the running configuration."
  @spec opts(Config.t(), Sovite.Core.Repo.t() | nil, Sovite.DNS.resolver()) :: opts()
  def opts(config, repo, resolver) do
    keys = for key <- config.dkim.key, key.signing_key != nil, do: key

    %{
      authserv_id: config.server.authserv_id,
      hostname: config.server.hostname,
      resolver: resolver,
      repo: repo,
      spf: config.spf,
      dkim_verify: config.dkim.verify,
      signing_keys:
        if(config.dkim.sign,
          do: keys |> Enum.filter(& &1.sign) |> Enum.group_by(& &1.domain, & &1.signing_key),
          else: %{}
        ),
      sign_opts:
        [
          headers: config.dkim.headers,
          expiration: config.dkim.expiration && div(config.dkim.expiration, 1000)
        ]
        |> Enum.reject(fn {_key, value} -> is_nil(value) end),
      arc_verify: config.arc.verify,
      seal_key: if(config.arc.seal, do: seal_key(keys, config.arc)),
      trusted_sealers: MapSet.new(config.arc.trusted_sealers),
      dmarc: config.dmarc.verify,
      enforce: config.dmarc.policy == :enforce,
      reports: config.dmarc.reports and repo != nil
    }
  end

  defp seal_key(keys, arc) do
    Enum.find_value(keys, fn key ->
      if key.domain == arc.domain and key.selector == arc.selector, do: key.signing_key
    end)
  end

  ## SPF, at MAIL

  @doc """
  Checks SPF for the `MAIL FROM` address `sender` (and the `HELO` name,
  with `spf.helo`). Returns `{:ok, results}`, `{:ok, nil}` when SPF is
  off, or `{:reject, reply, results}` for a `fail` with
  `spf.reject_fail`.
  """
  @spec check_spf(opts(), :inet.ip_address(), String.t() | nil, String.t()) ::
          {:ok, spf() | nil} | {:reject, Reply.t(), spf()}
  def check_spf(%{spf: %{verify: false}}, _ip, _helo, _sender), do: {:ok, nil}

  def check_spf(opts, ip, helo, sender) do
    spf_opts = [receiver: opts.hostname, timeout: opts.spf.timeout]
    mail_from = SPF.check_mail_from(opts.resolver, ip, sender, helo, spf_opts)

    helo_result =
      if opts.spf.helo and sender != "", do: SPF.check_helo(opts.resolver, ip, helo, spf_opts)

    results = %{mail_from: mail_from, helo: helo_result}

    if opts.spf.reject_fail and mail_from.result == :fail do
      address = if sender == "", do: "postmaster@#{helo}", else: sender
      explanation = mail_from.explanation || "see the SPF record of #{mail_from.domain}"

      text =
        "SPF: #{format_ip(ip)} is not allowed to send mail from <#{address}>: " <>
          sanitize(explanation)

      {:reject, Reply.new(550, "5.7.23", text), results}
    else
      {:ok, results}
    end
  end

  defp format_ip(ip), do: ip |> :inet.ntoa() |> to_string()

  # Explanations come from DNS: keep them to one printable line.
  defp sanitize(text), do: text |> String.replace(~r/[^\x20-\x7e]/, "?") |> String.slice(0, 200)

  ## The message

  @doc """
  Plans the work for a message once its header section is complete.
  `received` are the header fields as they came in, `fields` as they will
  be stored (after submission fixes and rewriting). Returns `nil` when
  there is nothing to do.
  """
  @spec start(
          opts(),
          [Sovite.Message.Headers.field()],
          [Sovite.Message.Headers.field()],
          context()
        ) ::
          map() | nil
  def start(opts, received, fields, context) do
    plan =
      if context.inbound,
        do: inbound_plan(opts, received, context),
        else: outbound_plan(opts, fields)

    specs =
      Enum.uniq(
        if(plan.dkim, do: Verifier.body_specs(plan.dkim), else: []) ++
          if(plan.arc, do: ARC.body_specs(plan.arc), else: []) ++
          if(plan.sign != [] or plan.seal != nil, do: [DKIM.body_spec()], else: [])
      )

    if context.inbound or plan.sign != [],
      do:
        Map.merge(plan, %{opts: opts, received: received, fields: fields, body: Body.new(specs)}),
      else: nil
  end

  defp inbound_plan(opts, received, context) do
    %{
      dkim: if(opts.dkim_verify, do: Verifier.new(received)),
      arc: if(opts.arc_verify or (context.forwarded and opts.seal_key), do: ARC.new(received)),
      seal: if(context.forwarded, do: opts.seal_key),
      sign: []
    }
  end

  defp outbound_plan(opts, fields) do
    keys =
      case DMARC.from_domain(fields) do
        {:ok, domain} -> keys_for(opts.signing_keys, domain)
        {:error, _} -> []
      end

    %{dkim: nil, arc: nil, seal: nil, sign: keys}
  end

  # The keys of the domain, or of its closest parent with keys.
  defp keys_for(keys, _domain) when map_size(keys) == 0, do: []

  defp keys_for(keys, domain) do
    case Map.fetch(keys, domain) do
      {:ok, found} ->
        found

      :error ->
        case String.split(domain, ".", parts: 2) do
          [_label, parent] -> keys_for(keys, parent)
          [_tld] -> []
        end
    end
  end

  @doc "Feeds body data."
  @spec update(map() | nil, iodata()) :: map() | nil
  def update(nil, _data), do: nil
  def update(work, data), do: %{work | body: Body.update(work.body, data)}

  @doc """
  Finishes the checks at the end of the data. Returns the header fields
  to add at the top of the message and what to do with it: `:accept`,
  `{:hold, reason}`, or `{:reject, reply}`.
  """
  @spec finish(map() | nil, context()) ::
          {[String.t()], :accept | {:hold, String.t()} | {:reject, Reply.t()}}
  def finish(nil, _context), do: {[], :accept}

  def finish(%{sign: [_ | _] = keys} = work, _context) do
    {hash, _length} = Map.fetch!(Body.finish(work.body), DKIM.body_spec())
    {Enum.map(keys, &DKIM.sign_fields(work.fields, hash, &1, work.opts.sign_opts)), :accept}
  end

  def finish(work, context) do
    opts = work.opts
    hashes = Body.finish(work.body)
    dkim = if work.dkim, do: Verifier.finish(work.dkim, hashes, opts.resolver), else: []
    arc = if work.arc, do: ARC.finish(work.arc, hashes, opts.resolver)
    dmarc = if opts.dmarc, do: dmarc(opts, work.received, context.spf, dkim)
    {verdict, override} = verdict(opts, dmarc, arc)

    results = results(context, work.dkim && dkim, arc, dmarc, verdict)
    value = AuthResults.value(opts.authserv_id, results)

    seal =
      if work.seal do
        {hash, _length} = Map.fetch!(hashes, DKIM.body_spec())
        ARC.seal(work.fields, hash, arc, value, work.seal)
      else
        []
      end

    if opts.reports, do: record(opts, context, dmarc, dkim, verdict, override)
    event(context, dkim, arc, dmarc, verdict)

    # With every check turned off there is nothing to report.
    field = if results == [], do: [], else: ["Authentication-Results: " <> value <> "\r\n"]
    {seal ++ field, verdict}
  end

  defp dmarc(opts, received, spf, dkim) do
    case DMARC.from_domain(received) do
      {:ok, domain} ->
        mail_from = spf && spf.mail_from
        spf_input = if mail_from, do: {mail_from.result, mail_from.domain}, else: {:none, nil}

        DMARC.check(opts.resolver, domain,
          spf: spf_input,
          dkim: Enum.map(dkim, &{&1.result, &1.domain})
        )

      {:error, reason} ->
        reason
    end
  end

  # What the DMARC result means for the message, and why the policy's
  # disposition was not applied, if it was not.
  defp verdict(opts, %DMARC.Result{result: :fail, disposition: disposition} = dmarc, arc)
       when disposition != :none do
    cond do
      trusted_chain?(opts, arc) -> {:accept, :trusted_forwarder}
      not opts.enforce -> {:accept, :local_policy}
      disposition == :reject -> {{:reject, dmarc_reply(dmarc)}, nil}
      disposition == :quarantine -> {{:hold, "DMARC policy of #{dmarc.from_domain}"}, nil}
    end
  end

  defp verdict(_opts, %DMARC.Result{result: :fail, sampled: false, policy: policy}, _arc)
       when policy != nil,
       do: {:accept, :sampled_out}

  defp verdict(_opts, _dmarc, _arc), do: {:accept, nil}

  defp trusted_chain?(_opts, nil), do: false

  defp trusted_chain?(opts, %ARC.Result{cv: :pass, sealers: sealers}),
    do: MapSet.member?(opts.trusted_sealers, List.last(sealers))

  defp trusted_chain?(_opts, _arc), do: false

  defp dmarc_reply(dmarc) do
    Reply.new(
      550,
      "5.7.26",
      "Unauthenticated email from #{dmarc.from_domain} is not accepted due to its DMARC policy"
    )
  end

  ## Authentication-Results

  defp results(context, dkim, arc, dmarc, verdict) do
    spf_results(context) ++ dkim_results(dkim) ++ arc_result(arc) ++ dmarc_result(dmarc, verdict)
  end

  defp spf_results(%{spf: nil}), do: []

  defp spf_results(%{spf: spf} = context) do
    mail_from = if context.sender == "", do: "postmaster@#{context.helo}", else: context.sender

    [spf_result(spf.mail_from, "smtp.mailfrom", mail_from)] ++
      if spf.helo, do: [spf_result(spf.helo, "smtp.helo", context.helo || "")], else: []
  end

  defp spf_result(result, property, value) do
    %{
      method: "spf",
      result: Atom.to_string(result.result),
      reason: reason(result.result, result.reason),
      properties: [{property, value}]
    }
  end

  # Reasons only where they help: why a check failed or could not be done.
  defp reason(result, reason) when result in [:fail, :temperror, :permerror, :policy], do: reason
  defp reason(_result, _reason), do: nil

  defp dkim_results(nil), do: []
  defp dkim_results([]), do: [%{method: "dkim", result: "none"}]

  defp dkim_results(results) do
    for result <- results do
      properties =
        [
          {"header.d", result.domain},
          {"header.i", result.identity},
          {"header.s", result.selector},
          {"header.a", result.algorithm},
          {"header.b", result.b}
        ]
        |> Enum.reject(fn {_name, value} -> value in [nil, ""] end)

      %{
        method: "dkim",
        result: Atom.to_string(result.result),
        reason: reason(result.result, result.reason),
        properties: properties
      }
    end
  end

  defp arc_result(nil), do: []

  defp arc_result(arc),
    do: [%{method: "arc", result: Atom.to_string(arc.cv), reason: reason(arc.cv, arc.reason)}]

  defp dmarc_result(nil, _verdict), do: []

  defp dmarc_result(%DMARC.Result{} = dmarc, verdict) do
    comment =
      if dmarc.policy do
        record = dmarc.policy.record
        applied = if verdict == :accept, do: :none, else: dmarc.disposition

        "p=#{upcase(record.p)} sp=#{upcase(record.sp)} dis=#{upcase(applied)}"
      end

    [
      %{
        method: "dmarc",
        result: Atom.to_string(dmarc.result),
        reason: reason(dmarc.result, dmarc.reason),
        comment: comment,
        properties: [{"header.from", dmarc.from_domain}]
      }
    ]
  end

  # The From: field had no usable domain.
  defp dmarc_result(reason, _verdict) when is_atom(reason),
    do: [%{method: "dmarc", result: "permerror", reason: from_problem(reason)}]

  defp from_problem(:missing), do: "no From field"
  defp from_problem(:multiple), do: "more than one From domain"
  defp from_problem(:invalid), do: "invalid From field"

  defp upcase(atom), do: atom |> Atom.to_string() |> String.upcase()

  ## Reports and telemetry

  defp record(
         opts,
         context,
         %DMARC.Result{policy: %{record: %{rua: [_ | _]}}} = dmarc,
         dkim,
         verdict,
         override
       )
       when dmarc.result in [:pass, :fail] do
    attrs =
      dmarc.policy
      |> policy_attrs()
      |> Map.merge(spf_attrs(context))
      |> Map.merge(%{
        source_ip: format_ip(context.ip),
        header_from: dmarc.from_domain,
        envelope_from: envelope_domain(context.sender, context.helo),
        envelope_to: context.recipients |> List.first() |> envelope_domain(nil),
        disposition: if(verdict == :accept, do: :none, else: dmarc.disposition),
        dkim: aligned(dmarc.dkim_aligned),
        spf: aligned(dmarc.spf_aligned),
        override: override,
        signatures:
          for(
            result <- dkim,
            result.domain != nil,
            do: %{domain: result.domain, selector: result.selector, result: result.result}
          )
      })

    case DMARCReportEntries.add(opts.repo, attrs) do
      {:ok, _entry} ->
        :ok

      {:error, changeset} ->
        Logger.warning("cannot store DMARC result: #{inspect(changeset.errors)}")
    end
  rescue
    error -> Logger.warning("cannot store DMARC result: #{Exception.message(error)}")
  end

  defp record(_opts, _context, _dmarc, _dkim, _verdict, _override), do: :ok

  defp policy_attrs(%{domain: domain, record: record}) do
    %{
      policy_domain: domain,
      rua: Enum.map_join(record.rua, ",", & &1.uri),
      adkim: record.adkim,
      aspf: record.aspf,
      p: record.p,
      sp: record.sp,
      np: record.np,
      pct: record.pct
    }
  end

  defp spf_attrs(%{spf: %{mail_from: mail_from}, sender: sender}) do
    %{
      spf_domain: mail_from.domain,
      spf_scope: if(sender == "", do: :helo, else: :mfrom),
      spf_result: mail_from.result
    }
  end

  defp spf_attrs(_context), do: %{}

  defp aligned(true), do: :pass
  defp aligned(false), do: :fail

  defp envelope_domain(nil, _helo), do: nil
  defp envelope_domain("", helo), do: helo

  defp envelope_domain(address, _helo) do
    case String.split(address, "@") do
      [_local, domain] -> String.downcase(domain)
      _ -> nil
    end
  end

  defp event(context, dkim, arc, dmarc, verdict) do
    :telemetry.execute([:sovite, :smtp, :message, :authenticated], %{}, %{
      session_id: context.session_id,
      queue_id: context.queue_id,
      spf: context.spf && context.spf.mail_from.result,
      dkim: dkim |> Enum.map(& &1.result) |> Enum.uniq() |> Enum.join(" "),
      arc: arc && arc.cv,
      dmarc: dmarc_status(dmarc),
      disposition: disposition(verdict)
    })
  end

  defp dmarc_status(%DMARC.Result{result: result}), do: result
  defp dmarc_status(nil), do: nil
  defp dmarc_status(_from_problem), do: :permerror

  defp disposition(:accept), do: :accept
  defp disposition({:hold, _reason}), do: :hold
  defp disposition({:reject, _reply}), do: :reject
end
