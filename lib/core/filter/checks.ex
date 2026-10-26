defmodule Sovite.Core.Filter.Checks do
  @moduledoc """
  Sovite's own checks as filter symbols: SPF, DKIM, ARC, DMARC, DNS block
  and allow lists, reverse DNS, and the MTA's greylisting, rate limits,
  and access rules. Their scores are in the built-in rules
  (`priv/rules/10-checks.toml`), which `[filter] rules` can change.

  The results come from the MTA, which has checked the mail already in
  its SMTP session, or from `run/3`, which checks a message the filter
  gets from elsewhere. `symbols/1` turns them into symbols for
  `Sovite.Rules.scan/3`.

  ## Symbols

    * SPF of the `MAIL FROM` domain: `R_SPF_ALLOW`, `R_SPF_FAIL`,
      `R_SPF_SOFTFAIL`, `R_SPF_NEUTRAL`, `R_SPF_NA`, `R_SPF_DNSFAIL`,
      `R_SPF_PERMFAIL`.
    * DKIM, one for each kind of result among the signatures:
      `R_DKIM_ALLOW`, `R_DKIM_REJECT`, `R_DKIM_TEMPFAIL`,
      `R_DKIM_PERMFAIL`, or `R_DKIM_NA` without signatures.
    * DMARC: `DMARC_POLICY_ALLOW`, `DMARC_POLICY_REJECT`,
      `DMARC_POLICY_QUARANTINE`, `DMARC_POLICY_SOFTFAIL` (a failure the
      policy asks nothing for), `DMARC_NA`, `DMARC_DNSFAIL`,
      `DMARC_BAD_POLICY`.
    * ARC: `ARC_ALLOW`, `ARC_REJECT`, `ARC_NA`.
    * DNS lists, one symbol per list that lists the client or a domain,
      named after its zone: `RBL_ZEN_SPAMHAUS_ORG` for an IP block list,
      `RWL_LIST_DNSWL_ORG` for an allow list (a negative weight),
      `RHSBL_...` and `RHSWL_...` for domain lists. Their score is the
      list's `weight` in `[screen]`, unless a rule file declares them.
    * Reverse DNS: `RDNS_NONE`, `RDNS_UNCONFIRMED` (names that do not
      resolve back to the client), `RDNS_DNSFAIL`.
    * `GREYLIST_PASSED` (the client came back after it was greylisted),
      `RATELIMITED` (with the limits as options), and `ACCESS_OK` (an
      access rule allowed the client, `HELO` name, sender, or a
      recipient; the kinds as options).
  """

  alias Sovite.Abuse.{DNSBL, ReverseDNS}
  alias Sovite.ARC
  alias Sovite.DKIM.{Body, Verifier}
  alias Sovite.DMARC
  alias Sovite.Message.Headers
  alias Sovite.SPF

  @typedoc """
  Check results. A check that was not done is left out; `dkim: []` is a
  message without signatures.
  """
  @type t :: %{
          optional(:spf) => SPF.Result.t() | nil,
          optional(:dkim) => [Sovite.DKIM.Result.t()] | nil,
          optional(:arc) => ARC.Result.t() | nil,
          optional(:dmarc) => DMARC.Result.t() | {:error, atom()} | nil,
          optional(:dnsbl) => DNSBL.result() | nil,
          optional(:rhsbl) => DNSBL.result() | nil,
          optional(:reverse_dns) => ReverseDNS.result() | nil,
          optional(:greylist) => :passed | nil,
          optional(:rate_limits) => [String.t()],
          optional(:access) => [String.t()]
        }

  @typedoc "A symbol for `Sovite.Rules.scan/3`: name, options, and score if not declared."
  @type symbol :: {String.t(), [String.t()], number()}

  @doc "The symbols of check results."
  @spec symbols(t()) :: [symbol()]
  def symbols(checks) do
    spf(checks[:spf]) ++
      dkim(checks[:dkim]) ++
      dmarc(checks[:dmarc]) ++
      arc(checks[:arc]) ++
      lists(checks[:dnsbl], "RBL_", "RWL_") ++
      lists(checks[:rhsbl], "RHSBL_", "RHSWL_") ++
      reverse_dns(checks[:reverse_dns]) ++
      policies(checks)
  end

  @spf %{
    pass: "R_SPF_ALLOW",
    fail: "R_SPF_FAIL",
    softfail: "R_SPF_SOFTFAIL",
    neutral: "R_SPF_NEUTRAL",
    none: "R_SPF_NA",
    temperror: "R_SPF_DNSFAIL",
    permerror: "R_SPF_PERMFAIL"
  }

  defp spf(nil), do: []

  defp spf(%SPF.Result{} = result) do
    options = Enum.reject([result.domain, result.mechanism], &is_nil/1)
    [{@spf[result.result], options, 0}]
  end

  @dkim %{
    pass: "R_DKIM_ALLOW",
    fail: "R_DKIM_REJECT",
    temperror: "R_DKIM_TEMPFAIL",
    permerror: "R_DKIM_PERMFAIL",
    neutral: "R_DKIM_PERMFAIL"
  }

  @dkim_order ~w(R_DKIM_ALLOW R_DKIM_REJECT R_DKIM_TEMPFAIL R_DKIM_PERMFAIL)

  defp dkim(nil), do: []
  defp dkim([]), do: [{"R_DKIM_NA", [], 0}]

  defp dkim(results) do
    results
    |> Enum.group_by(&@dkim[&1.result], &(&1.domain || ""))
    |> Enum.sort_by(fn {name, _domains} -> Enum.find_index(@dkim_order, &(&1 == name)) end)
    |> Enum.map(fn {name, domains} -> {name, Enum.uniq(domains), 0} end)
  end

  defp dmarc(nil), do: []
  defp dmarc({:error, reason}), do: [{"DMARC_NA", [Atom.to_string(reason)], 0}]

  defp dmarc(%DMARC.Result{} = result) do
    name =
      case result do
        %{result: :pass} -> "DMARC_POLICY_ALLOW"
        %{result: :fail, disposition: :reject} -> "DMARC_POLICY_REJECT"
        %{result: :fail, disposition: :quarantine} -> "DMARC_POLICY_QUARANTINE"
        %{result: :fail} -> "DMARC_POLICY_SOFTFAIL"
        %{result: :none} -> "DMARC_NA"
        %{result: :temperror} -> "DMARC_DNSFAIL"
        %{result: :permerror} -> "DMARC_BAD_POLICY"
      end

    [{name, [result.from_domain], 0}]
  end

  defp arc(nil), do: []
  defp arc(%ARC.Result{cv: :pass, sealers: sealers}), do: [{"ARC_ALLOW", sealers, 0}]
  defp arc(%ARC.Result{cv: :fail, reason: reason}), do: [{"ARC_REJECT", List.wrap(reason), 0}]
  defp arc(%ARC.Result{cv: :none}), do: [{"ARC_NA", [], 0}]

  defp lists(nil, _block, _allow), do: []

  defp lists(%{hits: hits}, block, allow) do
    for hit <- hits do
      prefix = if hit.weight < 0, do: allow, else: block
      {prefix <> zone_name(hit.zone), Enum.map(hit.codes, &ip/1), hit.weight}
    end
    |> Enum.uniq_by(&elem(&1, 0))
  end

  # "zen.spamhaus.org" as "ZEN_SPAMHAUS_ORG": what a symbol name may hold.
  defp zone_name(zone) do
    zone
    |> String.upcase()
    |> String.replace(~r/[^A-Z0-9]+/, "_")
    |> String.trim("_")
    |> String.slice(0, 100)
  end

  defp ip(address), do: address |> :inet.ntoa() |> to_string()

  defp reverse_dns(:none), do: [{"RDNS_NONE", [], 0}]
  defp reverse_dns({:unconfirmed, names}), do: [{"RDNS_UNCONFIRMED", Enum.take(names, 3), 0}]
  defp reverse_dns({:error, :temporary}), do: [{"RDNS_DNSFAIL", [], 0}]
  defp reverse_dns(_result), do: []

  defp policies(checks) do
    Enum.filter(
      [
        checks[:greylist] == :passed && {"GREYLIST_PASSED", [], 0},
        checks[:rate_limits] not in [nil, []] && {"RATELIMITED", checks[:rate_limits], 0},
        checks[:access] not in [nil, []] && {"ACCESS_OK", checks[:access], 0}
      ],
      & &1
    )
  end

  ## Running the checks

  @doc """
  Options for `run/3` from the configuration: the checks `[spf]`,
  `[dkim]`, `[arc]`, and `[dmarc]` verify, and the DNS lists of
  `[screen]`.
  """
  @spec opts(Sovite.Core.Config.t(), Sovite.DNS.resolver()) :: keyword()
  def opts(config, resolver) do
    [
      resolver: resolver,
      hostname: config.server.hostname,
      spf: config.spf.verify,
      dkim: config.dkim.verify,
      arc: config.arc.verify,
      dmarc: config.dmarc.verify,
      dnsbl: config.screen.dnsbl,
      rhsbl: config.screen.rhsbl,
      timeout: config.screen.lookup_timeout
    ]
  end

  @doc """
  Checks a message (header and body) the MTA has not checked: what the
  options turn on, of SPF, DKIM, ARC, DMARC, DNS lists, and reverse
  DNS. `envelope` has the client's `:ip` (a string or a tuple), its
  `:helo` name, and the `:from` address of `MAIL FROM`; checks that need
  one that is missing are not done.

  ## Options

    * `:resolver` - the DNS resolver. Required.
    * `:hostname` - this server's name, for SPF.
    * `:spf`, `:dkim`, `:arc`, `:dmarc`, `:reverse_dns` - booleans:
      which checks to do. Default to `true`.
    * `:dnsbl` - IP lists, `t:Sovite.Abuse.DNSBL.list_spec/0`.
    * `:rhsbl` - domain lists, each also with `:check`, which domains it
      looks up: `:helo`, `:sender` (the `MAIL FROM` domain), or both.
    * `:timeout` - milliseconds for the checks that look up DNS.
      Defaults to 10 seconds; checks that take longer are left out.
  """
  @spec run(binary(), map(), keyword()) :: t()
  def run(message, envelope, opts) do
    resolver = Keyword.fetch!(opts, :resolver)
    timeout = Keyword.get(opts, :timeout, 10_000)
    {fields, body} = split(message)
    on? = &Keyword.get(opts, &1, true)

    client = %{
      ip: parse_ip(envelope[:ip]),
      sender: envelope[:from] || "",
      helo: envelope[:helo],
      resolver: resolver,
      timeout: timeout
    }

    tasks =
      client_tasks(client, opts, on?) ++
        [
          signatures:
            (on?.(:dkim) or on?.(:arc)) && fn -> signatures(fields, body, resolver, opts) end
        ]

    deadline = System.monotonic_time(:millisecond) + timeout
    results = run_all(tasks, timeout)
    {dkim, arc} = Map.get(results, :signatures, {nil, nil})

    checks =
      results
      |> Map.delete(:signatures)
      |> Map.merge(%{dkim: on?.(:dkim) && dkim, arc: on?.(:arc) && arc})

    # DMARC needs SPF and DKIM: it comes last, in the time left.
    left = max(deadline - System.monotonic_time(:millisecond), 0)
    dmarc = on?.(:dmarc) && fn -> dmarc(resolver, fields, checks[:spf], dkim || []) end

    checks
    |> Map.merge(run_all([dmarc: dmarc], left))
    |> Enum.reject(fn {_check, result} -> result in [nil, false] end)
    |> Map.new()
  end

  # The checks of the client: those that need its address, and the
  # domain lists.
  defp client_tasks(%{ip: ip} = client, opts, on?) do
    %{resolver: resolver, sender: sender, helo: helo, timeout: timeout} = client
    lists = Keyword.get(opts, :dnsbl, [])

    [
      spf:
        ip && on?.(:spf) &&
          fn ->
            spf_opts = [receiver: Keyword.get(opts, :hostname, "localhost"), timeout: timeout]
            SPF.check_mail_from(resolver, ip, sender, helo, spf_opts)
          end,
      dnsbl:
        ip && lists != [] && fn -> DNSBL.score(resolver, {:ip, ip}, lists, timeout: timeout) end,
      rhsbl: rhsbl(resolver, Keyword.get(opts, :rhsbl, []), helo, sender, timeout),
      reverse_dns: ip && on?.(:reverse_dns) && fn -> ReverseDNS.check(resolver, ip) end
    ]
  end

  # Each check in its own process; those not done within the timeout are
  # left out.
  defp run_all(tasks, timeout) do
    tasks = for {name, fun} <- tasks, is_function(fun), do: {name, Task.async(fun)}

    tasks
    |> Enum.map(&elem(&1, 1))
    |> Task.yield_many(timeout)
    |> Enum.zip(tasks)
    |> Enum.flat_map(fn
      {{_task, {:ok, result}}, {name, _}} ->
        [{name, result}]

      {{task, nil}, _} ->
        _ = Task.shutdown(task, :brutal_kill)
        []

      {{_task, {:exit, _reason}}, _} ->
        []
    end)
    |> Map.new()
  end

  defp signatures(fields, body, resolver, opts) do
    dkim = Keyword.get(opts, :dkim, true) && Verifier.new(fields)
    arc = Keyword.get(opts, :arc, true) && ARC.new(fields)

    specs =
      Enum.uniq(
        if(dkim, do: Verifier.body_specs(dkim), else: []) ++
          if(arc, do: ARC.body_specs(arc), else: [])
      )

    hashes = specs |> Body.new() |> Body.update(body) |> Body.finish()

    {dkim && Verifier.finish(dkim, hashes, resolver), arc && ARC.finish(arc, hashes, resolver)}
  end

  defp rhsbl(_resolver, [], _helo, _sender, _timeout), do: nil

  defp rhsbl(resolver, lists, helo, sender, timeout) do
    targets =
      Enum.reject(
        [{:helo, helo && String.downcase(helo)}, {:sender, domain(sender)}],
        fn {_check, domain} -> domain in [nil, ""] end
      )

    targets != [] &&
      fn ->
        results =
          for {check, domain} <- targets,
              lists = Enum.filter(lists, &(check in Map.get(&1, :check, [:helo, :sender]))),
              lists != [],
              do: DNSBL.score(resolver, {:domain, domain}, lists, timeout: timeout)

        %{
          score: results |> Enum.map(& &1.score) |> Enum.sum(),
          hits: Enum.flat_map(results, & &1.hits),
          errors: Enum.flat_map(results, & &1.errors)
        }
      end
  end

  defp dmarc(resolver, fields, spf, dkim) do
    case DMARC.from_domain(fields) do
      {:ok, domain} ->
        spf_input = if spf, do: {spf.result, spf.domain}, else: {:none, nil}

        DMARC.check(resolver, domain,
          spf: spf_input,
          dkim: Enum.map(dkim, &{&1.result, &1.domain})
        )

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp split(message) do
    message =
      if Regex.match?(~r/(?<!\r)\n/, message),
        do: Regex.replace(~r/(?<!\r)\n/, message, "\r\n"),
        else: message

    case Headers.split(message) do
      {:ok, header, body} -> {Headers.parse(header), body}
      :more -> {Headers.parse(message <> "\r\n"), ""}
    end
  end

  defp parse_ip(nil), do: nil
  defp parse_ip(ip) when is_tuple(ip), do: ip

  defp parse_ip(text) do
    case Sovite.Net.parse_ip(text) do
      {:ok, ip} -> ip
      {:error, _} -> nil
    end
  end

  defp domain(address) do
    case String.split(address, "@") do
      [_local, domain] when domain != "" -> String.downcase(domain)
      _ -> nil
    end
  end
end
