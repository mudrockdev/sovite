defmodule Sovite.DMARC do
  @moduledoc """
  DMARC (RFC 7489): checks that the domain in a message's `From:` field
  is the one SPF or DKIM authenticated, and finds what its owner asks
  receivers to do with mail that fails.

      {:ok, domain} = Sovite.DMARC.from_domain(fields)

      result =
        Sovite.DMARC.check(resolver, domain,
          spf: {:pass, "bounces.example.com"},
          dkim: [{:pass, "example.com"}]
        )

      result.result       #=> :pass
      result.disposition  #=> :none

  Policies are found with the DMARCbis DNS tree walk instead of the
  Public Suffix List (`discover/2`): `_dmarc.<domain>` is queried for
  the From domain and then for its parents. The same walk gives the
  Organizational Domain used for relaxed alignment (`org_domain/2`).

  Aggregate reports are built by `Sovite.DMARC.Report`.
  """

  alias Sovite.DMARC.{Policy, Record, Result}
  alias Sovite.DNS
  alias Sovite.Message.{AddressList, Headers}

  # Org domains already looked up during one check, by domain.
  @typep cache :: %{String.t() => String.t()}

  @doc """
  Finds the DMARC policy for `domain` (DMARCbis DNS tree walk).

  `_dmarc.<domain>` is queried first. Without a single valid record
  there, the walk continues with the parents of `domain`, removing one
  label at a time, but jumps straight to the last 7 labels of a domain
  with more than 8, and stops before the top-level domain. Records that
  do not start with `v=DMARC1` are ignored, and a level with more than
  one DMARC record counts as having none. The first record found is the
  policy.

  Returns `{:none, org_domain}` without a policy, and
  `{:error, :temperror}` if a query fails with a DNS error other than
  NXDOMAIN.
  """
  @spec discover(DNS.resolver(), String.t()) ::
          {:ok, Policy.t()} | {:none, org_domain :: String.t()} | {:error, :temperror}
  def discover(resolver, domain) do
    domain = normalize(domain)

    with {:ok, found} <- walk(resolver, domain) do
      org_domain = org_from(domain, found)

      case found do
        [{at, record} | _] -> {:ok, %Policy{record: record, domain: at, org_domain: org_domain}}
        [] -> {:none, org_domain}
      end
    end
  end

  @doc """
  Finds the Organizational Domain of `domain` (DMARCbis §4.10.2), with
  the same tree walk as `discover/2`:

    * A record with `psd=n` makes the domain it is at the Organizational
      Domain.
    * A record with `psd=y` marks a public suffix: the Organizational
      Domain is one label longer (or `domain` itself, if the record is
      at `domain`).
    * Otherwise it is the domain with the fewest labels that has a
      record, or `domain` itself if none does.
  """
  @spec org_domain(DNS.resolver(), String.t()) :: {:ok, String.t()} | {:error, :temperror}
  def org_domain(resolver, domain) do
    domain = normalize(domain)
    with {:ok, found} <- walk(resolver, domain), do: {:ok, org_from(domain, found)}
  end

  # The records on the way up, closest first. The walk stops at a record
  # with psd=y or psd=n, which settles the org domain.
  defp walk(resolver, domain) do
    domain
    |> targets()
    |> Enum.reduce_while({:ok, []}, fn target, {:ok, found} ->
      case record_at(resolver, target) do
        {:ok, %Record{psd: nil} = record} -> {:cont, {:ok, [{target, record} | found]}}
        {:ok, record} -> {:halt, {:ok, [{target, record} | found]}}
        :none -> {:cont, {:ok, found}}
        {:error, :temperror} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, found} -> {:ok, Enum.reverse(found)}
      error -> error
    end
  end

  defp targets(domain) do
    labels = String.split(domain, ".")
    count = length(labels)
    shorter = for n <- min(count - 1, 7)..2//-1, do: labels |> Enum.take(-n) |> Enum.join(".")
    [domain | shorter]
  end

  defp record_at(resolver, domain) do
    case DNS.lookup(resolver, "_dmarc." <> domain, :txt) do
      {:ok, texts} ->
        with [text] <- Enum.filter(texts, &Record.dmarc?/1),
             {:ok, record} <- Record.parse(text) do
          {:ok, record}
        else
          _ -> :none
        end

      {:error, :nxdomain} ->
        :none

      {:error, _} ->
        {:error, :temperror}
    end
  end

  defp org_from(domain, found) do
    case List.last(found) do
      nil -> domain
      {^domain, %Record{psd: :yes}} -> domain
      {at, %Record{psd: :yes}} -> suffix(domain, label_count(at) + 1)
      {at, _record} -> at
    end
  end

  defp suffix(domain, n), do: domain |> String.split(".") |> Enum.take(-n) |> Enum.join(".")

  defp label_count(domain), do: domain |> String.split(".") |> length()

  @doc """
  Returns whether domains `a` and `b` are aligned (RFC 7489 §3.1):
  `:strict` needs the same domain, `:relaxed` the same Organizational
  Domain. Case and a trailing dot do not matter.
  """
  @spec aligned?(DNS.resolver(), :strict | :relaxed, String.t(), String.t()) ::
          {:ok, boolean()} | {:error, :temperror}
  def aligned?(resolver, mode, a, b) do
    {result, _cache} = align(resolver, mode, a, b, %{})
    result
  end

  @spec align(DNS.resolver(), :strict | :relaxed, String.t(), String.t(), cache()) ::
          {{:ok, boolean()} | {:error, :temperror}, cache()}
  defp align(resolver, mode, a, b, cache) do
    a = normalize(a)
    b = normalize(b)

    cond do
      a == b -> {{:ok, true}, cache}
      mode == :strict -> {{:ok, false}, cache}
      # An org domain is a parent of its domain, so these cannot share one.
      top_label(a) != top_label(b) -> {{:ok, false}, cache}
      true -> same_org(resolver, a, b, cache)
    end
  end

  defp same_org(resolver, a, b, cache) do
    with {{:ok, org_a}, cache} <- cached_org(resolver, a, cache),
         {{:ok, org_b}, cache} <- cached_org(resolver, b, cache) do
      {{:ok, org_a == org_b}, cache}
    end
  end

  defp cached_org(resolver, domain, cache) do
    case Map.fetch(cache, domain) do
      {:ok, org} ->
        {{:ok, org}, cache}

      :error ->
        case org_domain(resolver, domain) do
          {:ok, org} -> {{:ok, org}, Map.put(cache, domain, org)}
          error -> {error, cache}
        end
    end
  end

  defp top_label(domain), do: domain |> String.split(".") |> List.last()

  @doc """
  Evaluates DMARC for a message from `from_domain` (RFC 7489 §6.6).

  SPF counts if it passed for a domain aligned with `from_domain` under
  the policy's `aspf`, and DKIM if any passing signature's `d=` is
  aligned under `adkim`. Either one makes the result `:pass`.

  When the result is `:fail`, the disposition comes from `np` if the
  policy was found at a parent and `from_domain` does not exist (its A,
  AAAA, and MX lookups all return NXDOMAIN), from `sp` if the policy
  was found at a parent, and from `p` otherwise. Unless the message is
  sampled (see `Sovite.DMARC.Result`), the disposition is lowered one
  step: `:reject` to `:quarantine`, `:quarantine` to `:none`.

  ## Options

    * `:spf` - `{result, domain}`: the SPF result (`:pass`, `:fail`, ...)
      and the domain it was checked for (MAIL FROM, or HELO for the null
      sender), or `nil`. Defaults to `{:none, nil}`.
    * `:dkim` - the DKIM results, `[{result, d_domain}]`. Only `:pass`
      counts. Defaults to `[]`.
    * `:random` - a function returning a float in `[0, 1)`, used for
      `pct=` sampling. Defaults to `:rand.uniform/0`.
  """
  @spec check(DNS.resolver(), String.t(), keyword()) :: Result.t()
  def check(resolver, from_domain, opts \\ []) do
    from = normalize(from_domain)

    if Sovite.Validators.domain?(from) do
      case discover(resolver, from) do
        {:ok, policy} ->
          evaluate(resolver, from, policy, opts)

        {:none, _org_domain} ->
          %Result{result: :none, from_domain: from, reason: "no DMARC policy"}

        {:error, :temperror} ->
          %Result{result: :temperror, from_domain: from, reason: "DNS error finding the policy"}
      end
    else
      %Result{result: :permerror, from_domain: from, reason: "invalid From domain"}
    end
  end

  defp evaluate(resolver, from, %Policy{record: record} = policy, opts) do
    {spf_result, spf_domain} = Keyword.get(opts, :spf, {:none, nil})
    cache = %{from => policy.org_domain}

    with {{:ok, spf_aligned}, cache} <-
           spf_aligned(resolver, record.aspf, spf_result, spf_domain, from, cache),
         {{:ok, dkim_domain}, _cache} <-
           dkim_aligned(resolver, record.adkim, Keyword.get(opts, :dkim, []), from, cache) do
      result = %Result{
        result: :pass,
        from_domain: from,
        policy: policy,
        spf_aligned: spf_aligned,
        dkim_aligned: dkim_domain != nil,
        dkim_domain: dkim_domain
      }

      if spf_aligned or dkim_domain != nil,
        do: result,
        else: fail(resolver, from, policy, result, opts)
    else
      {{:error, :temperror}, _cache} ->
        %Result{
          result: :temperror,
          from_domain: from,
          policy: policy,
          reason: "DNS error checking alignment"
        }
    end
  end

  defp spf_aligned(resolver, mode, :pass, domain, from, cache) when is_binary(domain),
    do: align(resolver, mode, domain, from, cache)

  defp spf_aligned(_resolver, _mode, _result, _domain, _from, cache), do: {{:ok, false}, cache}

  # The d= of the first passing, aligned signature, or nil.
  defp dkim_aligned(resolver, mode, signatures, from, cache) do
    Enum.reduce_while(signatures, {{:ok, nil}, cache}, fn
      {:pass, domain}, {_none, cache} when is_binary(domain) ->
        case align(resolver, mode, domain, from, cache) do
          {{:ok, true}, cache} -> {:halt, {{:ok, normalize(domain)}, cache}}
          {{:ok, false}, cache} -> {:cont, {{:ok, nil}, cache}}
          error -> {:halt, error}
        end

      _signature, acc ->
        {:cont, acc}
    end)
  end

  defp fail(resolver, from, policy, result, opts) do
    applied = applied(resolver, from, policy)
    record = policy.record
    {disposition, sampled, reason} = sample(record, Map.fetch!(record, applied), opts)

    %{
      result
      | result: :fail,
        disposition: disposition,
        applied: applied,
        sampled: sampled,
        reason: reason
    }
  end

  defp applied(_resolver, from, %Policy{domain: from}), do: :p
  defp applied(resolver, from, _policy), do: if(exists?(resolver, from), do: :sp, else: :np)

  # DMARCbis: a domain is non-existent if it has no A, AAAA, or MX
  # records because the name itself is not in the DNS. A DNS error
  # counts as existing.
  defp exists?(resolver, domain),
    do:
      not Enum.all?([:a, :aaaa, :mx], &(DNS.lookup(resolver, domain, &1) == {:error, :nxdomain}))

  defp sample(%Record{testing: true}, disposition, _opts),
    do: {downgrade(disposition), false, "testing mode (t=y)"}

  defp sample(%Record{pct: 100}, disposition, _opts), do: {disposition, true, nil}

  defp sample(%Record{pct: pct}, disposition, opts) do
    random = Keyword.get(opts, :random, &:rand.uniform/0)

    if random.() * 100 < pct,
      do: {disposition, true, nil},
      else: {downgrade(disposition), false, "sampled out (pct=#{pct})"}
  end

  defp downgrade(:reject), do: :quarantine
  defp downgrade(_disposition), do: :none

  @doc """
  Returns the RFC5322.From domain of a message, from its header fields
  as parsed by `Sovite.Message.Headers.parse/1`.

  Fails with `:missing` without a `From:` field, with `:multiple` if
  there are several `From:` fields or the mailboxes in it have different
  domains (several mailboxes with the same domain are fine, as DMARCbis
  allows), and with `:invalid` if no domain can be read from it.
  """
  @spec from_domain([Headers.field()]) ::
          {:ok, String.t()} | {:error, :missing | :multiple | :invalid}
  def from_domain(fields) do
    case for({"from", raw} <- fields, do: raw) do
      [] -> {:error, :missing}
      [raw] -> raw |> :binary.split(":") |> List.last() |> mailbox_domain()
      _ -> {:error, :multiple}
    end
  end

  defp mailbox_domain(value) do
    with {:ok, [_ | _] = addresses} <- AddressList.addresses(value),
         domains = Enum.map(addresses, &address_domain/1),
         false <- Enum.member?(domains, :error) do
      case Enum.uniq(domains) do
        [domain] -> {:ok, domain}
        _ -> {:error, :multiple}
      end
    else
      _ -> {:error, :invalid}
    end
  end

  defp address_domain(address) do
    domain = address |> String.split("@") |> List.last() |> normalize()
    if Sovite.Validators.domain?(domain), do: domain, else: :error
  end

  @doc """
  Returns whether `rua_domain` accepts reports about `policy_domain`
  (RFC 7489 §7.1): always if both have the same Organizational Domain,
  and otherwise if `<policy_domain>._report._dmarc.<rua_domain>` has a
  TXT record starting with `v=DMARC1`.
  """
  @spec report_authorized?(DNS.resolver(), String.t(), String.t()) ::
          {:ok, boolean()} | {:error, :temperror}
  def report_authorized?(resolver, policy_domain, rua_domain) do
    policy_domain = normalize(policy_domain)
    rua_domain = normalize(rua_domain)

    case aligned?(resolver, :relaxed, policy_domain, rua_domain) do
      {:ok, true} ->
        {:ok, true}

      {:ok, false} ->
        case DNS.lookup(resolver, "#{policy_domain}._report._dmarc.#{rua_domain}", :txt) do
          {:ok, texts} -> {:ok, Enum.any?(texts, &Record.dmarc?/1)}
          {:error, :nxdomain} -> {:ok, false}
          {:error, _} -> {:error, :temperror}
        end

      error ->
        error
    end
  end

  defp normalize(domain), do: domain |> String.trim_trailing(".") |> String.downcase(:ascii)
end
