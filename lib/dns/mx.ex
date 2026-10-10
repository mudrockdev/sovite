defmodule Sovite.DNS.MX do
  @moduledoc """
  Finds the hosts that accept mail for a domain (RFC 5321 §5.1).

      {:ok, hosts} = Sovite.DNS.MX.resolve(resolver, "example.com")
      #=> [{"mx1.example.com", [{192, 0, 2, 25}, {8193, 3512, 0, 0, 0, 0, 0, 25}]}, ...]

  `hosts/2` looks up the MX records:

    * Hosts are ordered by preference. Hosts with the same preference are
      shuffled, to spread load as the RFC asks.
    * A domain with no MX records but with address records is its own mail
      host (implicit MX).
    * A Null MX (RFC 7505), a single record with exchange `"."`, means the
      domain accepts no mail: `{:error, :null_mx}`.

  `resolve/3` also looks up each host's addresses, and
  `resolve_secure/3` also says for each host whether DNSSEC
  authenticated all of it, as DANE requires (RFC 7672 §2.2).
  """

  alias Sovite.DNS
  alias Sovite.DNS.Resolver

  @typedoc "An MX host and its preference."
  @type mx :: {preference :: non_neg_integer(), host :: String.t()}

  @typedoc """
  Why there are no mail hosts.

    * `:null_mx` - the domain publishes a Null MX. Permanent.
    * `:nxdomain` - the domain does not exist. Permanent.
    * `:no_hosts` - the domain exists but has neither MX nor address
      records. Permanent.
    * `:loops_back` - this server is the best MX host (see `:exclude`).
      Permanent.
    * `:no_addresses` - none of the MX hosts has an address. Permanent.
    * `{:temporary, reason}` - a DNS error; try again later.
  """
  @type error ::
          :null_mx
          | :nxdomain
          | :no_hosts
          | :loops_back
          | :no_addresses
          | {:temporary, Resolver.error()}

  @doc """
  Returns the MX hosts for `domain`, best first.

  ## Options

    * `:exclude` - host names that are this server. If one of them is an
      MX host, it and every host with the same or a worse preference are
      removed (RFC 5321 §5.1), so a backup MX never relays to itself or
      to a worse backup.
  """
  @spec hosts(DNS.resolver(), String.t(), keyword()) :: {:ok, [mx(), ...]} | {:error, error()}
  def hosts(resolver, domain, opts \\ []) do
    with {:ok, hosts, _secure} <- find_hosts(resolver, domain, opts, false), do: {:ok, hosts}
  end

  defp find_hosts(resolver, domain, opts, dnssec) do
    case lookup(resolver, domain, :mx, dnssec) do
      {:ok, [], secure} ->
        implicit_mx(resolver, domain, secure, dnssec)

      {:ok, records, secure} ->
        if Enum.any?(records, &null_mx?/1),
          do: {:error, :null_mx},
          else: records |> exclude(opts[:exclude] || []) |> order(secure)

      {:error, :nxdomain} ->
        {:error, :nxdomain}

      {:error, reason} ->
        {:error, {:temporary, reason}}
    end
  end

  defp lookup(resolver, name, type, true), do: DNS.lookup_secure(resolver, name, type)

  defp lookup(resolver, name, type, false) do
    with {:ok, records} <- DNS.lookup(resolver, name, type), do: {:ok, records, false}
  end

  # RFC 7505 §3: a domain with a Null MX must not publish other MX
  # records. If it does anyway, the Null MX still wins.
  defp null_mx?({_preference, host}), do: host in ["", "."]

  # The host is the domain itself: whether its addresses are secure is
  # checked with the host's own lookups.
  defp implicit_mx(resolver, domain, secure, dnssec) do
    case find_addresses(resolver, domain, [:aaaa, :a], dnssec) do
      {:ok, [_ | _], _addresses_secure} -> {:ok, [{0, domain}], secure}
      {:ok, [], _} -> {:error, :no_hosts}
      {:error, :nxdomain} -> {:error, :nxdomain}
      {:error, reason} -> {:error, {:temporary, reason}}
    end
  end

  defp exclude(records, []), do: records

  defp exclude(records, names) do
    names = MapSet.new(names, &normalize/1)

    case for({preference, host} <- records, normalize(host) in names, do: preference) do
      [] -> records
      ours -> Enum.filter(records, fn {preference, _host} -> preference < Enum.min(ours) end)
    end
  end

  defp normalize(name), do: name |> String.trim_trailing(".") |> String.downcase(:ascii)

  defp order([], _secure), do: {:error, :loops_back}

  defp order(records, secure) do
    hosts =
      records
      |> Enum.uniq_by(fn {_preference, host} -> normalize(host) end)
      |> Enum.group_by(&elem(&1, 0))
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.flat_map(fn {_preference, group} -> Enum.shuffle(group) end)

    {:ok, hosts, secure}
  end

  @doc """
  Returns the mail hosts for `domain` with their addresses, best first.

  Hosts without addresses are left out. If no host has an address, the
  result is `{:error, :no_addresses}`, or `{:error, {:temporary, reason}}`
  if some lookups failed with a DNS error.

  ## Options

    * `:exclude` - see `hosts/3`.
    * `:families` - address types to look up, in order of preference:
      `[:aaaa, :a]` (default), `[:a, :aaaa]`, `[:a]`, or `[:aaaa]`.
  """
  @spec resolve(DNS.resolver(), String.t(), keyword()) ::
          {:ok, [{String.t(), [:inet.ip_address(), ...]}, ...]} | {:error, error()}
  def resolve(resolver, domain, opts \\ []) do
    with {:ok, hosts} <- resolve_secure(resolver, domain, Keyword.put(opts, :dnssec, false)) do
      {:ok, Enum.map(hosts, fn {host, ips, _secure} -> {host, ips} end)}
    end
  end

  @doc """
  Like `resolve/3`, and also says for each host whether DNSSEC
  authenticated its MX records (or, for an implicit MX, the domain's
  missing MX records) and all its address lookups. Only then may DANE
  be used for the host (RFC 7672 §2.2.1, §2.2.2).

  Takes the same options, and `:dnssec`: with `false`, lookups go
  through `Sovite.DNS.lookup/3` and no host is secure. Defaults to
  `true`, for `Sovite.DNS.lookup_secure/3`.
  """
  @spec resolve_secure(DNS.resolver(), String.t(), keyword()) ::
          {:ok, [{String.t(), [:inet.ip_address(), ...], boolean()}, ...]} | {:error, error()}
  def resolve_secure(resolver, domain, opts \\ []) do
    families = Keyword.get(opts, :families, [:aaaa, :a])
    dnssec = Keyword.get(opts, :dnssec, true)

    with {:ok, hosts, mx_secure} <- find_hosts(resolver, domain, opts, dnssec) do
      hosts
      |> Enum.map(fn {_preference, host} ->
        {host, find_addresses(resolver, host, families, dnssec), mx_secure}
      end)
      |> hosts_with_addresses()
    end
  end

  defp hosts_with_addresses(results) do
    found =
      for {host, {:ok, [_ | _] = ips, secure}, mx_secure} <- results,
          do: {host, ips, secure and mx_secure}

    case found do
      [_ | _] = found -> {:ok, found}
      [] -> no_addresses(results)
    end
  end

  # A host whose lookup failed might have an address after all.
  defp no_addresses(results) do
    case Enum.find(results, &match?({_, {:error, reason}, _} when reason != :nxdomain, &1)) do
      {_host, {:error, reason}, _} -> {:error, {:temporary, reason}}
      nil -> {:error, :no_addresses}
    end
  end

  @doc """
  Looks up the addresses of `host` for each record type in `families`,
  and returns them in that order. An address literal such as
  `"[192.0.2.1]"` is returned as is, without a lookup.

  Returns the addresses found, even if another lookup failed, so a host
  with only IPv4 addresses gives `{:ok, ipv4s}`. Without any address, a
  DNS error other than NXDOMAIN is returned, since a retry might find
  one; otherwise `{:ok, []}` (NODATA) or `{:error, :nxdomain}`.
  """
  @spec addresses(DNS.resolver(), String.t(), [:a | :aaaa]) ::
          {:ok, [:inet.ip_address()]} | {:error, Resolver.error()}
  def addresses(resolver, host, families \\ [:aaaa, :a]) do
    with {:ok, ips, _secure} <- find_addresses(resolver, host, families, false), do: {:ok, ips}
  end

  @doc """
  Like `addresses/3`, through `Sovite.DNS.lookup_secure/3`, and also
  says whether DNSSEC authenticated every lookup that answered. Address
  literals are never secure.
  """
  @spec secure_addresses(DNS.resolver(), String.t(), [:a | :aaaa]) ::
          {:ok, [:inet.ip_address()], boolean()} | {:error, Resolver.error()}
  def secure_addresses(resolver, host, families \\ [:aaaa, :a]),
    do: find_addresses(resolver, host, families, true)

  defp find_addresses(resolver, host, families, dnssec) do
    case Sovite.Validators.parse_address_literal(host) do
      {:ok, ip} ->
        {:ok, [ip], false}

      {:error, _} ->
        families |> Enum.map(&lookup(resolver, host, &1, dnssec)) |> combine()
    end
  end

  defp combine(results) do
    found = results |> Enum.flat_map(&ok_addresses/1) |> Enum.uniq()
    errors = for {:error, reason} <- results, do: reason
    answered = for {:ok, _ips, secure} <- results, do: secure
    secure = answered != [] and Enum.all?(answered)

    cond do
      found != [] -> {:ok, found, secure}
      # No address yet, but a failed lookup might have found one.
      temporary = Enum.find(errors, &(&1 != :nxdomain)) -> {:error, temporary}
      answered != [] -> {:ok, [], secure}
      true -> {:error, :nxdomain}
    end
  end

  defp ok_addresses({:ok, ips, _secure}), do: ips
  defp ok_addresses({:error, _}), do: []
end
