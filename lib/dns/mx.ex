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

  `resolve/3` also looks up each host's addresses.
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
    case DNS.lookup(resolver, domain, :mx) do
      {:ok, []} ->
        implicit_mx(resolver, domain)

      {:ok, records} ->
        if Enum.any?(records, &null_mx?/1),
          do: {:error, :null_mx},
          else: records |> exclude(opts[:exclude] || []) |> order()

      {:error, :nxdomain} ->
        {:error, :nxdomain}

      {:error, reason} ->
        {:error, {:temporary, reason}}
    end
  end

  # RFC 7505 §3: a domain with a Null MX must not publish other MX
  # records. If it does anyway, the Null MX still wins.
  defp null_mx?({_preference, host}), do: host in ["", "."]

  defp implicit_mx(resolver, domain) do
    case addresses(resolver, domain, [:aaaa, :a]) do
      {:ok, [_ | _]} -> {:ok, [{0, domain}]}
      {:ok, []} -> {:error, :no_hosts}
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

  defp order([]), do: {:error, :loops_back}

  defp order(records) do
    hosts =
      records
      |> Enum.uniq_by(fn {_preference, host} -> normalize(host) end)
      |> Enum.group_by(&elem(&1, 0))
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.flat_map(fn {_preference, group} -> Enum.shuffle(group) end)

    {:ok, hosts}
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
    families = Keyword.get(opts, :families, [:aaaa, :a])

    with {:ok, hosts} <- hosts(resolver, domain, opts) do
      hosts
      |> Enum.map(fn {_preference, host} -> {host, addresses(resolver, host, families)} end)
      |> hosts_with_addresses()
    end
  end

  defp hosts_with_addresses(results) do
    case for({host, {:ok, [_ | _] = ips}} <- results, do: {host, ips}) do
      [_ | _] = found -> {:ok, found}
      [] -> no_addresses(results)
    end
  end

  # A host whose lookup failed might have an address after all.
  defp no_addresses(results) do
    case Enum.find(results, &match?({_, {:error, reason}} when reason != :nxdomain, &1)) do
      {_host, {:error, reason}} -> {:error, {:temporary, reason}}
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
    case Sovite.Validators.parse_address_literal(host) do
      {:ok, ip} ->
        {:ok, [ip]}

      {:error, _} ->
        results = Enum.map(families, &DNS.lookup(resolver, host, &1))
        found = results |> Enum.flat_map(&ok_addresses/1) |> Enum.uniq()
        errors = for {:error, reason} <- results, do: reason

        cond do
          found != [] -> {:ok, found}
          # No address yet, but a failed lookup might have found one.
          temporary = Enum.find(errors, &(&1 != :nxdomain)) -> {:error, temporary}
          Enum.any?(results, &match?({:ok, _}, &1)) -> {:ok, []}
          true -> {:error, :nxdomain}
        end
    end
  end

  defp ok_addresses({:ok, ips}), do: ips
  defp ok_addresses({:error, _}), do: []
end
