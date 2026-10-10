defmodule Sovite.Abuse.ReverseDNS do
  @moduledoc """
  Reverse DNS of a client address, and whether the forward lookup of the
  name confirms it (forward-confirmed reverse DNS, FCrDNS).

      ReverseDNS.check(resolver, {192, 0, 2, 1})
      #=> {:ok, "mail.example.com"}

  `check/3` looks up the PTR names of the address, then the addresses of
  each name: A records for an IPv4 client, AAAA for IPv6. The first name
  with the client's address among them is the confirmed hostname. Names
  are lower-cased, and names that are not valid domains are skipped.
  IPv4-mapped IPv6 addresses are checked as IPv4.

  ## Options

    * `:max_names` - how many PTR names to check. Defaults to 10, the
      limit RFC 7208 §4.6.4 sets for SPF's `ptr`.
  """

  alias Sovite.Abuse.DNSBL
  alias Sovite.DNS

  @typedoc """
  The result of `check/3`:

    * `{:ok, hostname}` - a PTR name whose addresses include the client.
    * `{:unconfirmed, names}` - PTR names, none of which confirms it.
    * `:none` - no PTR records, or none that is a valid domain name.
    * `{:error, :temporary}` - a DNS error; a retry might confirm a name.
  """
  @type result ::
          {:ok, String.t()} | {:unconfirmed, [String.t()]} | :none | {:error, :temporary}

  @doc """
  Returns the PTR name of `ip`, in `in-addr.arpa` or `ip6.arpa`.

      iex> Sovite.Abuse.ReverseDNS.reverse_name({192, 0, 2, 1})
      "1.2.0.192.in-addr.arpa"
  """
  @spec reverse_name(:inet.ip_address()) :: String.t()
  def reverse_name(ip) do
    # An IP list query (RFC 5782 §2.1, §2.4) is built like a PTR name.
    case Sovite.Net.normalize(ip) do
      {_, _, _, _} = ip -> DNSBL.query_name(ip, "in-addr.arpa")
      ip -> DNSBL.query_name(ip, "ip6.arpa")
    end
  end

  @doc "Looks up the reverse DNS of `ip` and confirms it. See the module documentation."
  @spec check(DNS.resolver(), :inet.ip_address(), keyword()) :: result()
  def check(resolver, ip, opts \\ []) do
    ip = Sovite.Net.normalize(ip)

    case DNS.lookup(resolver, reverse_name(ip), :ptr) do
      {:ok, names} -> names |> valid_names(opts) |> confirm(resolver, ip)
      {:error, :nxdomain} -> :none
      {:error, _reason} -> {:error, :temporary}
    end
  end

  defp valid_names(names, opts) do
    names
    |> Enum.map(&(&1 |> String.trim_trailing(".") |> String.downcase(:ascii)))
    |> Enum.filter(&Sovite.Validators.domain?/1)
    |> Enum.uniq()
    |> Enum.take(Keyword.get(opts, :max_names, 10))
  end

  defp confirm([], _resolver, _ip), do: :none

  defp confirm(names, resolver, ip) do
    type = if tuple_size(ip) == 4, do: :a, else: :aaaa

    Enum.reduce_while(names, {:unconfirmed, names}, fn name, acc ->
      case forward(resolver, name, type, ip) do
        :confirmed -> {:halt, {:ok, name}}
        :unconfirmed -> {:cont, acc}
        # A later name may still confirm.
        :error -> {:cont, {:error, :temporary}}
      end
    end)
  end

  defp forward(resolver, name, type, ip) do
    case DNS.lookup(resolver, name, type) do
      {:ok, addresses} -> if ip in addresses, do: :confirmed, else: :unconfirmed
      {:error, :nxdomain} -> :unconfirmed
      {:error, _reason} -> :error
    end
  end
end
