defmodule Sovite.Net do
  @moduledoc """
  IP address and CIDR network helpers.

  All functions are pure and never raise on bad input. Addresses are
  `:inet` tuples. A network is `{address, prefix_length}`.
  """

  import Bitwise

  @type network :: {:inet.ip_address(), 0..128}

  @doc """
  Parses an IP address string.

      iex> Sovite.Net.parse_ip("192.0.2.1")
      {:ok, {192, 0, 2, 1}}
      iex> Sovite.Net.parse_ip("2001:db8::1")
      {:ok, {8193, 3512, 0, 0, 0, 0, 0, 1}}
      iex> Sovite.Net.parse_ip("192.0.2")
      {:error, :invalid_ip}
  """
  @spec parse_ip(term()) :: {:ok, :inet.ip_address()} | {:error, :invalid_ip}
  def parse_ip(string) when is_binary(string) and byte_size(string) in 2..45 do
    # The strict parser rejects shorthand like "10.1" and zone IDs need a
    # charlist, so only pass it plausible characters.
    if String.match?(string, ~r/\A[0-9A-Fa-f:.]+\z/) do
      case :inet.parse_strict_address(String.to_charlist(string)) do
        {:ok, ip} -> {:ok, ip}
        {:error, _} -> {:error, :invalid_ip}
      end
    else
      {:error, :invalid_ip}
    end
  end

  def parse_ip(_), do: {:error, :invalid_ip}

  @doc """
  Parses a network in CIDR notation. A bare address is a single-host
  network. Addresses with bits set past the prefix are rejected, since
  they are usually typos.

      iex> Sovite.Net.parse_cidr("192.0.2.0/24")
      {:ok, {{192, 0, 2, 0}, 24}}
      iex> Sovite.Net.parse_cidr("::1")
      {:ok, {{0, 0, 0, 0, 0, 0, 0, 1}, 128}}
      iex> Sovite.Net.parse_cidr("192.0.2.1/24")
      {:error, :host_bits_set}
  """
  @spec parse_cidr(term()) :: {:ok, network()} | {:error, :invalid_cidr | :host_bits_set}
  def parse_cidr(string) when is_binary(string) do
    with [address | prefix] when length(prefix) <= 1 <- String.split(string, "/"),
         {:ok, ip} <- parse_ip(address),
         {:ok, length} <- parse_prefix(prefix, bits(ip)) do
      if mask(ip, length) == ip, do: {:ok, {ip, length}}, else: {:error, :host_bits_set}
    else
      _ -> {:error, :invalid_cidr}
    end
  end

  def parse_cidr(_), do: {:error, :invalid_cidr}

  @doc """
  Returns `true` if `ip` is in `network`. IPv4-mapped IPv6 addresses
  match IPv4 networks.

      iex> Sovite.Net.in_network?({192, 0, 2, 7}, {{192, 0, 2, 0}, 24})
      true
      iex> Sovite.Net.in_network?({0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0207}, {{192, 0, 2, 0}, 24})
      true
  """
  @spec in_network?(:inet.ip_address(), network()) :: boolean()
  def in_network?(ip, {network, length}) do
    ip = normalize(ip)
    tuple_size(ip) == tuple_size(network) and mask(ip, length) == network
  end

  @doc "Returns `true` if `ip` is in any of `networks`."
  @spec in_networks?(:inet.ip_address(), [network()]) :: boolean()
  def in_networks?(ip, networks), do: Enum.any?(networks, &in_network?(ip, &1))

  @doc """
  Converts an IPv4-mapped IPv6 address (`::ffff:192.0.2.1`), as seen on
  dual-stack sockets, to its IPv4 address. Other addresses are returned
  unchanged.
  """
  @spec normalize(:inet.ip_address()) :: :inet.ip_address()
  def normalize({0, 0, 0, 0, 0, 0xFFFF, high, low}),
    do: {high >>> 8, high &&& 0xFF, low >>> 8, low &&& 0xFF}

  def normalize(ip), do: ip

  @doc """
  Formats a network as a CIDR string.

      iex> Sovite.Net.format_cidr({{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32})
      "2001:db8::/32"
  """
  @spec format_cidr(network()) :: String.t()
  def format_cidr({ip, length}), do: "#{:inet.ntoa(ip)}/#{length}"

  defp parse_prefix([], bits), do: {:ok, bits}

  # Plain decimal only: no sign, no leading zeros.
  defp parse_prefix([prefix], bits) do
    with true <- String.match?(prefix, ~r/\A(0|[1-9][0-9]{0,2})\z/),
         length when length <= bits <- String.to_integer(prefix) do
      {:ok, length}
    else
      _ -> :error
    end
  end

  defp bits(ip) when tuple_size(ip) == 4, do: 32
  defp bits(_ip), do: 128

  defp mask(ip, length) do
    {size, total} = if tuple_size(ip) == 4, do: {8, 32}, else: {16, 128}
    value = ip |> Tuple.to_list() |> Enum.reduce(0, &(&2 <<< size ||| &1))
    masked = value &&& bnot((1 <<< (total - length)) - 1)
    bits = <<masked::size(total)>>
    List.to_tuple(for <<part::size(^size) <- bits>>, do: part)
  end
end
