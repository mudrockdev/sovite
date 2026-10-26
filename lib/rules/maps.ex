defmodule Sovite.Rules.Maps do
  @moduledoc """
  Maps: lists that rules look values up in, of one type each.

    * `ip` - IP addresses and networks (`192.0.2.1`, `2001:db8::/32`).
    * `domain` - domains, matching their subdomains too: `example.com`
      matches `mail.example.com`. A mail address is looked up by its
      domain.
    * `address` - mail addresses, or `@domain` for every address at a
      domain. Compared case-insensitively.
    * `string` - any other values (hashes, HELO names, ...), compared
      case-insensitively.

  A map's text has one entry per line; anything after `#` and after the
  first white space of a line is ignored.

      iex> {map, []} = Sovite.Rules.Maps.parse(:domain, "example.com  # ours\\nexample.net\\n")
      iex> Sovite.Rules.Maps.member?(map, "mail.Example.COM")
      true
      iex> Sovite.Rules.Maps.member?(map, "example.org")
      false
  """

  import Bitwise

  alias Sovite.IDNA

  @type type :: :ip | :domain | :address | :string
  @opaque t :: {type(), term()}

  @types %{"ip" => :ip, "domain" => :domain, "address" => :address, "string" => :string}

  @doc "The type named `name` (`\"ip\"`, ...), or `:error`."
  @spec type(String.t()) :: {:ok, type()} | :error
  def type(name), do: Map.fetch(@types, name)

  @doc "The names of the types."
  @spec types() :: [String.t()]
  def types, do: Map.keys(@types)

  @doc """
  Parses a map's text. Returns the map, with the entries that are not
  valid left out, and those as `{line, reason}`.
  """
  @spec parse(type(), String.t()) :: {t(), [{pos_integer(), String.t()}]}
  def parse(type, text) when is_binary(text) do
    text
    |> String.replace_invalid()
    |> String.split(["\r\n", "\n"])
    |> Enum.with_index(1)
    |> Enum.map(fn {line, number} -> {entry(line), number} end)
    |> Enum.reject(fn {entry, _number} -> entry == "" end)
    |> numbered(type)
  end

  @doc "A map of `entries`; the invalid ones are left out and returned as `{index, reason}`."
  @spec new(type(), [String.t()]) :: {t(), [{pos_integer(), String.t()}]}
  def new(type, entries) when is_list(entries), do: numbered(Enum.with_index(entries, 1), type)

  defp numbered(entries, type) do
    {keys, errors} =
      Enum.reduce(entries, {[], []}, fn {entry, number}, {keys, errors} ->
        case key(type, entry) do
          {:ok, key} -> {[key | keys], errors}
          {:error, reason} -> {keys, [{number, "#{inspect(entry)}: #{reason}"} | errors]}
        end
      end)

    {build(type, keys), Enum.reverse(errors)}
  end

  defp entry(line) do
    line
    |> String.split("#", parts: 2)
    |> hd()
    |> String.trim()
    |> String.split(~r/\s/, parts: 2)
    |> hd()
  end

  @doc "How many entries a map has."
  @spec size(t()) :: non_neg_integer()
  def size({:ip, %{size: size}}), do: size
  def size({_type, set}), do: MapSet.size(set)

  @doc "Whether `value` is in the map."
  @spec member?(t(), String.t()) :: boolean()
  def member?({:ip, networks}, value) do
    case ip(value) do
      {:ok, family, n, _bits} ->
        Enum.any?(networks[family], fn {length, set} ->
          MapSet.member?(set, mask(n, family, length))
        end)

      :error ->
        false
    end
  end

  def member?({:domain, set}, value) do
    domain = value |> String.split("@") |> List.last()

    case normalize_domain(domain) do
      {:ok, domain} -> domain |> parents() |> Enum.any?(&MapSet.member?(set, &1))
      :error -> false
    end
  end

  def member?({:address, set}, value) do
    case address(value) do
      {:ok, address} ->
        [_local, domain] = String.split(address, "@", parts: 2)
        MapSet.member?(set, address) or MapSet.member?(set, "@" <> domain)

      :error ->
        false
    end
  end

  def member?({:string, set}, value), do: MapSet.member?(set, String.downcase(value))

  # Keys.

  defp key(:ip, entry) do
    {address, length} =
      case String.split(entry, "/", parts: 2) do
        [address, length] -> {address, Integer.parse(length)}
        [address] -> {address, nil}
      end

    with {:ok, family, n, bits} <- ip(address),
         {:ok, length} <- prefix(length, bits),
         true <- mask(n, family, length) == n || {:error, "host bits set"} do
      {:ok, {family, length, n}}
    else
      :error -> {:error, "not an IP address or network"}
      {:error, reason} -> {:error, reason}
    end
  end

  defp key(:domain, entry) do
    case normalize_domain(String.trim_leading(String.trim_leading(entry, "*"), ".")) do
      {:ok, domain} -> {:ok, domain}
      :error -> {:error, "not a domain"}
    end
  end

  defp key(:address, "@" <> domain) do
    case normalize_domain(domain) do
      {:ok, domain} -> {:ok, "@" <> domain}
      :error -> {:error, "not a domain"}
    end
  end

  defp key(:address, entry) do
    case address(entry) do
      {:ok, address} -> {:ok, address}
      :error -> {:error, "not a mail address"}
    end
  end

  defp key(:string, entry), do: {:ok, String.downcase(entry)}

  defp prefix(nil, bits), do: {:ok, bits}
  defp prefix({length, ""}, bits) when length >= 0 and length <= bits, do: {:ok, length}
  defp prefix(_length, _bits), do: {:error, "bad prefix length"}

  defp build(:ip, keys) do
    networks =
      for family <- [:inet, :inet6], into: %{} do
        sets =
          for({^family, length, n} <- keys, do: {length, n})
          |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
          |> Enum.map(fn {length, ns} -> {length, MapSet.new(ns)} end)
          |> Enum.sort_by(&elem(&1, 0), :desc)

        {family, sets}
      end

    {:ip, Map.put(networks, :size, keys |> Enum.uniq() |> length())}
  end

  defp build(type, keys), do: {type, MapSet.new(keys)}

  # Values.

  defp ip(text) do
    case :inet.parse_strict_address(String.to_charlist(text)) do
      {:ok, {0, 0, 0, 0, 0, 0xFFFF, high, low}} ->
        {:ok, :inet, high <<< 16 ||| low, 32}

      {:ok, {a, b, c, d}} ->
        {:ok, :inet, a <<< 24 ||| b <<< 16 ||| c <<< 8 ||| d, 32}

      {:ok, ip} ->
        {:ok, :inet6, ip |> Tuple.to_list() |> Enum.reduce(0, &(&2 <<< 16 ||| &1)), 128}

      {:error, _} ->
        :error
    end
  end

  defp mask(n, family, length) do
    bits = if family == :inet, do: 32, else: 128
    n &&& bnot((1 <<< (bits - length)) - 1)
  end

  defp normalize_domain(domain) do
    domain = domain |> String.trim_trailing(".") |> String.downcase()

    cond do
      domain == "" ->
        :error

      domain =~ ~r/\A[a-z0-9_]([a-z0-9_\-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_\-]*[a-z0-9_])?)*\z/ ->
        {:ok, domain}

      true ->
        idna(domain)
    end
  end

  defp idna(domain) do
    case IDNA.to_ascii(domain) do
      {:ok, ascii} -> {:ok, ascii}
      {:error, _} -> :error
    end
  end

  defp address(value) do
    with [local, domain] when local != "" <- String.split(value, "@", parts: 2),
         {:ok, domain} <- normalize_domain(domain) do
      {:ok, String.downcase(local) <> "@" <> domain}
    else
      _ -> :error
    end
  end

  # "a.b.example" and the domains above it.
  defp parents(domain) do
    labels = String.split(domain, ".")
    for n <- 0..(length(labels) - 1), do: labels |> Enum.drop(n) |> Enum.join(".")
  end
end
