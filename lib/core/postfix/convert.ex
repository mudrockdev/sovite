defmodule Sovite.Core.Postfix.Convert do
  @moduledoc false
  # Converts Postfix values (times, sizes, networks, TLS protocols,
  # addresses) to what Sovite's config and tables accept.

  import Bitwise

  alias Sovite.Validators

  @doc """
  A Postfix time (`300s`, `5d`, `2w`, or a bare number in `unit`) as a
  Sovite duration. Returns `:zero` for 0.
  """
  @spec duration(String.t(), String.t()) :: {:ok, String.t()} | :zero | :error
  def duration(value, unit) do
    case Regex.run(~r/\A(\d+)\s*(ms|s|m|h|d|w)?\z/, String.trim(value)) do
      [_, amount | rest] ->
        amount = String.to_integer(amount)
        unit = List.first(rest) || unit

        cond do
          amount == 0 -> :zero
          unit == "w" -> fits("#{amount * 7}d", amount * 7)
          true -> fits("#{amount}#{unit}", amount)
        end

      nil ->
        :error
    end
  end

  # Sovite durations have at most 9 digits.
  defp fits(text, amount) when amount < 1_000_000_000, do: {:ok, text}
  defp fits(_text, _amount), do: :error

  @doc "A Sovite duration in milliseconds."
  @spec milliseconds(String.t()) :: non_neg_integer()
  def milliseconds(duration) do
    [_, amount, unit] = Regex.run(~r/\A(\d+)(ms|s|m|h|d)\z/, duration)

    String.to_integer(amount) *
      case unit do
        "ms" -> 1
        "s" -> 1000
        "m" -> 60_000
        "h" -> 3_600_000
        "d" -> 86_400_000
      end
  end

  @doc "A non-negative integer."
  @spec integer(String.t()) :: {:ok, non_neg_integer()} | :error
  def integer(value) do
    case Integer.parse(String.trim(value)) do
      {number, ""} when number >= 0 -> {:ok, number}
      _ -> :error
    end
  end

  @doc "Whether a Postfix boolean is yes."
  @spec yes?(String.t() | nil) :: boolean()
  def yes?(value),
    do: is_binary(value) and String.downcase(String.trim(value)) in ["yes", "true", "1"]

  @doc "Whether a Postfix boolean is no."
  @spec no?(String.t() | nil) :: boolean()
  def no?(value),
    do: is_binary(value) and String.downcase(String.trim(value)) in ["no", "false", "0"]

  @doc """
  Converts a Postfix network list (mynetworks syntax) to CIDR strings.
  Returns the networks and the problems, as `{item, message}`.
  """
  @spec networks([String.t()]) :: {[String.t()], [{String.t(), String.t()}]}
  def networks(items) do
    {networks, problems} =
      Enum.reduce(items, {[], []}, fn item, {networks, problems} ->
        case network(item) do
          {:ok, network} -> {[network | networks], problems}
          {:ok, network, note} -> {[network | networks], [{item, note} | problems]}
          {:error, message} -> {networks, [{item, message} | problems]}
        end
      end)

    {networks |> Enum.reverse() |> Enum.uniq(), Enum.reverse(problems)}
  end

  @doc "Converts one network of a Postfix network list."
  @spec network(String.t()) ::
          {:ok, String.t()} | {:ok, String.t(), String.t()} | {:error, String.t()}
  def network("!" <> _),
    do: {:error, "exclusions (\"!\") are not supported: list only the networks to trust"}

  def network("/" <> _),
    do: {:error, "network lists in files are not supported: list the networks"}

  def network(item) do
    {address, prefix} =
      case String.split(item, "/", parts: 2) do
        [address, prefix] -> {unbracket(address), "/" <> prefix}
        [address] -> {unbracket(address), ""}
      end

    case Sovite.Net.parse_cidr(address <> prefix) do
      {:ok, network} -> {:ok, format(network, prefix)}
      {:error, :host_bits_set} -> masked(address, prefix)
      {:error, _} -> not_network(item)
    end
  end

  defp not_network(item) do
    if item =~ ~r/\A[a-z]+:/i,
      do: {:error, "lookup tables are not supported: list the networks"},
      else: {:error, "host names are not supported: use addresses or CIDR networks"}
  end

  defp unbracket("[" <> rest), do: String.trim_trailing(rest, "]")
  defp unbracket(address), do: address

  defp format({ip, _length}, ""), do: ip |> :inet.ntoa() |> to_string()
  defp format(network, _prefix), do: Sovite.Net.format_cidr(network)

  defp masked(address, "/" <> prefix) do
    {:ok, ip} = Sovite.Net.parse_ip(address)
    length = String.to_integer(prefix)
    network = {mask(ip, length), length}
    text = Sovite.Net.format_cidr(network)
    {:ok, text, "has bits set after the prefix length: using #{text}"}
  end

  defp mask(ip, length) do
    bits = tuple_size(ip) * if(tuple_size(ip) == 4, do: 8, else: 16)
    size = div(bits, tuple_size(ip))
    value = ip |> Tuple.to_list() |> Enum.reduce(0, &(&2 <<< size ||| &1))
    masked = value &&& (1 <<< bits) - 1 - ((1 <<< (bits - length)) - 1)

    for(i <- (tuple_size(ip) - 1)..0//-1, do: masked >>> (i * size) &&& (1 <<< size) - 1)
    |> List.to_tuple()
  end

  @doc """
  The lowest TLS version a Postfix protocol list allows: `"TLSv1"`,
  `"TLSv1.1"`, `"TLSv1.2"`, or `"TLSv1.3"`. Handles `>=TLSv1.2`,
  `<=TLSv1.3`, `!SSLv3, !TLSv1`, and lists of protocols.
  """
  @spec min_tls(String.t()) :: {:ok, String.t()} | :error
  def min_tls(value) do
    versions = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    items = value |> String.split(~r/[\s,:]+/, trim: true)

    allowed =
      Enum.reduce(items, nil, fn
        ">=" <> version, acc ->
          from(acc || versions, version, versions)

        "<=" <> _version, acc ->
          acc

        "!" <> version, acc ->
          List.delete(acc || versions, version)

        version, acc ->
          if(version in versions, do: Enum.uniq((acc || []) ++ [version]), else: acc)
      end)

    case Enum.filter(versions, &(&1 in (allowed || versions))) do
      [lowest | _] -> {:ok, lowest}
      [] -> :error
    end
  end

  defp from(allowed, version, versions) do
    case Enum.find_index(versions, &(&1 == version)) do
      nil -> allowed
      index -> Enum.filter(allowed, &(&1 in Enum.drop(versions, index)))
    end
  end

  @doc "Whether `value` is an email address Sovite accepts."
  @spec address?(String.t()) :: boolean()
  def address?(value), do: Validators.mailbox?(value)

  @doc "Whether `value` is a domain."
  @spec domain?(String.t()) :: boolean()
  def domain?(value), do: Validators.domain?(value)

  @doc """
  Whether `pattern` has one of the forms Sovite's tables accept:
  `:address`, `:catchall` (`@domain`), `:local_part`, `:domain`,
  `:subdomains` (`.domain`), `:wildcard` (`*`).
  """
  @spec form?(String.t(), [atom()]) :: boolean()
  def form?(pattern, forms), do: Enum.any?(forms, &form(pattern, &1))

  defp form(pattern, :wildcard), do: pattern == "*"
  defp form("@" <> domain, :catchall), do: Validators.domain?(domain)
  defp form("." <> domain, :subdomains), do: Validators.domain?(domain)
  defp form(pattern, :address), do: Validators.mailbox?(pattern)

  defp form(pattern, :domain),
    do: not String.contains?(pattern, "@") and Validators.domain?(pattern)

  defp form(pattern, :local_part),
    do: not String.contains?(pattern, "@") and Validators.local_part?(pattern)

  defp form(_pattern, _form), do: false

  @doc """
  Quotes `text` for /bin/sh: single quotes, with embedded single quotes
  written as `'\\''`.

      iex> Sovite.Core.Postfix.Convert.shell_quote("it's")
      ~S('it'\\''s')
  """
  @spec shell_quote(String.t()) :: String.t()
  def shell_quote(text), do: "'" <> String.replace(text, "'", ~S('\'')) <> "'"
end
