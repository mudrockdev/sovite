defmodule Sovite.URL do
  @moduledoc """
  URLs and mail addresses in text, as a filter sees them: found, taken
  apart, and normalized, with the tricks that hide them noted.

      iex> [url] = Sovite.URL.extract("Click hxxps://Bank.Example[.]com/login now!")
      iex> {url.host, url.path, url.flags}
      {"bank.example.com", "/login", [:obfuscated]}

      iex> {:ok, url} = Sovite.URL.parse("http://bank.example@3232235777/")
      iex> {url.host, url.user, url.flags}
      {"192.168.1.1", "bank.example", [:userinfo, :numeric_host]}

  `extract/2` finds URLs with a scheme (`http`, `https`, `ftp`, and the
  `hxxp` spelling) or starting with `www.`. Bare domains (`example.com`)
  need a list of top-level domains to tell them from file names, so they
  are not looked for yet.

  Hosts are lower-cased, %-escapes decoded, internationalized names put
  in A-labels, and numeric IPv4 forms (`3232235777`, `0xC0.0xA8.1.1`,
  `0300.0250.1.1`, as browsers read them) turned into dotted decimal.

  ## Flags

    * `:obfuscated` - written to dodge filters: `hxxp://`, `[.]` or
      `(.)` for dots.
    * `:userinfo` - a user name before the host (`http://bank@evil/`),
      which makes the URL look like it goes to the user name.
    * `:numeric_host` - an IPv4 address written in another form than
      dotted decimal.
    * `:ip` - the host is an IP address.
    * `:idn` - the host is an internationalized domain name.
    * `:encoded_host` - the host has %-escapes.
    * `:no_scheme` - found as `www.` without a scheme.
    * `:redirect_target` - found in another URL's query, as redirectors
      and link trackers carry where they send the reader (see
      `redirect_targets/1`).
  """

  alias Sovite.IDNA

  defstruct [:url, :scheme, :user, :host, :port, :path, :query, :fragment, flags: []]

  @type flag ::
          :obfuscated
          | :userinfo
          | :numeric_host
          | :ip
          | :idn
          | :encoded_host
          | :no_scheme
          | :redirect_target

  @type t :: %__MODULE__{
          url: String.t(),
          scheme: String.t(),
          user: String.t() | nil,
          host: String.t(),
          port: :inet.port_number() | nil,
          path: String.t(),
          query: String.t() | nil,
          fragment: String.t() | nil,
          flags: [flag()]
        }

  @schemes ~w(http https ftp)

  # A scheme (or "www."), then anything but white space and the characters
  # that end a URL in text. "[.]" and "(.)" are kept to be undone.
  @candidate ~r/(?:\b(?:https?|hxxps?|ftp):\/\/|\bwww(?:\.|\[\.\]|\(\.\)))(?:\[\.\]|\(\.\)|[^\s<>"'`{}|\\^\[\]()])+/iu

  @address ~r/[\p{L}\p{N}._%+\-]+@(?:[\p{L}\p{N}\-]+\.)+[\p{L}]{2,}/u

  @doc """
  The URLs in `text` (UTF-8), in order, the same URL once. At most
  `:max_urls` (1,000 by default).
  """
  @spec extract(String.t(), keyword()) :: [t()]
  def extract(text, opts \\ []) when is_binary(text) do
    max = Keyword.get(opts, :max_urls, 1000)
    text = String.replace_invalid(text)

    @candidate
    |> Regex.scan(text)
    |> Stream.map(fn [candidate] -> candidate |> trim_trailing() |> found() end)
    |> Stream.filter(&match?({:ok, _}, &1))
    |> Stream.map(&elem(&1, 1))
    |> Stream.uniq_by(& &1.url)
    |> Enum.take(max)
  end

  @doc """
  The URLs in the query of `url`: where a redirector or a link tracker
  sends the reader (`?url=https://...`, `?q=https%3A%2F%2F...`), flagged
  `:redirect_target`. One level deep.

      iex> {:ok, url} = Sovite.URL.parse("https://www.google.com/url?sa=t&q=https%3A%2F%2Fevil.example%2Fx")
      iex> Enum.map(Sovite.URL.redirect_targets(url), &{&1.url, &1.flags})
      [{"https://evil.example/x", [:redirect_target]}]
  """
  @spec redirect_targets(t()) :: [t()]
  def redirect_targets(%__MODULE__{query: nil}), do: []

  def redirect_targets(%__MODULE__{query: query}) do
    for pair <- String.split(query, "&"),
        [_name, value] <- [:binary.split(pair, "=")],
        value =
          value |> String.replace("+", " ") |> percent_safe() |> URI.decode() |> String.trim(),
        Regex.match?(~r/\A(?:https?:\/\/|www\.)/i, value),
        {:ok, target} <- [found(value)] do
      %{target | flags: [:redirect_target | target.flags]}
    end
  end

  @doc "The mail addresses in `text`, in order, the same address once, with lower-cased domains."
  @spec addresses(String.t(), keyword()) :: [String.t()]
  def addresses(text, opts \\ []) when is_binary(text) do
    max = Keyword.get(opts, :max_addresses, 1000)

    @address
    |> Regex.scan(String.replace_invalid(text))
    |> Stream.map(fn [address] ->
      [local, domain] = String.split(address, "@", parts: 2)
      String.trim(local, ".") <> "@" <> String.downcase(String.trim_trailing(domain, "."))
    end)
    |> Stream.uniq()
    |> Enum.take(max)
  end

  # Sentence punctuation after a URL is not part of it.
  defp trim_trailing(candidate), do: String.replace(candidate, ~r/[.,;:!?]+\z/, "")

  defp found(candidate) do
    {candidate, obfuscated} = deobfuscate(candidate)

    {candidate, no_scheme} =
      if Regex.match?(~r/\A[a-z]+:\/\//i, candidate),
        do: {candidate, false},
        else: {"http://" <> candidate, true}

    with {:ok, url} <- parse(candidate) do
      flags = Enum.filter([obfuscated && :obfuscated, no_scheme && :no_scheme], & &1)
      {:ok, %{url | flags: flags ++ url.flags}}
    end
  end

  defp deobfuscate(candidate) do
    clean =
      candidate
      |> String.replace(~r/\Ahxxp/i, "http")
      |> String.replace(["[.]", "(.)"], ".")

    {clean, clean != candidate}
  end

  @doc """
  Takes an absolute URL apart and normalizes its host (see the module
  docs). `:error` for what is not a URL with a host, or with another
  scheme than `http`, `https`, or `ftp`.
  """
  @spec parse(String.t()) :: {:ok, t()} | :error
  def parse(text) when is_binary(text) do
    with [_, scheme, authority, rest] <-
           Regex.run(~r/\A([A-Za-z][A-Za-z0-9+.\-]*):\/\/([^\/?#]*)(.*)\z/s, text),
         scheme = String.downcase(scheme),
         true <- scheme in @schemes,
         {user, host_port, flags} = userinfo(authority),
         {:ok, host, port, host_flags} <- host_port(host_port) do
      {path, query, fragment} = path_parts(rest)

      {:ok,
       %__MODULE__{
         url: build(scheme, user, host, port, path, query),
         scheme: scheme,
         user: user,
         host: host,
         port: port,
         path: path,
         query: query,
         fragment: fragment,
         flags: flags ++ host_flags
       }}
    else
      _ -> :error
    end
  end

  defp userinfo(authority) do
    case :binary.matches(authority, "@") do
      [] ->
        {nil, authority, []}

      matches ->
        {at, 1} = List.last(matches)
        user = binary_part(authority, 0, at)

        {URI.decode(percent_safe(user)),
         binary_part(authority, at + 1, byte_size(authority) - at - 1), [:userinfo]}
    end
  end

  defp host_port(host_port) do
    {host, port} =
      case Regex.run(~r/\A(\[[^\]]*\]|[^:]*)(?::(\d{0,5}))?\z/, host_port) do
        [_, host] -> {host, nil}
        [_, host, ""] -> {host, nil}
        [_, host, port] -> {host, String.to_integer(port)}
        nil -> {host_port, :error}
      end

    with true <- port != :error and (port == nil or port <= 65_535),
         {:ok, host, flags} <- host(host) do
      {:ok, host, port, flags}
    else
      _ -> :error
    end
  end

  defp host("[" <> rest) do
    with true <- String.ends_with?(rest, "]"),
         {:ok, ip} <-
           :inet.parse_ipv6strict_address(String.to_charlist(String.trim_trailing(rest, "]"))) do
      {:ok, "[" <> to_string(:inet.ntoa(ip)) <> "]", [:ip]}
    else
      _ -> :error
    end
  end

  defp host(""), do: :error

  defp host(host) do
    encoded = String.contains?(host, "%")

    host =
      host
      |> percent_safe()
      |> URI.decode()
      |> String.replace_invalid()
      |> String.trim_trailing(".")
      |> String.downcase()

    flags = if encoded, do: [:encoded_host], else: []

    case ipv4(host) do
      {:ok, ip, :dotted} -> {:ok, ip, flags ++ [:ip]}
      {:ok, ip, :numeric} -> {:ok, ip, flags ++ [:numeric_host]}
      :error -> name(host, flags)
    end
  end

  defp name(host, flags) do
    if host =~ ~r/\A[a-z0-9._-]+\z/ do
      {:ok, host, flags}
    else
      case IDNA.to_ascii(host) do
        {:ok, ascii} -> {:ok, ascii, flags ++ [:idn]}
        {:error, _} -> :error
      end
    end
  end

  # IPv4 as browsers read it (WHATWG URL Standard): up to four numbers in
  # decimal, octal (leading 0), or hex (0x), the last filling the
  # remaining bytes.
  defp ipv4(host) do
    parts = String.split(host, ".")

    with true <- length(parts) in 1..4 and Enum.all?(parts, &(&1 != "")),
         {:ok, numbers} <- numbers(parts),
         {:ok, value} <- ipv4_value(numbers) do
      <<a, b, c, d>> = <<value::32>>
      dotted = "#{a}.#{b}.#{c}.#{d}"
      {:ok, dotted, if(dotted == host, do: :dotted, else: :numeric)}
    else
      _ -> :error
    end
  end

  defp numbers(parts) do
    Enum.reduce_while(parts, {:ok, []}, fn part, {:ok, acc} ->
      case number(part) do
        {:ok, n} -> {:cont, {:ok, [n | acc]}}
        :error -> {:halt, :error}
      end
    end)
    |> case do
      {:ok, numbers} -> {:ok, Enum.reverse(numbers)}
      :error -> :error
    end
  end

  defp number("0x" <> hex), do: integer(hex, 16)
  defp number("0X" <> hex), do: integer(hex, 16)
  defp number("0" <> octal) when octal != "", do: integer(octal, 8)
  defp number(decimal), do: integer(decimal, 10)

  defp integer("", 16), do: {:ok, 0}

  defp integer(digits, base) do
    case Integer.parse(digits, base) do
      {n, ""} when n >= 0 -> {:ok, n}
      _ -> :error
    end
  end

  defp ipv4_value(numbers) do
    {init, [last]} = Enum.split(numbers, -1)
    count = length(numbers)

    if Enum.all?(init, &(&1 <= 255)) and last < 256 ** (5 - count) do
      value =
        init
        |> Enum.with_index()
        |> Enum.reduce(last, fn {n, i}, acc -> acc + n * 256 ** (3 - i) end)

      {:ok, value}
    else
      :error
    end
  end

  defp path_parts(rest) do
    {rest, fragment} = split_at(rest, "#")
    {path, query} = split_at(rest, "?")
    {if(path == "", do: "/", else: path), query, fragment}
  end

  defp split_at(text, char) do
    case :binary.split(text, char) do
      [before, after_char] -> {before, after_char}
      [whole] -> {whole, nil}
    end
  end

  defp build(scheme, _user, host, port, path, query) do
    port = if port, do: ":#{port}", else: ""
    query = if query, do: "?" <> query, else: ""
    scheme <> "://" <> host <> port <> path <> query
  end

  # URI.decode raises on a "%" without two hex digits: keep those.
  defp percent_safe(value), do: Regex.replace(~r/%(?![0-9A-Fa-f]{2})/, value, "%25")
end
