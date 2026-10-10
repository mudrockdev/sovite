defmodule Sovite.Core.Postfix.Table do
  @moduledoc """
  Reads Postfix lookup tables, for `Sovite.Core.Postfix.Migration`.

  A table is named `type:name`:

    * `hash:`, `btree:`, `lmdb:`, `cdb:`, `dbm:`, `sdbm:` - indexed
      files built with `postmap` from a text file. The text file is read
      (`hash:/etc/postfix/virtual` reads `/etc/postfix/virtual`, not
      `virtual.db`). `texthash:` is the text file itself.
    * `proxy:TYPE:name` - one of the above through `proxymap(8)`; the
      file is read as without `proxy:`.
    * `inline:{ key=value, { key = text } }` and `static:value` - the
      entries are in the name.

  Other types (`mysql:`, `pgsql:`, `ldap:`, `regexp:`, `pcre:`, `cidr:`,
  `sqlite:`, `memcache:`, `socketmap:`, `tcp:`, `unionmap:`, ...) cannot
  be read: they are reported as unsupported.

  Text files have one `key value` entry per logical line (see
  `Sovite.Core.Postfix.MainCf.logical_lines/1`). Keys are lower-cased,
  as `postmap` does. Alias files (`aliases(5)`) are `name: dest, dest`.
  """

  alias Sovite.Core.Postfix.MainCf

  @file_types ~w(hash btree lmdb cdb dbm sdbm texthash)

  @typedoc "Where a table's entries come from."
  @type source ::
          {:file, type :: String.t(), path :: String.t()}
          | {:inline, [{String.t(), String.t()}]}
          | {:static, String.t()}
          | {:unsupported, type :: String.t()}

  @typedoc "Why a table could not be read."
  @type error :: {:unsupported, String.t()} | {:unreadable, String.t(), term()}

  @typedoc "Reads a file: `File.read/1`, or a function that maps paths first."
  @type reader :: (String.t() -> {:ok, binary()} | {:error, term()})

  @doc """
  Parses a table name.

      iex> Sovite.Core.Postfix.Table.source("hash:/etc/postfix/virtual")
      {:file, "hash", "/etc/postfix/virtual"}
      iex> Sovite.Core.Postfix.Table.source("mysql:/etc/postfix/mysql.cf")
      {:unsupported, "mysql"}
  """
  @spec source(String.t()) :: source()
  def source(name) do
    case String.split(String.trim(name), ":", parts: 2) do
      ["proxy", inner] -> proxied(source(inner))
      [type, path] when type in @file_types and path != "" -> {:file, type, path}
      ["inline", entries] -> {:inline, inline(entries)}
      ["static", value] -> {:static, MainCf.ungroup(value)}
      [type, _rest] -> {:unsupported, String.downcase(type)}
      [_no_type] -> {:unsupported, "no type"}
    end
  end

  defp proxied({:file, _type, _path} = file), do: file
  defp proxied({:unsupported, type}), do: {:unsupported, "proxy:" <> type}
  defp proxied(_other), do: {:unsupported, "proxy"}

  defp inline(entries) do
    for item <- entries |> MainCf.ungroup() |> MainCf.split(),
        [key, value] <- [String.split(MainCf.ungroup(item), "=", parts: 2)],
        do: {key |> String.trim() |> String.downcase(), String.trim(value)}
  end

  @doc """
  Reads the entries of table `name` as `{key, value}` pairs, in file
  order. `read` reads a file.
  """
  @spec read(String.t(), reader()) :: {:ok, [{String.t(), String.t()}]} | {:error, error()}
  def read(name, read), do: read_source(source(name), read, :entries)

  @doc "Reads alias table `name` as `{name, destinations}` pairs. See `read/2`."
  @spec read_aliases(String.t(), reader()) ::
          {:ok, [{String.t(), [String.t()]}]} | {:error, error()}
  def read_aliases(name, read) do
    read_source(source(name), read, :aliases)
  end

  defp read_source({:file, _type, path}, read, kind) do
    case read.(path) do
      {:ok, contents} when kind == :entries -> {:ok, parse(contents)}
      {:ok, contents} -> {:ok, parse_aliases(contents)}
      {:error, reason} -> {:error, {:unreadable, path, reason}}
    end
  end

  defp read_source({:inline, entries}, _read, :entries), do: {:ok, entries}
  defp read_source({:inline, entries}, _read, :aliases), do: {:ok, alias_entries(entries)}
  defp read_source({:static, value}, _read, :entries), do: {:ok, [{"*", value}]}
  defp read_source({:static, _value}, _read, :aliases), do: {:error, {:unsupported, "static"}}
  defp read_source({:unsupported, type}, _read, _kind), do: {:error, {:unsupported, type}}

  defp alias_entries(entries), do: for({key, value} <- entries, do: {key, destinations(value)})

  @doc """
  Parses a `postmap` source file.

      iex> Sovite.Core.Postfix.Table.parse("# comment\\nAlice@Example.com  alice@example.org,\\n  bob@example.org\\n")
      [{"alice@example.com", "alice@example.org, bob@example.org"}]
  """
  @spec parse(String.t()) :: [{String.t(), String.t()}]
  def parse(contents) do
    for {_number, line} <- MainCf.logical_lines(contents) do
      case String.split(line, ~r/\s+/, parts: 2) do
        [key, value] -> {String.downcase(key), String.trim(value)}
        [key] -> {String.downcase(key), ""}
      end
    end
  end

  @doc """
  Parses an `aliases(5)` file: `name: destination, destination`. Names
  may be quoted.

      iex> Sovite.Core.Postfix.Table.parse_aliases(~s(postmaster: root\\n"x y": a@example.com, "|/bin/prog arg"\\n))
      [{"postmaster", ["root"]}, {"x y", ["a@example.com", "|/bin/prog arg"]}]
  """
  @spec parse_aliases(String.t()) :: [{String.t(), [String.t()]}]
  def parse_aliases(contents) do
    for {_number, line} <- MainCf.logical_lines(contents),
        {name, value} <- [alias_line(line)],
        do: {name, destinations(value)}
  end

  defp alias_line("\"" <> rest) do
    case String.split(rest, "\"", parts: 2) do
      [name, ":" <> value] -> {String.downcase(name), value}
      [name, value] -> {String.downcase(name), String.trim_leading(value, ":")}
      [name] -> {String.downcase(name), ""}
    end
  end

  defp alias_line(line) do
    case String.split(line, ":", parts: 2) do
      [name, value] -> {name |> String.trim() |> String.downcase(), value}
      [name] -> {String.downcase(name), ""}
    end
  end

  @doc """
  Splits a list of destinations on commas, keeping quoted ones (such as
  `"|command with args"`) whole and removing the quotes.
  """
  @spec destinations(String.t()) :: [String.t()]
  def destinations(value) do
    {items, current, _quoted} =
      value
      |> String.graphemes()
      |> Enum.reduce({[], "", false}, fn
        "\"", {items, current, quoted} -> {items, current, not quoted}
        ",", {items, current, false} -> {[current | items], "", false}
        char, {items, current, quoted} -> {items, current <> char, quoted}
      end)

    [current | items]
    |> Enum.reverse()
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  @doc "Describes a read error for the report."
  @spec describe_error(error()) :: String.t()
  def describe_error({:unsupported, type}),
    do: "#{type}: tables cannot be read; migrate its entries by hand"

  def describe_error({:unreadable, path, reason}) when is_atom(reason),
    do: "cannot read #{path}: #{:file.format_error(reason)}"

  def describe_error({:unreadable, path, reason}), do: "cannot read #{path}: #{inspect(reason)}"
end
