defmodule Sovite.Core.Postfix.TomlWriter do
  @moduledoc """
  Writes the TOML of a generated config file, for
  `Sovite.Core.Postfix.Migration`. Only what a Sovite config needs:
  strings, integers, booleans, arrays of those, inline tables, tables,
  and arrays of tables, with comments.
  """

  @typedoc "A value: string, integer, boolean, an array, or `{:inline, pairs}`."
  @type value ::
          String.t()
          | integer()
          | boolean()
          | [String.t() | integer()]
          | {:inline, [{String.t(), value()}]}

  @typedoc "A key and its value, optionally with a comment written above it."
  @type entry :: {String.t(), value()} | {String.t(), value(), String.t() | nil}

  @typedoc "A part of the document. Top-level `:entries` must come before the tables."
  @type part ::
          {:comment, String.t()}
          | {:entries, [entry()]}
          | {:table, String.t(), [entry()]}
          | {:table, String.t(), [entry()], String.t() | nil}
          | {:array_table, String.t(), [entry()]}
          | {:array_table, String.t(), [entry()], String.t() | nil}

  @doc """
  Renders `parts`. Tables without entries are left out; each array table
  is written, even when empty. A table's comment goes after its header.
  """
  @spec render([part()]) :: String.t()
  def render(parts) do
    parts
    |> Enum.flat_map(&part/1)
    |> Enum.join("\n")
    |> String.trim_leading("\n")
    |> Kernel.<>("\n")
  end

  defp part({:comment, text}), do: comment_lines(text, "")
  defp part({:entries, entries}), do: ["" | Enum.flat_map(entries, &entry/1)]
  defp part({:table, name, entries}), do: part({:table, name, entries, nil})
  defp part({:table, _name, [], _comment}), do: []
  defp part({:table, name, entries, comment}), do: section("[#{name}]", entries, comment)
  defp part({:array_table, name, entries}), do: part({:array_table, name, entries, nil})
  defp part({:array_table, name, entries, comment}), do: section("[[#{name}]]", entries, comment)

  defp section(header, entries, comment),
    do: ["", header] ++ comment_lines(comment, "") ++ Enum.flat_map(entries, &entry/1)

  defp entry({key, value}), do: entry({key, value, nil})

  defp entry({key, value, comment}),
    do: comment_lines(comment, "check: ") ++ ["#{key(key)} = #{value(value)}"]

  defp comment_lines(nil, _prefix), do: []

  defp comment_lines(text, prefix) do
    (prefix <> text)
    |> String.replace(~r/[\r\n]+/, " ")
    |> wrap(76)
    |> Enum.map(&String.trim_trailing("# " <> &1))
  end

  @doc """
  A key: bare when it only has letters, digits, `_`, and `-`, otherwise
  quoted.

      iex> Sovite.Core.Postfix.TomlWriter.key("alice@example.com")
      ~s("alice@example.com")
  """
  @spec key(String.t()) :: String.t()
  def key(key) do
    if key =~ ~r/\A[A-Za-z0-9_-]+\z/, do: key, else: string(key)
  end

  @doc "A value."
  @spec value(value()) :: String.t()
  def value(value) when is_binary(value), do: string(value)
  def value(value) when is_boolean(value), do: to_string(value)
  def value(value) when is_integer(value), do: Integer.to_string(value)
  def value(values) when is_list(values), do: "[" <> Enum.map_join(values, ", ", &value/1) <> "]"

  def value({:inline, pairs}),
    do:
      "{ " <>
        Enum.map_join(pairs, ", ", fn {key, value} -> "#{key(key)} = #{value(value)}" end) <> " }"

  @doc """
  A basic string, with `\\`, `"`, and control characters escaped.
  Invalid UTF-8 is replaced.

      iex> Sovite.Core.Postfix.TomlWriter.string(~s(a "b" \\\\ c\\td))
      ~S("a \\"b\\" \\\\ c\\td")
  """
  @spec string(String.t()) :: String.t()
  def string(text) do
    escaped =
      text
      |> String.replace_invalid()
      |> String.to_charlist()
      |> Enum.map(&escape/1)

    IO.iodata_to_binary([?", escaped, ?"])
  end

  defp escape(?"), do: ~S(\")
  defp escape(?\\), do: ~S(\\)
  defp escape(?\b), do: ~S(\b)
  defp escape(?\t), do: ~S(\t)
  defp escape(?\n), do: ~S(\n)
  defp escape(?\f), do: ~S(\f)
  defp escape(?\r), do: ~S(\r)

  defp escape(char) when char < 0x20 or char == 0x7F,
    do: "\\u" <> String.pad_leading(Integer.to_string(char, 16), 4, "0")

  defp escape(char), do: <<char::utf8>>

  @doc "Wraps `text` into lines of at most `width` characters, at spaces."
  @spec wrap(String.t(), pos_integer()) :: [String.t()]
  def wrap(text, width) do
    text
    |> String.split(" ", trim: true)
    |> Enum.reduce([], fn
      word, [] ->
        [word]

      word, [line | rest] ->
        if String.length(line) + 1 + String.length(word) > width,
          do: [word, line | rest],
          else: [line <> " " <> word | rest]
    end)
    |> Enum.reverse()
    |> case do
      [] -> [""]
      lines -> lines
    end
  end
end
