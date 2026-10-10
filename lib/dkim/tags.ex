defmodule Sovite.DKIM.Tags do
  @moduledoc """
  DKIM tag lists (RFC 6376 §3.2): `tag=value` pairs separated by `;`,
  as used by `DKIM-Signature:` fields, key records, and the ARC fields.

      iex> Sovite.DKIM.Tags.parse("v=1; a=rsa-sha256;\\r\\n\\td=example.com;")
      {:ok, %{"v" => "1", "a" => "rsa-sha256", "d" => "example.com"}}

  Folding whitespace around tags and values is removed; inside values it
  is kept (base64 values drop it with `strip_whitespace/1`). Tag names
  are case-sensitive. A duplicate tag makes the whole list invalid.
  """

  @doc "Parses a tag list into a map of tag names to values."
  @spec parse(String.t()) :: {:ok, %{String.t() => String.t()}} | :error
  def parse(text) do
    text
    |> String.split(";")
    |> drop_trailing_empty()
    |> Enum.reduce_while({:ok, %{}}, fn spec, {:ok, acc} ->
      case parse_spec(spec) do
        {:ok, name, value} when not is_map_key(acc, name) ->
          {:cont, {:ok, Map.put(acc, name, value)}}

        _ ->
          {:halt, :error}
      end
    end)
  end

  # A tag list may end with ";".
  defp drop_trailing_empty(specs) do
    case List.last(specs) do
      nil -> specs
      last -> if trim(last) == "", do: List.delete_at(specs, -1), else: specs
    end
  end

  defp parse_spec(spec) do
    with [name, value] <- :binary.split(spec, "="),
         name = trim(name),
         true <- Regex.match?(~r/\A[A-Za-z][A-Za-z0-9_]*\z/, name) do
      {:ok, name, trim(value)}
    else
      _ -> :error
    end
  end

  @doc "Removes folding whitespace from both ends of `text`."
  @spec trim(String.t()) :: String.t()
  def trim(text), do: String.replace(text, ~r/\A[ \t\r\n]+|[ \t\r\n]+\z/, "")

  @doc "Removes all whitespace, for base64 values."
  @spec strip_whitespace(String.t()) :: String.t()
  def strip_whitespace(text), do: String.replace(text, ~r/[ \t\r\n]/, "")

  @doc """
  Returns the raw field `raw` with the value of its `b=` tag emptied,
  whitespace around it included, as signing and verifying need
  (RFC 6376 §3.7). Everything else is kept byte for byte.

      iex> Sovite.DKIM.Tags.empty_b("DKIM-Signature: a=x; b=abc\\r\\n def; bh=y\\r\\n")
      "DKIM-Signature: a=x; b=; bh=y\\r\\n"
  """
  @spec empty_b(String.t()) :: String.t()
  def empty_b(raw) do
    [name, value] = :binary.split(raw, ":")
    trailer = if String.ends_with?(value, "\r\n"), do: "\r\n", else: ""
    value = String.replace_suffix(value, "\r\n", "")

    specs = value |> String.split(";") |> Enum.map(&empty_b_spec/1)
    name <> ":" <> Enum.join(specs, ";") <> trailer
  end

  defp empty_b_spec(spec) do
    case :binary.split(spec, "=") do
      [tag, _value] -> if trim(tag) == "b", do: tag <> "=", else: spec
      _ -> spec
    end
  end
end
