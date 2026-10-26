defmodule Sovite.MIME.Params do
  @moduledoc """
  Header values with parameters (RFC 2045 §5.1, RFC 2183): the value and
  its `name=value` parameters, as in `Content-Type:` and
  `Content-Disposition:`.

      iex> Sovite.MIME.Params.parse(~s[Text/Plain; charset="UTF-8" (comment); format=flowed])
      {"text/plain", %{"charset" => "UTF-8", "format" => "flowed"}}
      iex> Sovite.MIME.Params.parse("attachment; filename*0*=utf-8''%E2%82%AC; filename*1=.txt")
      {"attachment", %{"filename" => "€.txt"}}

  The value is lower-cased; parameter names are lower-cased, values are
  kept as written, unquoted, in UTF-8. Continuations and charsets of RFC
  2231 (`name*0*=utf-8''...`) are put together and decoded, and so are
  encoded words in values (`filename="=?utf-8?B?...?="`), which RFC 2231
  does not allow but many senders use. Comments are left out. The first
  of two parameters with the same name counts. Values without a name, or
  that do not parse, are skipped: a filter wants what it can get.
  """

  alias Sovite.Charset
  alias Sovite.MIME.EncodedWord

  @doc "Parses a header value: the lower-cased value (`nil` if empty) and the parameters."
  @spec parse(String.t()) :: {String.t() | nil, %{String.t() => String.t()}}
  def parse(text) when is_binary(text) do
    # Raw 8-bit bytes (file names, often) are windows-1252 when not UTF-8.
    text = if String.valid?(text), do: text, else: elem(Charset.to_utf8(text, "windows-1252"), 1)

    [value | params] =
      text
      |> String.replace(~r/\r?\n/, "")
      |> split([], [], :plain)

    value = value |> String.trim() |> String.downcase()
    {if(value == "", do: nil, else: value), params |> pairs() |> combine()}
  end

  # Splits at ";" outside quoted strings, leaving out comments.
  defp split(<<>>, current, acc, _state), do: Enum.reverse([finish(current) | acc])

  defp split(<<?;, rest::binary>>, current, acc, :plain),
    do: split(rest, [], [finish(current) | acc], :plain)

  defp split(<<?", rest::binary>>, current, acc, :plain),
    do: split(rest, [?" | current], acc, :quoted)

  defp split(<<?", rest::binary>>, current, acc, :quoted),
    do: split(rest, [?" | current], acc, :plain)

  defp split(<<?\\, c, rest::binary>>, current, acc, :quoted),
    do: split(rest, [c, ?\\ | current], acc, :quoted)

  defp split(<<?(, rest::binary>>, current, acc, :plain),
    do: split(skip_comment(rest, 1), current, acc, :plain)

  defp split(<<c, rest::binary>>, current, acc, state), do: split(rest, [c | current], acc, state)

  defp finish(current), do: current |> Enum.reverse() |> IO.iodata_to_binary()

  defp skip_comment(<<>>, _depth), do: <<>>
  defp skip_comment(<<?\\, _c, rest::binary>>, depth), do: skip_comment(rest, depth)
  defp skip_comment(<<?), rest::binary>>, 1), do: rest
  defp skip_comment(<<?), rest::binary>>, depth), do: skip_comment(rest, depth - 1)
  defp skip_comment(<<?(, rest::binary>>, depth), do: skip_comment(rest, depth + 1)
  defp skip_comment(<<_c, rest::binary>>, depth), do: skip_comment(rest, depth)

  defp pairs(params) do
    for param <- params,
        [name, value] <- [:binary.split(param, "=")],
        name = name |> String.trim() |> String.downcase(),
        name != "",
        do: {name, value |> String.trim() |> unquote_value()}
  end

  defp unquote_value(<<?", rest::binary>>) do
    rest
    |> String.trim_trailing("\"")
    |> String.replace(~r/\\(.)/s, "\\1")
  end

  defp unquote_value(value), do: value

  # RFC 2231: name*0, name*1*, ... are pieces of one value; a "*" at the
  # end means the piece is %-encoded, the first with its charset.
  defp combine(pairs) do
    pairs
    |> Enum.with_index()
    |> Enum.group_by(fn {{name, _value}, _index} -> base(name) end)
    |> Enum.sort_by(fn {_base, [{_pair, index} | _]} -> index end)
    |> Enum.reduce(%{}, fn {base, pieces}, acc ->
      Map.put_new(acc, base, value(Enum.map(pieces, &elem(&1, 0))))
    end)
  end

  defp base(name), do: name |> String.split("*") |> hd()

  # RFC 2231 pieces win over a plain value of the same name.
  defp value(pieces) do
    case Enum.filter(pieces, fn {name, _value} -> String.contains?(name, "*") end) do
      [] ->
        {_name, plain} = hd(pieces)
        EncodedWord.decode(plain)

      extended ->
        extended |> Enum.sort_by(fn {name, _value} -> section(name) end) |> continuation()
    end
  end

  defp section(name) do
    case Regex.run(~r/\*(\d+)\*?\z/, name) do
      [_, number] -> String.to_integer(number)
      nil -> 0
    end
  end

  defp continuation([]), do: ""

  defp continuation([{first_name, first} | _] = pieces) do
    {charset, first} =
      if String.ends_with?(first_name, "*") do
        case String.split(first, "'", parts: 3) do
          [charset, _language, text] -> {charset, text}
          _ -> {"utf-8", first}
        end
      else
        {"utf-8", first}
      end

    bytes =
      [{first_name, first} | tl(pieces)]
      |> Enum.map(fn {name, value} ->
        if String.ends_with?(name, "*"), do: URI.decode(percent_safe(value)), else: value
      end)
      |> IO.iodata_to_binary()

    case Charset.to_utf8(bytes, if(charset == "", do: "utf-8", else: charset)) do
      {:ok, text} -> text
      {:error, :unknown_charset} -> EncodedWord.decode(bytes)
    end
  end

  # URI.decode raises on a "%" without two hex digits: keep those.
  defp percent_safe(value), do: Regex.replace(~r/%(?![0-9A-Fa-f]{2})/, value, "%25")
end
