defmodule Sovite.Message.AddressList do
  @moduledoc """
  Rewrites the addresses in an RFC 5322 address list (the value of
  `From:`, `To:`, `Cc:`, and similar fields) and keeps every other byte:
  display names, comments, groups, and folding.

      iex> Sovite.Message.AddressList.rewrite(~s|"Alice (work)" <alice@host.example.com>, bob@x|, &String.upcase/1)
      ~s|"Alice (work)" <ALICE@HOST.EXAMPLE.COM>, BOB@X|

  `fun` gets each address as written (`local@domain`) and returns the
  replacement. Anything that does not parse as an address is left alone,
  so a malformed field passes through unchanged.
  """

  @doc "Rewrites each address in `value` with `fun`."
  @spec rewrite(binary(), (String.t() -> String.t())) :: binary()
  def rewrite(value, fun) do
    case tokenize(value, [], []) do
      {:ok, units} -> units |> Enum.map(&rewrite_unit(&1, fun)) |> IO.iodata_to_binary()
      :error -> value
    end
  end

  @doc """
  Rewrites the addresses in a whole header field (`"To: a@b\\r\\n"`), as
  kept by `Sovite.Message.Headers`.
  """
  @spec rewrite_field(binary(), (String.t() -> String.t())) :: binary()
  def rewrite_field(raw, fun) do
    case :binary.split(raw, ":") do
      [name, value] -> name <> ":" <> rewrite(value, fun)
      [_] -> raw
    end
  end

  # A unit is the pieces between two top-level separators, plus the
  # separator. Pieces: {:text, bin} | {:quoted, bin} | {:comment, bin} |
  # {:angle, bin} | {:sep, bin}.
  defp tokenize("", unit, units), do: {:ok, Enum.reverse([Enum.reverse(unit) | units])}

  defp tokenize(<<sep, rest::binary>>, unit, units) when sep in [?,, ?;, ?:] do
    unit = Enum.reverse([{:sep, <<sep>>} | unit])
    # "group-name:" is a display name, not an address.
    unit = if sep == ?:, do: Enum.map(unit, &as_text/1), else: unit
    tokenize(rest, [], [unit | units])
  end

  defp tokenize(~s(") <> rest, unit, units) do
    with {:ok, quoted, rest} <- delimited(rest, ?", ""),
         do: tokenize(rest, [{:quoted, quoted} | unit], units)
  end

  defp tokenize("(" <> rest, unit, units) do
    with {:ok, comment, rest} <- comment(rest, 1, ""),
         do: tokenize(rest, [{:comment, comment} | unit], units)
  end

  defp tokenize("<" <> rest, unit, units) do
    case :binary.split(rest, ">") do
      [inside, rest] -> tokenize(rest, [{:angle, inside} | unit], units)
      [_] -> :error
    end
  end

  defp tokenize(value, unit, units) do
    [text] = Regex.run(~r/\A[^,;:"(<]+/, value) || [binary_part(value, 0, 1)]
    rest = binary_part(value, byte_size(text), byte_size(value) - byte_size(text))
    tokenize(rest, [{:text, text} | unit], units)
  end

  defp as_text({:sep, _} = sep), do: sep
  defp as_text({_kind, _} = piece), do: {:text, encode_piece(piece)}

  defp delimited(value, close, acc) do
    case value do
      "" -> :error
      <<?\\, char, rest::binary>> -> delimited(rest, close, acc <> <<?\\, char>>)
      <<^close, rest::binary>> -> {:ok, acc <> <<close>>, rest}
      <<char, rest::binary>> -> delimited(rest, close, acc <> <<char>>)
    end
  end

  defp comment("", _depth, _acc), do: :error

  defp comment(<<?\\, char, rest::binary>>, depth, acc),
    do: comment(rest, depth, acc <> <<?\\, char>>)

  defp comment("(" <> rest, depth, acc), do: comment(rest, depth + 1, acc <> "(")
  defp comment(")" <> rest, 1, acc), do: {:ok, acc <> ")", rest}
  defp comment(")" <> rest, depth, acc), do: comment(rest, depth - 1, acc <> ")")
  defp comment(<<char, rest::binary>>, depth, acc), do: comment(rest, depth, acc <> <<char>>)

  defp rewrite_unit(pieces, fun) do
    if Enum.any?(pieces, &match?({:angle, _}, &1)),
      do: Enum.map(pieces, &rewrite_angle(&1, fun)),
      else: rewrite_bare(pieces, fun)
  end

  defp rewrite_angle({:angle, inside}, fun) do
    # An obsolete source route (<@relay:user@domain>) is kept as it is.
    {route, address} =
      case :binary.split(inside, ":") do
        [route, address] -> {route <> ":", address}
        [address] -> {"", address}
      end

    trimmed = String.trim(address)

    if trimmed != "" and String.contains?(trimmed, "@") do
      ["<", route, fun.(trimmed), ">"]
    else
      ["<", inside, ">"]
    end
  end

  defp rewrite_angle(piece, _fun), do: encode_piece(piece)

  # A bare address: the pieces between leading and trailing whitespace
  # and comments.
  defp rewrite_bare(pieces, fun) do
    {sep, pieces} =
      case List.last(pieces) do
        {:sep, _} = sep -> {[encode_piece(sep)], Enum.drop(pieces, -1)}
        _ -> {[], pieces}
      end

    {leading, rest} = Enum.split_while(pieces, &blank?/1)
    {trailing, core} = rest |> Enum.reverse() |> Enum.split_while(&blank?/1)
    core = Enum.reverse(core)
    trailing = Enum.reverse(trailing)

    address = core |> Enum.map(&encode_piece/1) |> IO.iodata_to_binary()
    {lead_ws, address} = split_leading_ws(address)
    {address, trail_ws} = split_trailing_ws(address)

    rewritten = if rewritable?(address, core), do: fun.(address), else: address

    [
      Enum.map(leading, &encode_piece/1),
      lead_ws,
      rewritten,
      trail_ws,
      Enum.map(trailing, &encode_piece/1),
      sep
    ]
  end

  # One addr-spec: has an "@", no comment inside, and no whitespace
  # outside quoted strings (a quoted local part may contain spaces).
  defp rewritable?(address, core) do
    unquoted = Regex.replace(~r/"(?:[^"\\]|\\.)*"/, address, "")

    String.contains?(address, "@") and not Enum.any?(core, &match?({:comment, _}, &1)) and
      not String.match?(unquoted, ~r/\s/)
  end

  defp blank?({:comment, _}), do: true
  defp blank?({:text, text}), do: String.trim(text) == ""
  defp blank?(_piece), do: false

  defp split_leading_ws(value) do
    trimmed = String.trim_leading(value)
    {binary_part(value, 0, byte_size(value) - byte_size(trimmed)), trimmed}
  end

  defp split_trailing_ws(value) do
    trimmed = String.trim_trailing(value)
    {trimmed, binary_part(value, byte_size(trimmed), byte_size(value) - byte_size(trimmed))}
  end

  defp encode_piece({:text, text}), do: text
  defp encode_piece({:quoted, quoted}), do: ~s(") <> quoted
  defp encode_piece({:comment, comment}), do: "(" <> comment
  defp encode_piece({:angle, inside}), do: "<" <> inside <> ">"
  defp encode_piece({:sep, sep}), do: sep
end
