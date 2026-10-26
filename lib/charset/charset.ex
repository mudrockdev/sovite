defmodule Sovite.Charset do
  @moduledoc """
  Decodes text in the charsets mail uses into UTF-8.

      iex> Sovite.Charset.to_utf8(<<"caf", 0xE9>>, "ISO-8859-1")
      {:ok, "café"}
      iex> Sovite.Charset.to_utf8(<<0x93, 0xFA, 0x96, 0x7B>>, "shift_jis")
      {:ok, "日本"}
      iex> Sovite.Charset.to_utf8("x", "x-unknown")
      {:error, :unknown_charset}

  Charset names (labels) are those of the WHATWG Encoding Standard, as
  browsers and mail readers treat them: `iso-8859-1` and `us-ascii` are
  windows-1252, `gb2312` is GBK, `ks_c_5601-1987` is EUC-KR (UHC), and
  `shift_jis` is Windows-31J. Besides those: UTF-16 and UTF-32 in either
  byte order (a byte order mark decides, big-endian without one, as RFC
  2781 says), and UTF-7, which spam uses to hide words.

  Bytes that are not valid in the charset become U+FFFD: decoding never
  fails on what a message holds, only on a charset it does not know.

  The tables of the multi-byte and single-byte charsets are made from
  Python's codecs by `scripts/charset_tables.py`, and compiled in.
  """

  import Bitwise

  @tables Path.join(__DIR__, "tables")

  @single ~w(ibm866 iso-8859-2 iso-8859-3 iso-8859-4 iso-8859-5 iso-8859-6 iso-8859-7
             iso-8859-8 iso-8859-10 iso-8859-13 iso-8859-14 iso-8859-15 iso-8859-16 koi8-r
             koi8-u macintosh windows-874 windows-1250 windows-1251 windows-1252 windows-1253
             windows-1254 windows-1255 windows-1256 windows-1257 windows-1258)

  @double ~w(gbk gb18030 big5 shift_jis euc-kr euc-jp)

  for name <- @single ++ @double ++ ~w(jis-x-0212 gb18030-ranges) do
    @external_resource Path.join(@tables, name <> ".bin")
  end

  @single_tables Map.new(@single, fn name ->
                   data = File.read!(Path.join(@tables, name <> ".bin"))
                   {name, List.to_tuple(for <<cp::16 <- data>>, do: cp)}
                 end)

  @double_tables Map.new(@double, fn name ->
                   <<"D", lead_min, lead_max, trail_min, trail_max, singles::binary-256,
                     pairs::binary>> = File.read!(Path.join(@tables, name <> ".bin"))

                   {name,
                    %{
                      lead_min: lead_min,
                      lead_max: lead_max,
                      trail: trail_min..trail_max,
                      width: trail_max - trail_min + 1,
                      singles: List.to_tuple(for <<cp::16 <- singles>>, do: cp),
                      pairs: pairs
                    }}
                 end)

  @jis0212 File.read!(Path.join(@tables, "jis-x-0212.bin"))

  @gb18030_ranges (fn ->
                     <<"R", count::16, data::binary>> =
                       File.read!(Path.join(@tables, "gb18030-ranges.bin"))

                     ranges =
                       for <<index::32, cp::32, length::32 <- data>>, do: {index, cp, length}

                     ^count = length(ranges)
                     List.to_tuple(ranges)
                   end).()

  @labels %{
    "utf-8" => ~w(unicode-1-1-utf-8 unicode11utf8 unicode20utf8 utf-8 utf8 x-unicode20utf8),
    "ibm866" => ~w(866 cp866 csibm866 ibm866),
    "iso-8859-2" =>
      ~w(csisolatin2 iso-8859-2 iso-ir-101 iso8859-2 iso88592 iso_8859-2 iso_8859-2:1987 l2 latin2),
    "iso-8859-3" =>
      ~w(csisolatin3 iso-8859-3 iso-ir-109 iso8859-3 iso88593 iso_8859-3 iso_8859-3:1988 l3 latin3),
    "iso-8859-4" =>
      ~w(csisolatin4 iso-8859-4 iso-ir-110 iso8859-4 iso88594 iso_8859-4 iso_8859-4:1988 l4 latin4),
    "iso-8859-5" =>
      ~w(csisolatincyrillic cyrillic iso-8859-5 iso-ir-144 iso8859-5 iso88595 iso_8859-5 iso_8859-5:1988),
    "iso-8859-6" =>
      ~w(arabic asmo-708 csiso88596e csiso88596i csisolatinarabic ecma-114 iso-8859-6 iso-8859-6-e iso-8859-6-i iso-ir-127 iso8859-6 iso88596 iso_8859-6 iso_8859-6:1987),
    "iso-8859-7" =>
      ~w(csisolatingreek ecma-118 elot_928 greek greek8 iso-8859-7 iso-ir-126 iso8859-7 iso88597 iso_8859-7 iso_8859-7:1987 sun_eu_greek),
    "iso-8859-8" =>
      ~w(csiso88598e csisolatinhebrew hebrew iso-8859-8 iso-8859-8-e iso-ir-138 iso8859-8 iso88598 iso_8859-8 iso_8859-8:1988 visual csiso88598i iso-8859-8-i logical),
    "iso-8859-10" => ~w(csisolatin6 iso-8859-10 iso-ir-157 iso8859-10 iso885910 l6 latin6),
    "iso-8859-13" => ~w(iso-8859-13 iso8859-13 iso885913),
    "iso-8859-14" => ~w(iso-8859-14 iso8859-14 iso885914),
    "iso-8859-15" => ~w(csisolatin9 iso-8859-15 iso8859-15 iso885915 iso_8859-15 l9 latin9),
    "iso-8859-16" => ~w(iso-8859-16),
    "koi8-r" => ~w(cskoi8r koi koi8 koi8-r koi8_r),
    "koi8-u" => ~w(koi8-ru koi8-u),
    "macintosh" => ~w(csmacintosh mac macintosh x-mac-roman),
    "windows-874" => ~w(dos-874 iso-8859-11 iso8859-11 iso885911 tis-620 windows-874),
    "windows-1250" => ~w(cp1250 windows-1250 x-cp1250),
    "windows-1251" => ~w(cp1251 windows-1251 x-cp1251),
    "windows-1252" =>
      ~w(ansi_x3.4-1968 ascii cp1252 cp819 csisolatin1 ibm819 iso-8859-1 iso-ir-100 iso8859-1 iso88591 iso_8859-1 iso_8859-1:1987 l1 latin1 us-ascii windows-1252 x-cp1252),
    "windows-1253" => ~w(cp1253 windows-1253 x-cp1253),
    "windows-1254" =>
      ~w(cp1254 csisolatin5 iso-8859-9 iso-ir-148 iso8859-9 iso88599 iso_8859-9 iso_8859-9:1989 l5 latin5 windows-1254 x-cp1254),
    "windows-1255" => ~w(cp1255 windows-1255 x-cp1255),
    "windows-1256" => ~w(cp1256 windows-1256 x-cp1256),
    "windows-1257" => ~w(cp1257 windows-1257 x-cp1257),
    "windows-1258" => ~w(cp1258 windows-1258 x-cp1258),
    "gbk" =>
      ~w(chinese csgb2312 csiso58gb231280 gb2312 gb_2312 gb_2312-80 gbk iso-ir-58 x-gbk cp936 ms936 windows-936),
    "gb18030" => ~w(gb18030),
    "big5" => ~w(big5 big5-hkscs cn-big5 csbig5 x-x-big5 cp950),
    "euc-jp" => ~w(cseucpkdfmtjapanese euc-jp x-euc-jp),
    "iso-2022-jp" => ~w(csiso2022jp iso-2022-jp),
    "shift_jis" =>
      ~w(csshiftjis ms932 ms_kanji shift-jis shift_jis sjis windows-31j x-sjis cp932),
    "euc-kr" =>
      ~w(cseuckr csksc56011987 euc-kr iso-ir-149 korean ks_c_5601-1987 ks_c_5601-1989 ksc5601 ksc_5601 windows-949 cp949),
    "utf-16be" => ~w(unicodefffe utf-16be),
    "utf-16le" => ~w(utf-16le),
    "utf-16" => ~w(csunicode iso-10646-ucs-2 ucs-2 unicode unicodefeff utf-16),
    "utf-32be" => ~w(utf-32be),
    "utf-32le" => ~w(utf-32le),
    "utf-32" => ~w(utf-32 ucs-4 iso-10646-ucs-4),
    "utf-7" => ~w(utf-7 unicode-1-1-utf-7 csunicode11utf7)
  }

  @label_names for {name, labels} <- @labels, label <- labels, into: %{}, do: {label, name}

  @replacement 0xFFFD

  @doc """
  The charset a label names, in its canonical form (`"windows-1252"` for
  `"Latin1"`), or `nil` for a label it does not know.

      iex> Sovite.Charset.canonical(" ISO-8859-1 ")
      "windows-1252"
  """
  @spec canonical(String.t()) :: String.t() | nil
  def canonical(label) when is_binary(label),
    do: Map.get(@label_names, label |> String.trim() |> String.downcase(:ascii))

  @doc "Decodes `data` in the charset `label` names into UTF-8. See the module docs."
  @spec to_utf8(binary(), String.t()) :: {:ok, String.t()} | {:error, :unknown_charset}
  def to_utf8(data, label) when is_binary(data) and is_binary(label) do
    case canonical(label) do
      nil -> {:error, :unknown_charset}
      name -> {:ok, decode(name, data)}
    end
  end

  ## Decoders

  defp decode("utf-8", <<0xEF, 0xBB, 0xBF, rest::binary>>), do: decode("utf-8", rest)
  defp decode("utf-8", data), do: String.replace_invalid(data, <<@replacement::utf8>>)

  defp decode(name, data) when is_map_key(@single_tables, name),
    do: single(data, Map.fetch!(@single_tables, name))

  defp decode("gb18030", data), do: gb18030(data, Map.fetch!(@double_tables, "gb18030"), [])

  defp decode("euc-jp", data), do: euc_jp(data, Map.fetch!(@double_tables, "euc-jp"), [])

  defp decode(name, data) when is_map_key(@double_tables, name),
    do: double(data, Map.fetch!(@double_tables, name), [])

  defp decode("iso-2022-jp", data), do: iso2022jp(data, :ascii, [])

  defp decode("utf-16", <<0xFE, 0xFF, rest::binary>>), do: utf16(rest, :big, [])
  defp decode("utf-16", <<0xFF, 0xFE, rest::binary>>), do: utf16(rest, :little, [])
  defp decode("utf-16", data), do: utf16(data, :big, [])
  defp decode("utf-16be", data), do: utf16(data, :big, [])
  defp decode("utf-16le", data), do: utf16(data, :little, [])
  defp decode("utf-32", <<0, 0, 0xFE, 0xFF, rest::binary>>), do: utf32(rest, :big, [])
  defp decode("utf-32", <<0xFF, 0xFE, 0, 0, rest::binary>>), do: utf32(rest, :little, [])
  defp decode("utf-32", data), do: utf32(data, :big, [])
  defp decode("utf-32be", data), do: utf32(data, :big, [])
  defp decode("utf-32le", data), do: utf32(data, :little, [])
  defp decode("utf-7", data), do: utf7(data, [])

  defp done(acc), do: acc |> Enum.reverse() |> IO.iodata_to_binary()

  defp char(cp) when cp in 0xD800..0xDFFF or cp > 0x10FFFF or cp == 0, do: <<@replacement::utf8>>
  defp char(cp), do: <<cp::utf8>>

  # Single-byte: ASCII, and a table for 0x80..0xFF.
  defp single(data, table) do
    for <<b <- data>>, into: "" do
      if b < 0x80, do: <<b>>, else: char(elem(table, b - 0x80))
    end
  end

  # Double-byte: single bytes (ASCII, and those the table has, such as
  # Shift_JIS's half-width katakana), or a lead byte and a trail byte.
  defp double(<<>>, _table, acc), do: done(acc)
  defp double(<<b, rest::binary>>, table, acc) when b < 0x80, do: double(rest, table, [b | acc])
  defp double(data, table, acc), do: multi(data, table, acc, &double/3)

  defp multi(<<b, rest::binary>> = data, table, acc, next) do
    case elem(table.singles, b - 0x80) do
      0 -> two_bytes(data, table, acc, next)
      cp -> next.(rest, table, [char(cp) | acc])
    end
  end

  defp two_bytes(<<lead, trail, rest::binary>>, table, acc, next)
       when lead >= table.lead_min and lead <= table.lead_max do
    case pair(table, lead, trail) do
      0 -> next.(rest_after_bad(trail, rest), table, [<<@replacement::utf8>> | acc])
      cp -> next.(rest, table, [char(cp) | acc])
    end
  end

  defp two_bytes(<<_b, rest::binary>>, table, acc, next),
    do: next.(rest, table, [<<@replacement::utf8>> | acc])

  # An invalid trail byte that is ASCII is kept, as the Encoding Standard
  # says: it can only be the start of the next character.
  defp rest_after_bad(trail, rest) when trail < 0x80, do: <<trail, rest::binary>>
  defp rest_after_bad(_trail, rest), do: rest

  defp pair(table, lead, trail) do
    if trail in table.trail do
      offset = ((lead - table.lead_min) * table.width + trail - table.trail.first) * 2
      <<_::binary-size(^offset), cp::16, _::binary>> = table.pairs
      cp
    else
      0
    end
  end

  # GB 18030: four bytes when the second is a digit.
  defp gb18030(<<b1, b2, b3, b4, rest::binary>>, table, acc)
       when b1 in 0x81..0xFE and b2 in 0x30..0x39 and b3 in 0x81..0xFE and b4 in 0x30..0x39 do
    index = (b1 - 0x81) * 12_600 + (b2 - 0x30) * 1260 + (b3 - 0x81) * 10 + (b4 - 0x30)
    gb18030(rest, table, [char(four_byte(index)) | acc])
  end

  defp gb18030(<<b, rest::binary>>, table, acc) when b < 0x80, do: gb18030(rest, table, [b | acc])
  defp gb18030(<<>>, _table, acc), do: done(acc)
  defp gb18030(data, table, acc), do: multi(data, table, acc, &gb18030/3)

  defp four_byte(index) when index >= 189_000 and index < 189_000 + 0x100000,
    do: 0x10000 + index - 189_000

  defp four_byte(index), do: range_lookup(index, 0, tuple_size(@gb18030_ranges) - 1)

  defp range_lookup(_index, low, high) when low > high, do: @replacement

  defp range_lookup(index, low, high) do
    middle = div(low + high, 2)
    {first, cp, length} = elem(@gb18030_ranges, middle)

    cond do
      index < first -> range_lookup(index, low, middle - 1)
      index >= first + length -> range_lookup(index, middle + 1, high)
      true -> cp + index - first
    end
  end

  # EUC-JP: JIS X 0208 and half-width katakana in two bytes, JIS X 0212
  # after 0x8F.
  defp euc_jp(<<0x8F, l, t, rest::binary>>, table, acc) when l in 0xA1..0xFE and t in 0xA1..0xFE,
    do: euc_jp(rest, table, [char(jis0212(l - 0xA1, t - 0xA1)) | acc])

  defp euc_jp(<<b, rest::binary>>, table, acc) when b < 0x80, do: euc_jp(rest, table, [b | acc])
  defp euc_jp(<<>>, _table, acc), do: done(acc)
  defp euc_jp(data, table, acc), do: multi(data, table, acc, &euc_jp/3)

  defp jis0212(row, cell) do
    offset = (row * 94 + cell) * 2
    <<_::binary-size(^offset), cp::16, _::binary>> = @jis0212
    if cp == 0, do: @replacement, else: cp
  end

  # ISO-2022-JP (RFC 1468): escape sequences switch between ASCII, JIS X
  # 0208 (two bytes, as in EUC-JP without the high bit), JIS X 0212, and
  # half-width katakana.
  defp iso2022jp(<<>>, _mode, acc), do: done(acc)
  defp iso2022jp(<<0x1B, "(B", rest::binary>>, _mode, acc), do: iso2022jp(rest, :ascii, acc)
  defp iso2022jp(<<0x1B, "(J", rest::binary>>, _mode, acc), do: iso2022jp(rest, :ascii, acc)
  defp iso2022jp(<<0x1B, "(I", rest::binary>>, _mode, acc), do: iso2022jp(rest, :katakana, acc)
  defp iso2022jp(<<0x1B, "$@", rest::binary>>, _mode, acc), do: iso2022jp(rest, :jis0208, acc)
  defp iso2022jp(<<0x1B, "$B", rest::binary>>, _mode, acc), do: iso2022jp(rest, :jis0208, acc)
  defp iso2022jp(<<0x1B, "$(D", rest::binary>>, _mode, acc), do: iso2022jp(rest, :jis0212, acc)

  defp iso2022jp(<<l, t, rest::binary>>, :jis0208, acc)
       when l in 0x21..0x7E and t in 0x21..0x7E do
    cp = pair(Map.fetch!(@double_tables, "euc-jp"), l + 0x80, t + 0x80)
    iso2022jp(rest, :jis0208, [char(if cp == 0, do: @replacement, else: cp) | acc])
  end

  defp iso2022jp(<<l, t, rest::binary>>, :jis0212, acc) when l in 0x21..0x7E and t in 0x21..0x7E,
    do: iso2022jp(rest, :jis0212, [char(jis0212(l - 0x21, t - 0x21)) | acc])

  defp iso2022jp(<<b, rest::binary>>, :katakana, acc) when b in 0x21..0x5F,
    do: iso2022jp(rest, :katakana, [char(0xFF61 + b - 0x21) | acc])

  defp iso2022jp(<<b, rest::binary>>, mode, acc) when b < 0x80 and mode == :ascii,
    do: iso2022jp(rest, mode, [b | acc])

  defp iso2022jp(<<_b, rest::binary>>, mode, acc),
    do: iso2022jp(rest, mode, [<<@replacement::utf8>> | acc])

  # UTF-16, with surrogate pairs.
  defp utf16(<<>>, _order, acc), do: done(acc)
  defp utf16(<<_odd>>, _order, acc), do: done([<<@replacement::utf8>> | acc])

  defp utf16(data, order, acc) do
    case unit(data, order) do
      {high, rest} when high in 0xD800..0xDBFF ->
        case rest != "" and byte_size(rest) >= 2 and unit(rest, order) do
          {low, rest} when low in 0xDC00..0xDFFF ->
            utf16(rest, order, [char(0x10000 + ((high - 0xD800) <<< 10) + (low - 0xDC00)) | acc])

          _ ->
            utf16(rest, order, [<<@replacement::utf8>> | acc])
        end

      {unit, rest} ->
        utf16(rest, order, [char(unit) | acc])
    end
  end

  defp unit(<<u::16-big, rest::binary>>, :big), do: {u, rest}
  defp unit(<<u::16-little, rest::binary>>, :little), do: {u, rest}

  defp utf32(<<>>, _order, acc), do: done(acc)
  defp utf32(<<cp::32-big, rest::binary>>, :big, acc), do: utf32(rest, :big, [char(cp) | acc])

  defp utf32(<<cp::32-little, rest::binary>>, :little, acc),
    do: utf32(rest, :little, [char(cp) | acc])

  defp utf32(_partial, _order, acc), do: done([<<@replacement::utf8>> | acc])

  # UTF-7 (RFC 2152): "+" starts modified base64 of UTF-16, "-" (or any
  # other character) ends it, "+-" is "+".
  defp utf7(<<>>, acc), do: done(acc)
  defp utf7(<<"+-", rest::binary>>, acc), do: utf7(rest, [?+ | acc])

  defp utf7(<<"+", rest::binary>>, acc) do
    {encoded, rest} = base64_run(rest, [])
    rest = with <<"-", after_dash::binary>> <- rest, do: after_dash
    utf7(rest, [utf7_base64(encoded) | acc])
  end

  defp utf7(<<b, rest::binary>>, acc) when b < 0x80, do: utf7(rest, [b | acc])
  defp utf7(<<_b, rest::binary>>, acc), do: utf7(rest, [<<@replacement::utf8>> | acc])

  defp base64_run(<<c, rest::binary>>, acc)
       when c in ?A..?Z or c in ?a..?z or c in ?0..?9 or c in [?+, ?/],
       do: base64_run(rest, [c | acc])

  defp base64_run(rest, acc), do: {acc |> Enum.reverse() |> List.to_string(), rest}

  defp utf7_base64(encoded) do
    bits = for <<c <- encoded>>, into: <<>>, do: <<base64_value(c)::6>>
    whole = div(bit_size(bits), 16) * 16
    <<units::bitstring-size(^whole), _padding::bitstring>> = bits
    utf16(units, :big, [])
  end

  defp base64_value(c) when c in ?A..?Z, do: c - ?A
  defp base64_value(c) when c in ?a..?z, do: c - ?a + 26
  defp base64_value(c) when c in ?0..?9, do: c - ?0 + 52
  defp base64_value(?+), do: 62
  defp base64_value(?/), do: 63
end
