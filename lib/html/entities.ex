defmodule Sovite.HTML.Entities do
  @moduledoc """
  Character references in HTML (`&amp;`, `&#233;`, `&#xE9;`), as the
  HTML Standard decodes them: the named references of HTML5 (made from
  Python's `html.entities` by `scripts/html_entities.py`), the legacy
  ones that need no `;` (`&amp`, `&copy`), numbers in decimal and hex,
  with 0x80-0x9F taken as windows-1252 and invalid code points as
  U+FFFD.

      iex> Sovite.HTML.Entities.decode("caf&eacute; &amp &#x41;&#66;&#128;")
      "café & AB€"
  """

  @external_resource Path.join(__DIR__, "entities.txt")

  @entities __DIR__
            |> Path.join("entities.txt")
            |> File.read!()
            |> String.split("\n", trim: true)
            |> Map.new(fn line ->
              [name | points] = String.split(line, " ")
              {name, points |> Enum.map(&String.to_integer(&1, 16)) |> List.to_string()}
            end)

  # Named references that need no ";", longest first, for prefix matching.
  @legacy @entities
          |> Map.keys()
          |> Enum.reject(&String.ends_with?(&1, ";"))
          |> Enum.sort_by(&(-byte_size(&1)))

  # The HTML Standard's replacements for C1 control code points.
  @c1 %{
    0x80 => 0x20AC,
    0x82 => 0x201A,
    0x83 => 0x0192,
    0x84 => 0x201E,
    0x85 => 0x2026,
    0x86 => 0x2020,
    0x87 => 0x2021,
    0x88 => 0x02C6,
    0x89 => 0x2030,
    0x8A => 0x0160,
    0x8B => 0x2039,
    0x8C => 0x0152,
    0x8E => 0x017D,
    0x91 => 0x2018,
    0x92 => 0x2019,
    0x93 => 0x201C,
    0x94 => 0x201D,
    0x95 => 0x2022,
    0x96 => 0x2013,
    0x97 => 0x2014,
    0x98 => 0x02DC,
    0x99 => 0x2122,
    0x9A => 0x0161,
    0x9B => 0x203A,
    0x9C => 0x0153,
    0x9E => 0x017E,
    0x9F => 0x0178
  }

  @reference ~r/&(?:#([0-9]{1,8});?|#[xX]([0-9a-fA-F]{1,7});?|([A-Za-z][A-Za-z0-9]{0,31})(;?))/

  @doc "Decodes the character references in `text` (UTF-8)."
  @spec decode(String.t()) :: String.t()
  def decode(text) when is_binary(text) do
    if String.contains?(text, "&"),
      do: Regex.replace(@reference, text, &reference/5),
      else: text
  end

  defp reference(_all, decimal, "", "", "") when decimal != "",
    do: number(String.to_integer(decimal))

  defp reference(_all, "", hex, "", "") when hex != "", do: number(String.to_integer(hex, 16))

  defp reference(all, "", "", name, ";") do
    case Map.fetch(@entities, name <> ";") do
      {:ok, text} -> text
      :error -> legacy(all, name, ";")
    end
  end

  defp reference(all, "", "", name, ""), do: legacy(all, name, "")

  # A legacy reference may be followed by more letters: "&notit" is "¬it".
  defp legacy(all, name, tail) do
    case Enum.find(@legacy, &String.starts_with?(name, &1)) do
      nil ->
        all

      prefix ->
        Map.fetch!(@entities, prefix) <>
          binary_part(name, byte_size(prefix), byte_size(name) - byte_size(prefix)) <> tail
    end
  end

  defp number(0), do: "�"
  defp number(cp) when cp in 0xD800..0xDFFF or cp > 0x10FFFF, do: "�"
  defp number(cp) when is_map_key(@c1, cp), do: <<Map.fetch!(@c1, cp)::utf8>>
  defp number(cp), do: <<cp::utf8>>
end
