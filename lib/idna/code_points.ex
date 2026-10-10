defmodule Sovite.IDNA.CodePoints do
  @moduledoc """
  The IDNA2008 rules for code points in U-labels: the derived property
  of RFC 5892, the contextual rules of its Appendix A, and the Bidi rule
  of RFC 5893.

  The derived property is computed from the Unicode data OTP ships
  (`:unicode_util`: general category, canonical combining class, and
  normalization), so it follows the Unicode version of the running OTP
  instead of a fixed table. OTP has no Bidi_Class, Script, or
  Joining_Type data: the Bidi rule and the contextual rules use the
  Unicode blocks of the scripts concerned instead, and a zero-width
  non-joiner is only allowed after a virama (the regular-expression
  rule, which needs Joining_Type, is not applied). Both only make the
  rules stricter.
  """

  @typedoc "RFC 5892 §2: what a code point may be used for."
  @type property :: :pvalid | :contextj | :contexto | :disallowed | :unassigned

  # RFC 5892 §2.6, Exceptions (F).
  @exceptions %{
    0x00DF => :pvalid,
    0x03C2 => :pvalid,
    0x06FD => :pvalid,
    0x06FE => :pvalid,
    0x0F0B => :pvalid,
    0x3007 => :pvalid,
    0x00B7 => :contexto,
    0x0375 => :contexto,
    0x05F3 => :contexto,
    0x05F4 => :contexto,
    0x30FB => :contexto,
    0x0640 => :disallowed,
    0x07FA => :disallowed,
    0x302E => :disallowed,
    0x302F => :disallowed,
    0x3031 => :disallowed,
    0x3032 => :disallowed,
    0x3033 => :disallowed,
    0x3034 => :disallowed,
    0x3035 => :disallowed,
    0x303B => :disallowed
  }

  @letter_digits [
    {:letter, :lowercase},
    {:letter, :uppercase},
    {:letter, :other},
    {:letter, :modifier},
    {:number, :decimal},
    {:mark, :non_spacing},
    {:mark, :spacing_combining}
  ]

  @doc """
  The IDNA2008 derived property of a code point (RFC 5892 §3).

      iex> Sovite.IDNA.CodePoints.property(?a)
      :pvalid
      iex> Sovite.IDNA.CodePoints.property(?A)
      :disallowed
      iex> Sovite.IDNA.CodePoints.property(0x200D)
      :contextj
  """
  @spec property(non_neg_integer()) :: property()
  def property(cp) when cp in ?a..?z or cp in ?0..?9 or cp == ?-, do: :pvalid
  def property(cp) when cp < 0x80, do: :disallowed

  # Exceptions (F): the two kinds of Arabic-Indic digits.
  def property(cp) when cp in 0x0660..0x0669 or cp in 0x06F0..0x06F9, do: :contexto

  def property(cp) do
    case Map.fetch(@exceptions, cp) do
      {:ok, property} -> property
      :error -> derived(cp)
    end
  end

  defp derived(cp) do
    category = :unicode_util.category(cp)

    cond do
      category == {:other, :not_assigned} and not noncharacter?(cp) -> :unassigned
      cp in [0x200C, 0x200D] -> :contextj
      disallowed?(cp, category) -> :disallowed
      category in @letter_digits -> :pvalid
      true -> :disallowed
    end
  end

  defp disallowed?(cp, category) do
    old_hangul_jamo?(cp) or unstable?(cp) or ignorable?(cp, category) or ignorable_block?(cp)
  end

  # RFC 5892 §2.9 (I).
  defp old_hangul_jamo?(cp),
    do: cp in 0x1100..0x11FF or cp in 0xA960..0xA97F or cp in 0xD7B0..0xD7FF

  # RFC 5892 §2.2 (B): changed by NFKC case folding.
  defp unstable?(cp) do
    string = <<cp::utf8>>

    folded =
      string
      |> nfkc()
      |> String.to_charlist()
      |> Enum.flat_map(&casefold/1)
      |> List.to_string()
      |> nfkc()

    folded != string
  end

  defp casefold(cp) do
    case :unicode_util.casefold([cp]) do
      [folded | _] when is_list(folded) -> folded
      [folded | _] when is_integer(folded) -> [folded]
      _ -> [cp]
    end
  end

  defp nfkc(string), do: :unicode.characters_to_nfkc_binary(string)

  # RFC 5892 §2.3 (C): Default_Ignorable_Code_Point, White_Space, and
  # Noncharacter_Code_Point. Format characters (Cf) are not letters or
  # digits anyway; these are the ignorable ones that are.
  defp ignorable?(cp, category) do
    category == {:other, :format} or :unicode_util.is_whitespace(cp) or
      noncharacter?(cp) or
      cp in [0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0] or
      cp in 0x180B..0x180F or cp in 0xFE00..0xFE0F or cp in 0xE0100..0xE01EF
  end

  defp noncharacter?(cp), do: cp in 0xFDD0..0xFDEF or Bitwise.band(cp, 0xFFFE) == 0xFFFE

  # RFC 5892 §2.4 (D).
  defp ignorable_block?(cp),
    do: cp in 0x20D0..0x20FF or cp in 0x1D100..0x1D1FF or cp in 0x1D200..0x1D24F

  @doc "Whether a code point is a combining mark (Mn, Mc, or Me)."
  @spec combining_mark?(non_neg_integer()) :: boolean()
  def combining_mark?(cp), do: match?({:mark, _}, :unicode_util.category(cp))

  ## Contextual rules (RFC 5892 Appendix A)

  @doc """
  Checks the CONTEXTJ or CONTEXTO code point at `index` of `label` (a
  list of code points).
  """
  @spec context?([non_neg_integer()], non_neg_integer()) :: boolean()
  def context?(label, index) do
    cp = Enum.at(label, index)
    before = if index > 0, do: Enum.at(label, index - 1)
    after_ = Enum.at(label, index + 1)
    rule(cp, before, after_, label)
  end

  # A.1 and A.2: ZERO WIDTH NON-JOINER and JOINER after a virama.
  defp rule(cp, before, _after, _label) when cp in [0x200C, 0x200D],
    do: before != nil and virama?(before)

  # A.3: MIDDLE DOT between two "l".
  defp rule(0x00B7, before, after_, _label), do: before == ?l and after_ == ?l

  # A.4: GREEK LOWER NUMERAL SIGN before Greek.
  defp rule(0x0375, _before, after_, _label), do: after_ != nil and greek?(after_)

  # A.5 and A.6: HEBREW GERESH and GERSHAYIM after Hebrew.
  defp rule(cp, before, _after, _label) when cp in [0x05F3, 0x05F4],
    do: before != nil and hebrew?(before)

  # A.7: KATAKANA MIDDLE DOT in a label with Hiragana, Katakana, or Han.
  defp rule(0x30FB, _before, _after, label), do: Enum.any?(label, &japanese?/1)

  # A.8 and A.9: the two kinds of Arabic-Indic digits do not mix.
  defp rule(cp, _before, _after, label) when cp in 0x0660..0x0669,
    do: not Enum.any?(label, &(&1 in 0x06F0..0x06F9))

  defp rule(cp, _before, _after, label) when cp in 0x06F0..0x06F9,
    do: not Enum.any?(label, &(&1 in 0x0660..0x0669))

  defp rule(_cp, _before, _after, _label), do: false

  defp virama?(cp), do: :unicode_util.lookup(cp)[:ccc] == 9
  defp greek?(cp), do: cp in 0x0370..0x03FF or cp in 0x1F00..0x1FFF
  defp hebrew?(cp), do: cp in 0x0590..0x05FF or cp in 0xFB1D..0xFB4F

  # Hiragana, Katakana, and Han.
  @japanese [
    {0x3040, 0x30FA},
    {0x30FC, 0x30FF},
    {0x31F0, 0x31FF},
    {0xFF66, 0xFF9F},
    {0x2E80, 0x2FDF},
    {0x3005, 0x3005},
    {0x3007, 0x3007},
    {0x3021, 0x3029},
    {0x3038, 0x303B},
    {0x3400, 0x4DBF},
    {0x4E00, 0x9FFF},
    {0xF900, 0xFAFF},
    {0x20000, 0x3FFFF}
  ]

  defp japanese?(cp), do: in_ranges?(cp, @japanese)

  defp in_ranges?(cp, ranges),
    do: Enum.any?(ranges, fn {first, last} -> cp >= first and cp <= last end)

  ## Bidi rule (RFC 5893)

  @doc """
  Whether a label has right-to-left characters (Bidi classes R, AL, or
  AN), which makes its domain a "Bidi domain name".
  """
  @spec rtl?([non_neg_integer()]) :: boolean()
  def rtl?(label), do: Enum.any?(label, &(bidi_class(&1) in [:r, :al, :an]))

  @doc "Whether a label satisfies the Bidi rule (RFC 5893 §2)."
  @spec bidi?([non_neg_integer()]) :: boolean()
  def bidi?([]), do: false

  def bidi?([first | _] = label) do
    classes = Enum.map(label, &bidi_class/1)
    ending = classes |> Enum.reverse() |> Enum.drop_while(&(&1 == :nsm)) |> List.first()

    case bidi_class(first) do
      class when class in [:r, :al] ->
        Enum.all?(classes, &(&1 in [:r, :al, :an, :en, :es, :cs, :et, :on, :bn, :nsm])) and
          ending in [:r, :al, :en, :an] and not (:en in classes and :an in classes)

      :l ->
        Enum.all?(classes, &(&1 in [:l, :en, :es, :cs, :et, :on, :bn, :nsm])) and
          ending in [:l, :en]

      _ ->
        false
    end
  end

  # An approximation of Bidi_Class from Unicode blocks, for the code
  # points U-labels can have: {first, last, class}, the first match wins.
  @bidi_ranges [
    {?0, ?9, :en},
    {?-, ?-, :es},
    {0x0660, 0x0669, :an},
    {0x066B, 0x066C, :an},
    {0x06DD, 0x06DD, :an},
    {0x06F0, 0x06F9, :en},
    {0x10D30, 0x10D39, :an},
    {0x10E60, 0x10E7E, :an},
    {0x0590, 0x05FF, :r},
    {0x07C0, 0x085F, :r},
    {0xFB1D, 0xFB4F, :r},
    {0x10800, 0x10FFF, :r},
    {0x1E800, 0x1EFFF, :r},
    {0x0600, 0x07BF, :al},
    {0x0860, 0x08FF, :al},
    {0xFB50, 0xFDFF, :al},
    {0xFE70, 0xFEFF, :al}
  ]

  defp bidi_class(cp) do
    case Enum.find(@bidi_ranges, fn {first, last, _class} -> cp >= first and cp <= last end) do
      {_first, _last, class} when class in [:en, :es, :an] -> class
      found -> mark_or(cp, found)
    end
  end

  # Non-spacing marks are NSM in any script.
  defp mark_or(cp, found) do
    cond do
      :unicode_util.category(cp) in [{:mark, :non_spacing}, {:mark, :enclosing}] -> :nsm
      found -> elem(found, 2)
      true -> :l
    end
  end
end
