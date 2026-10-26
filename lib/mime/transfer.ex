defmodule Sovite.MIME.Transfer do
  @moduledoc """
  Content transfer encodings (RFC 2045 §6): base64 and quoted-printable
  are decoded, `7bit`, `8bit`, `binary`, and unknown encodings are taken
  as they are.

  Mail in the wild breaks the rules, and senders of spam break them on
  purpose, so decoding is lenient: characters outside the base64
  alphabet are skipped and missing padding is allowed; a broken `=`
  escape in quoted-printable is kept as it is. `decode/2` says whether
  it had to.

      iex> Sovite.MIME.Transfer.decode("aGVs\\r\\nbG8=", "base64")
      {:ok, "hello"}
      iex> Sovite.MIME.Transfer.decode("caf=C3=A9 =\\r\\nau lait", "quoted-printable")
      {:ok, "café au lait"}
      iex> Sovite.MIME.Transfer.decode("=ZZ", "quoted-printable")
      {:damaged, "=ZZ"}
  """

  import Bitwise

  @doc """
  Decodes `data` in `encoding` (case-insensitive). `{:damaged, data}`
  when the encoding was broken: the data is decoded as well as it could.
  """
  @spec decode(binary(), String.t() | nil) :: {:ok, binary()} | {:damaged, binary()}
  def decode(data, encoding) when is_binary(data) do
    case encoding && encoding |> String.trim() |> String.downcase(:ascii) do
      "base64" -> base64(data)
      "quoted-printable" -> quoted_printable(data)
      _other -> {:ok, data}
    end
  end

  ## base64

  defp base64(data) do
    {sextets, skipped} = sextets(data, [], false)
    bits = for s <- Enum.reverse(sextets), into: <<>>, do: <<s::6>>
    whole = div(bit_size(bits), 8) * 8
    <<bytes::binary-size(div(^whole, 8)), rest::bitstring>> = bits
    # Leftover bits are padding when they are zero.
    clean = not skipped and (bit_size(rest) == 0 or zero?(rest)) and bit_size(rest) < 6
    if clean, do: {:ok, bytes}, else: {:damaged, bytes}
  end

  defp zero?(bits) do
    size = bit_size(bits)
    <<value::size(^size)>> = bits
    value == 0
  end

  # The sextets of `data`, and whether anything but the alphabet, white
  # space, and trailing padding was skipped. Decoding stops at padding.
  defp sextets(<<>>, acc, skipped), do: {acc, skipped}
  defp sextets(<<?=, rest::binary>>, acc, skipped), do: {acc, skipped or not padding?(rest)}

  defp sextets(<<c, rest::binary>>, acc, skipped) do
    case value(c) do
      nil -> sextets(rest, acc, skipped or c not in ~c" \t\r\n")
      v -> sextets(rest, [v | acc], skipped)
    end
  end

  defp padding?(rest), do: String.trim(rest, "=") |> String.trim() == ""

  defp value(c) when c in ?A..?Z, do: c - ?A
  defp value(c) when c in ?a..?z, do: c - ?a + 26
  defp value(c) when c in ?0..?9, do: c - ?0 + 52
  defp value(?+), do: 62
  defp value(?/), do: 63
  defp value(_c), do: nil

  ## quoted-printable

  defp quoted_printable(data), do: qp(data, [], true)

  defp qp(<<>>, acc, clean), do: result(acc, clean)

  # A soft line break ("=" at the end of a line, perhaps after white
  # space), or an escape.
  defp qp(<<?=, rest::binary>>, acc, clean) do
    case soft_break(rest) do
      {:ok, rest} -> qp(rest, acc, clean)
      :error -> escape(rest, acc, clean)
    end
  end

  # Trailing white space on a line is not part of the text (RFC 2045 §6.7 rule 3).
  defp qp(<<c, _::binary>> = data, acc, clean) when c in [?\s, ?\t] do
    {blanks, rest} = blanks(data, [])

    case rest do
      "" -> qp(rest, acc, clean)
      <<"\r\n", _::binary>> -> qp(rest, acc, clean)
      <<"\n", _::binary>> -> qp(rest, acc, clean)
      _text -> qp(rest, [blanks | acc], clean)
    end
  end

  defp qp(<<c, rest::binary>>, acc, clean), do: qp(rest, [c | acc], clean)

  # A broken escape is kept as it is.
  defp escape(<<h, l, after_escape::binary>> = rest, acc, clean) do
    case hex(h, l) do
      {:ok, byte} -> qp(after_escape, [byte | acc], clean)
      :error -> qp(rest, [?= | acc], false)
    end
  end

  defp escape(rest, acc, _clean), do: qp(rest, [?= | acc], false)

  defp blanks(<<c, rest::binary>>, acc) when c in [?\s, ?\t], do: blanks(rest, [c | acc])
  defp blanks(rest, acc), do: {Enum.reverse(acc), rest}

  defp skip_blanks(<<c, rest::binary>>) when c in [?\s, ?\t], do: skip_blanks(rest)
  defp skip_blanks(rest), do: rest

  defp soft_break(rest) do
    case skip_blanks(rest) do
      <<"\r\n", rest::binary>> -> {:ok, rest}
      <<"\n", rest::binary>> -> {:ok, rest}
      "" -> {:ok, ""}
      _ -> :error
    end
  end

  defp hex(h, l) do
    with {:ok, high} <- digit(h), {:ok, low} <- digit(l), do: {:ok, (high <<< 4) + low}
  end

  defp digit(c) when c in ?0..?9, do: {:ok, c - ?0}
  defp digit(c) when c in ?A..?F, do: {:ok, c - ?A + 10}
  # Lower case is not allowed, but is common.
  defp digit(c) when c in ?a..?f, do: {:ok, c - ?a + 10}
  defp digit(_c), do: :error

  defp result(acc, clean) do
    bytes = acc |> Enum.reverse() |> IO.iodata_to_binary()
    if clean, do: {:ok, bytes}, else: {:damaged, bytes}
  end
end
