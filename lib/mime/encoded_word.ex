defmodule Sovite.MIME.EncodedWord do
  @moduledoc """
  Header values in UTF-8: encoded words (RFC 2047, `=?utf-8?B?...?=`)
  decoded, and raw 8-bit bytes made UTF-8.

      iex> Sovite.MIME.EncodedWord.decode("=?ISO-8859-1?Q?Andr=E9?= Pirard <a@example.com>")
      "André Pirard <a@example.com>"
      iex> Sovite.MIME.EncodedWord.decode("=?utf-8?B?SGVs?= =?utf-8?B?bG8=?=")
      "Hello"

  As mail readers do, encoded words are decoded wherever they are, also
  inside quoted strings and words (RFC 2047 does not allow that, but spam
  uses it to hide words from filters that follow the rules). White space
  between two encoded words is dropped. An encoded word in a charset that
  `Sovite.Charset` does not know is left as it is.

  Raw bytes that are not UTF-8 (8-bit headers without `SMTPUTF8`) are
  taken as windows-1252.
  """

  alias Sovite.Charset
  alias Sovite.MIME.Transfer

  @word ~r/=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/

  @doc "Decodes the encoded words of a header value, and returns it in UTF-8."
  @spec decode(binary()) :: String.t()
  def decode(value) when is_binary(value) do
    value = raw_utf8(value)

    if String.contains?(value, "=?") do
      @word
      |> Regex.split(value, include_captures: true)
      |> join()
    else
      value
    end
  end

  defp raw_utf8(value) do
    if String.valid?(value),
      do: value,
      else: elem(Charset.to_utf8(value, "windows-1252"), 1)
  end

  # Text and encoded words alternate. White space between two words goes:
  # it separates them, it is not text.
  defp join(parts, acc \\ [])
  defp join([text], acc), do: [text | acc] |> Enum.reverse() |> IO.iodata_to_binary()

  defp join([text, word | rest], acc) do
    text = if acc != [] and String.trim(text) == "", do: "", else: text
    join(rest, [word(word), text | acc])
  end

  defp word(word) do
    [_all, charset, encoding, text] = Regex.run(@word, word)
    # RFC 2231 §5: a language after "*".
    charset = charset |> String.split("*") |> hd()

    bytes =
      case String.upcase(encoding) do
        "B" -> elem(Transfer.decode(text, "base64"), 1)
        "Q" -> text |> String.replace("_", " ") |> Transfer.decode("quoted-printable") |> elem(1)
      end

    case Charset.to_utf8(bytes, charset) do
      {:ok, decoded} -> decoded
      {:error, :unknown_charset} -> word
    end
  end
end
