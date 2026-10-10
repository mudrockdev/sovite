defmodule Sovite.SMTP.XText do
  @moduledoc """
  The xtext encoding of ESMTP parameter values (RFC 3461 §4): `+` and
  `=`, and bytes outside `!`..`~`, are written as `+` and two upper-case
  hex digits. Used by `XCLIENT`, `XFORWARD`, and DSN `ORCPT`/`ENVID`.

      iex> Sovite.SMTP.XText.encode("a b+c=d")
      "a+20b+2Bc+3Dd"
      iex> Sovite.SMTP.XText.decode("a+20b+2Bc+3Dd")
      {:ok, "a b+c=d"}
      iex> Sovite.SMTP.XText.decode("a+2")
      :error
  """

  @doc "Encodes `value` as xtext."
  @spec encode(binary()) :: String.t()
  def encode(value) when is_binary(value) do
    for <<byte <- value>>, into: "" do
      if byte in 33..126 and byte not in [?+, ?=],
        do: <<byte>>,
        else: "+" <> Base.encode16(<<byte>>)
    end
  end

  @doc "Decodes xtext. Hex digits may be in either case."
  @spec decode(binary()) :: {:ok, binary()} | :error
  def decode(value) when is_binary(value), do: decode(value, [])

  defp decode(<<>>, acc), do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}

  defp decode(<<?+, hex::binary-size(2), rest::binary>>, acc) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, byte} -> decode(rest, [byte | acc])
      :error -> :error
    end
  end

  defp decode(<<byte, rest::binary>>, acc) when byte in 33..126 and byte not in [?+, ?=],
    do: decode(rest, [byte | acc])

  defp decode(_value, _acc), do: :error
end
