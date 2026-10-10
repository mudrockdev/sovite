defmodule Sovite.ProxyProtocol.CRC32C do
  @moduledoc """
  CRC-32C (Castagnoli, RFC 3720 / RFC 4960 Appendix B), the checksum of
  `PP2_TYPE_CRC32C`. Erlang only has the IEEE CRC-32 built in.
  """

  import Bitwise

  # Reflected form of the polynomial 0x1EDC6F41.
  @polynomial 0x82F63B78

  @table List.to_tuple(
           for n <- 0..255 do
             Enum.reduce(1..8, n, fn _, crc ->
               if (crc &&& 1) == 1, do: bxor(crc >>> 1, @polynomial), else: crc >>> 1
             end)
           end
         )

  @doc """
  Returns the CRC-32C of `data`.

      iex> Sovite.ProxyProtocol.CRC32C.checksum("123456789")
      0xE3069283
      iex> Sovite.ProxyProtocol.CRC32C.checksum("")
      0
  """
  @spec checksum(iodata()) :: non_neg_integer()
  def checksum(data), do: data |> IO.iodata_to_binary() |> update(0xFFFFFFFF) |> bxor(0xFFFFFFFF)

  defp update(<<byte, rest::binary>>, crc),
    do: update(rest, bxor(crc >>> 8, elem(@table, bxor(crc, byte) &&& 0xFF)))

  defp update(<<>>, crc), do: crc
end
