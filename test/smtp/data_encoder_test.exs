defmodule Sovite.SMTP.DataEncoderTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.SMTP.{DataDecoder, DataEncoder}

  defp encode(chunks) do
    {data, encoder} =
      Enum.reduce(chunks, {[], DataEncoder.new()}, fn chunk, {acc, encoder} ->
        {data, encoder} = DataEncoder.encode(encoder, chunk)
        {[acc, data], encoder}
      end)

    IO.iodata_to_binary([data, DataEncoder.finish(encoder)])
  end

  test "stuffs leading dots, also across chunk boundaries" do
    assert encode([".a\r\nb\r\n.c\r\n"]) == "..a\r\nb\r\n..c\r\n.\r\n"
    assert encode(["a\r\n", ".b\r\n"]) == "a\r\n..b\r\n.\r\n"
    assert encode(["a\r", "\n.b\r\n"]) == "a\r\n..b\r\n.\r\n"
    assert encode(["a", ".b\r\n"]) == "a.b\r\n.\r\n"
  end

  test "a line with a single dot cannot end the data" do
    assert encode(["a\r\n.\r\nb\r\n"]) == "a\r\n..\r\nb\r\n.\r\n"
  end

  test "adds the final CRLF when missing" do
    assert encode([]) == ".\r\n"
    assert encode(["", []]) == ".\r\n"
    assert encode(["no newline"]) == "no newline\r\n.\r\n"
    assert encode(["cr\r"]) == "cr\r\n.\r\n"
  end

  property "the server-side decoder gets back the original message" do
    check all(
            lines <- list_of(string([?., ?a, ?\s], max_length: 5), max_length: 10),
            split <- list_of(integer(1..7), max_length: 10)
          ) do
      message = Enum.map_join(lines, &(&1 <> "\r\n"))
      chunks = chunk(message, split)

      assert {:done, decoded, ""} = DataDecoder.decode(DataDecoder.new(), encode(chunks))
      assert IO.iodata_to_binary(decoded) == message
    end
  end

  defp chunk(binary, []), do: [binary]

  defp chunk(binary, [size | sizes]) when byte_size(binary) > size do
    <<head::binary-size(^size), rest::binary>> = binary
    [head | chunk(rest, sizes)]
  end

  defp chunk(binary, _sizes), do: [binary]
end
