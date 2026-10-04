defmodule Sovite.SMTP.DataDecoderTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.SMTP.DataDecoder

  # Decodes `chunks` one at a time, as they would arrive from a socket.
  # Chunks after the end of data are part of the rest.
  defp decode(chunks, policy \\ :reject),
    do: decode_chunks(DataDecoder.new(policy), List.wrap(chunks), [])

  defp decode_chunks(_decoder, [], acc), do: {:more, IO.iodata_to_binary(acc)}

  defp decode_chunks(decoder, [chunk | chunks], acc) do
    case DataDecoder.decode(decoder, chunk) do
      {:more, content, decoder} ->
        decode_chunks(decoder, chunks, [acc, content])

      {:done, content, rest} ->
        {:done, IO.iodata_to_binary([acc, content]), IO.iodata_to_binary([rest | chunks])}

      {:error, reason, content} ->
        {:error, reason, IO.iodata_to_binary([acc, content])}
    end
  end

  defp stuff(content), do: String.replace(content, ~r/^\./m, "..")

  test "ends at CRLF.CRLF and returns the rest" do
    assert decode("Subject: x\r\n\r\nbody\r\n.\r\nQUIT\r\n") ==
             {:done, "Subject: x\r\n\r\nbody\r\n", "QUIT\r\n"}
  end

  test "an empty message is a lone dot" do
    assert decode(".\r\n") == {:done, "", ""}
  end

  test "removes dot-stuffing" do
    assert decode("..leading\r\n...two\r\na.b\r\n.\r\n") ==
             {:done, ".leading\r\n..two\r\na.b\r\n", ""}
  end

  test "handles the terminator split across chunks" do
    for split <- ["x\r", "\n", ".", "\r", "\n"] |> Enum.scan(&(&2 <> &1)) do
      input = "x\r\n.\r\n"
      rest = binary_part(input, byte_size(split), byte_size(input) - byte_size(split))
      assert decode([split, rest]) == {:done, "x\r\n", ""}
    end

    assert decode(["a\r\n.", "x\r\n.\r\n"]) == {:done, "a\r\nx\r\n", ""}
    assert decode(["a\r\n.\r", "\n"]) == {:done, "a\r\n", ""}
  end

  test "is not done until the terminator arrives" do
    assert decode(["line one\r\n", "line two"]) == {:more, "line one\r\nline two"}
  end

  describe "SMTP smuggling" do
    # Sequences that some MTAs have treated as end of data.
    @vectors ["\n.\n", "\n.\r\n", "\r.\r", "\r.\r\n", "\r\n.\n", "\r\n.\r"]

    test "rejects every bare line ending under :reject" do
      for vector <- @vectors do
        assert {:error, reason, content} =
                 decode("a" <> vector <> "MAIL FROM:<x@evil.test>\r\n.\r\n")

        assert reason in [:bare_lf, :bare_cr]
        assert content in ["a", "a\r\n"]
      end
    end

    test "never ends the data on them under :normalize" do
      for vector <- @vectors do
        assert {:done, content, ""} =
                 decode("a" <> vector <> "MAIL FROM:<x@evil.test>\r\n.\r\n", :normalize)

        # The smuggled command stays inside the message.
        assert content =~ "MAIL FROM:<x@evil.test>\r\n"
        refute content =~ ~r/[^\r]\n|\r[^\n]/
      end
    end

    test "rejects a bare LF split across chunks" do
      assert {:error, :bare_lf, "a"} = decode(["a", "\nb\r\n.\r\n"])
      assert {:error, :bare_cr, "a"} = decode(["a\r", "b"])
    end
  end

  test ":normalize converts bare line endings to CRLF" do
    assert decode("a\nb\rc\r\n.\r\n", :normalize) == {:done, "a\r\nb\r\nc\r\n", ""}
  end

  property "decodes stuffed content split at any points" do
    check all(
            lines <- list_of(string([?., ?a..?c], max_length: 8), max_length: 10),
            rest <- string(?A..?C, max_length: 5),
            splits <- list_of(integer(0..200), max_length: 6)
          ) do
      content = Enum.map_join(lines, &(&1 <> "\r\n"))
      wire = stuff(content) <> ".\r\n" <> rest

      chunks =
        splits
        |> Enum.map(&min(&1, byte_size(wire)))
        |> Enum.concat([0, byte_size(wire)])
        |> Enum.sort()
        |> Enum.dedup()
        |> Enum.chunk_every(2, 1, :discard)
        |> Enum.map(fn [from, to] -> binary_part(wire, from, to - from) end)

      assert decode(chunks) == {:done, content, rest}
    end
  end
end
