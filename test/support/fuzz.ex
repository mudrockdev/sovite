defmodule Sovite.Test.Fuzz do
  @moduledoc """
  Generators for the fuzz tests in `test/fuzz/`, tagged `:fuzz`.

  Inputs are random bytes, and mutations of real inputs (seeds): bits
  flipped, bytes replaced with ones that parsers treat specially, tokens
  of the format inserted, parts deleted, duplicated, or cut off. The
  mutations are generated as data, so StreamData shrinks a failure to
  the seed and the fewest mutations that cause it.

  `mix test` runs each property `runs/0` times (100 by default).
  `mix fuzz` runs only these, many more times:

      mix fuzz                      # FUZZ_RUNS=10000
      FUZZ_RUNS=200000 mix fuzz test/fuzz/smtp_fuzz_test.exs
  """

  use ExUnitProperties

  @special [0, ?\t, ?\n, ?\r, ?\s, ?", ?(, ?), ?,, ?., ?:, ?;, ?<, ?=, ?>, ?@, ?[, ?\\, ?], ?%] ++
             [?{, ?}, ?+, ?-, ?/, ?#, 0x7F, 0x80, 0xBF, 0xC0, 0xC3, 0xE2, 0xF0, 0xFF]

  @doc "How many inputs each property tries: `FUZZ_RUNS`, or 100."
  def runs do
    case Integer.parse(System.get_env("FUZZ_RUNS", "")) do
      {runs, ""} when runs > 0 -> runs
      _ -> 100
    end
  end

  @doc "Random bytes, biased toward the bytes parsers treat specially."
  def bytes(opts \\ []) do
    byte = frequency([{3, integer(0..255)}, {2, member_of(@special)}, {3, integer(?a..?z)}])
    gen(all(list <- list_of(byte, opts), do: :erlang.list_to_binary(list)))
  end

  @doc """
  Mutations of `seeds` (a non-empty list of binaries). `tokens` are
  pieces of the format that are inserted too, such as `"\\r\\n"` or `"="`.
  """
  def mutated(seeds, tokens \\ []) do
    tokens = Enum.uniq(tokens ++ ["\r\n", "\n", "\r", " ", ""])

    mutation =
      one_of([
        tuple({constant(:flip), non_negative_integer(), integer(0..7)}),
        tuple({constant(:replace), non_negative_integer(), member_of(@special)}),
        tuple({constant(:insert), non_negative_integer(), member_of(tokens)}),
        tuple({constant(:insert), non_negative_integer(), bytes(max_length: 8)}),
        tuple({constant(:delete), non_negative_integer(), integer(1..16)}),
        tuple({constant(:duplicate), non_negative_integer(), integer(1..64)}),
        tuple({constant(:truncate), non_negative_integer()})
      ])

    gen all(seed <- member_of(seeds), mutations <- list_of(mutation, max_length: 6)) do
      Enum.reduce(mutations, seed, &mutate/2)
    end
  end

  @doc "Seeds, their mutations, or random bytes."
  def input(seeds, tokens \\ []) do
    frequency([{1, member_of(seeds)}, {6, mutated(seeds, tokens)}, {2, bytes(max_length: 200)}])
  end

  @doc "`binary` cut into pieces at random points, as it may arrive from a socket."
  def chunked(binary) do
    gen all(cuts <- list_of(integer(0..byte_size(binary)), max_length: 8)) do
      cuts = cuts |> Enum.uniq() |> Enum.sort()

      {chunks, last} =
        Enum.reduce(cuts, {[], 0}, fn cut, {chunks, from} ->
          {[binary_part(binary, from, cut - from) | chunks], cut}
        end)

      Enum.reverse([binary_part(binary, last, byte_size(binary) - last) | chunks])
    end
  end

  @doc """
  Runs `fun` and fails if it takes longer than `limit` milliseconds:
  parsers must not be made slow by their input (backtracking regular
  expressions, quadratic loops).
  """
  def quick(fun, limit \\ 1_000) do
    {time, result} = :timer.tc(fun, :millisecond)

    if time > limit,
      do: raise(ExUnit.AssertionError, message: "took #{time} ms, the limit is #{limit} ms")

    result
  end

  defp mutate(_mutation, <<>>), do: <<>>

  defp mutate({:flip, at, bit}, binary) do
    at = rem(at, byte_size(binary))
    <<before::binary-size(^at), byte, rest::binary>> = binary
    <<before::binary, Bitwise.bxor(byte, Bitwise.bsl(1, bit)), rest::binary>>
  end

  defp mutate({:replace, at, byte}, binary) do
    at = rem(at, byte_size(binary))
    <<before::binary-size(^at), _, rest::binary>> = binary
    <<before::binary, byte, rest::binary>>
  end

  defp mutate({:insert, at, bytes}, binary) do
    at = rem(at, byte_size(binary) + 1)
    <<before::binary-size(^at), rest::binary>> = binary
    before <> bytes <> rest
  end

  defp mutate({:delete, at, length}, binary) do
    at = rem(at, byte_size(binary))
    length = min(length, byte_size(binary) - at)
    <<before::binary-size(^at), _::binary-size(^length), rest::binary>> = binary
    before <> rest
  end

  defp mutate({:duplicate, at, length}, binary) do
    at = rem(at, byte_size(binary))
    length = min(length, byte_size(binary) - at)
    <<before::binary-size(^at), part::binary-size(^length), rest::binary>> = binary
    before <> part <> part <> rest
  end

  defp mutate({:truncate, at}, binary), do: binary_part(binary, 0, rem(at, byte_size(binary)))
end
