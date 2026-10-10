defmodule Sovite.IDNA.Punycode do
  @moduledoc """
  Punycode (RFC 3492): encodes a string of Unicode code points as ASCII
  letters, digits, and hyphens, for the A-labels of internationalized
  domain names (`xn--` followed by the encoding).

      iex> Sovite.IDNA.Punycode.encode("bücher")
      {:ok, "bcher-kva"}
      iex> Sovite.IDNA.Punycode.decode("bcher-kva")
      {:ok, "bücher"}

  Both directions work on whole labels and never raise: invalid input
  returns `:error`. Case is kept as given; the IDNA rules decide what is
  valid.
  """

  @base 36
  @tmin 1
  @tmax 26
  @skew 38
  @damp 700
  @initial_bias 72
  @initial_n 128
  # Labels are at most 63 octets; this bounds the work for any input.
  @max_length 256

  @doc "Encodes a UTF-8 string (RFC 3492 §6.3)."
  @spec encode(String.t()) :: {:ok, String.t()} | :error
  def encode(string) when is_binary(string) and byte_size(string) <= @max_length * 4 do
    with true <- String.valid?(string),
         code_points = String.to_charlist(string),
         true <- length(code_points) <= @max_length do
      basic = for c <- code_points, c < 0x80, do: c
      b = length(basic)
      output = if b > 0, do: Enum.reverse([?- | Enum.reverse(basic)]), else: []

      code_points
      |> encode_loop(%{n: @initial_n, delta: 0, bias: @initial_bias, h: b, b: b})
      |> then(&{:ok, List.to_string(output ++ &1)})
    else
      _ -> :error
    end
  end

  def encode(_), do: :error

  defp encode_loop(code_points, state, acc \\ []) do
    if state.h == length(code_points) do
      acc |> Enum.reverse() |> List.flatten()
    else
      m = code_points |> Enum.filter(&(&1 >= state.n)) |> Enum.min()
      state = %{state | delta: state.delta + (m - state.n) * (state.h + 1), n: m}

      {state, acc} = Enum.reduce(code_points, {state, acc}, &encode_step/2)
      encode_loop(code_points, %{state | delta: state.delta + 1, n: state.n + 1}, acc)
    end
  end

  defp encode_step(c, {state, acc}) do
    cond do
      c < state.n ->
        {%{state | delta: state.delta + 1}, acc}

      c == state.n ->
        digits = variable_digits(state.delta, state.bias, @base, [])
        bias = adapt(state.delta, state.h + 1, state.h == state.b)
        {%{state | delta: 0, bias: bias, h: state.h + 1}, [digits | acc]}

      true ->
        {state, acc}
    end
  end

  # The digits of q as a generalized variable-length integer.
  defp variable_digits(q, bias, k, acc) do
    t = threshold(k, bias)

    if q < t do
      Enum.reverse([digit(q) | acc])
    else
      d = t + rem(q - t, @base - t)
      variable_digits(div(q - t, @base - t), bias, k + @base, [digit(d) | acc])
    end
  end

  @doc "Decodes an encoded label into a UTF-8 string (RFC 3492 §6.2)."
  @spec decode(String.t()) :: {:ok, String.t()} | :error
  def decode(input) when is_binary(input) and byte_size(input) <= @max_length do
    {basic, extended} = split_basic(input)

    with true <- ascii?(input),
         {:ok, output} <-
           decode_loop(
             String.to_charlist(extended),
             %{n: @initial_n, i: 0, bias: @initial_bias},
             String.to_charlist(basic)
           ),
         string = List.to_string(output),
         true <- String.valid?(string) do
      {:ok, string}
    else
      _ -> :error
    end
  rescue
    # List.to_string/1 on a code point it cannot encode.
    _ in ArgumentError -> :error
  end

  def decode(_), do: :error

  # Everything before the last "-" is basic code points.
  defp split_basic(input) do
    case :binary.matches(input, "-") do
      [] ->
        {"", input}

      matches ->
        {last, _} = List.last(matches)
        {binary_part(input, 0, last), binary_part(input, last + 1, byte_size(input) - last - 1)}
    end
  end

  defp decode_loop([], _state, output), do: {:ok, output}

  defp decode_loop(input, state, output) do
    with {:ok, i, rest} <- read_integer(input, state.i, 1, state.bias, @base) do
      length = length(output) + 1
      bias = adapt(i - state.i, length, state.i == 0)
      n = state.n + div(i, length)
      i = rem(i, length)

      if valid_code_point?(n) and length <= @max_length do
        output = List.insert_at(output, i, n)
        decode_loop(rest, %{n: n, i: i + 1, bias: bias}, output)
      else
        :error
      end
    end
  end

  defp read_integer([char | rest], i, w, bias, k) do
    with {:ok, d} <- digit_value(char) do
      i = i + d * w
      t = threshold(k, bias)

      cond do
        i > 0x10FFFF * (@max_length + 1) -> :error
        d < t -> {:ok, i, rest}
        true -> read_integer(rest, i, w * (@base - t), bias, k + @base)
      end
    end
  end

  defp read_integer([], _i, _w, _bias, _k), do: :error

  defp valid_code_point?(n), do: n <= 0x10FFFF and n not in 0xD800..0xDFFF

  defp threshold(k, bias) do
    cond do
      k <= bias -> @tmin
      k >= bias + @tmax -> @tmax
      true -> k - bias
    end
  end

  defp adapt(delta, num_points, first_time) do
    delta = if first_time, do: div(delta, @damp), else: div(delta, 2)
    adapt_loop(delta + div(delta, num_points), 0)
  end

  defp adapt_loop(delta, k) do
    if delta > div((@base - @tmin) * @tmax, 2),
      do: adapt_loop(div(delta, @base - @tmin), k + @base),
      else: k + div((@base - @tmin + 1) * delta, delta + @skew)
  end

  defp digit(d) when d < 26, do: ?a + d
  defp digit(d), do: ?0 + d - 26

  defp digit_value(c) when c in ?a..?z, do: {:ok, c - ?a}
  defp digit_value(c) when c in ?A..?Z, do: {:ok, c - ?A}
  defp digit_value(c) when c in ?0..?9, do: {:ok, c - ?0 + 26}
  defp digit_value(_c), do: :error

  defp ascii?(binary), do: for(<<c <- binary>>, reduce: true, do: (acc -> acc and c < 0x80))
end
