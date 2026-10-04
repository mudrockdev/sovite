defmodule Sovite.Queue.ID do
  @moduledoc """
  Queue IDs: 14 characters from `[0-9A-Za-z]`, safe in file names.

  The first 9 characters encode the creation time in microseconds and the
  last 5 are random, so IDs are unique and sort by creation time.
  """

  @alphabet ~c"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  @time_chars 9
  @random_chars 5

  @doc "Generates a new queue ID."
  @spec generate() :: String.t()
  def generate do
    time = System.os_time(:microsecond)
    <<random::40>> = :crypto.strong_rand_bytes(5)
    encode(time, @time_chars) <> encode(random, @random_chars)
  end

  @doc "Returns `true` if `id` has the format of a queue ID."
  @spec valid?(term()) :: boolean()
  def valid?(id) when is_binary(id) and byte_size(id) == @time_chars + @random_chars,
    do: String.match?(id, ~r/\A[0-9A-Za-z]+\z/)

  def valid?(_id), do: false

  defp encode(value, length) do
    for i <- (length - 1)..0//-1, into: "" do
      <<Enum.at(@alphabet, value |> div(Integer.pow(62, i)) |> rem(62))>>
    end
  end
end
