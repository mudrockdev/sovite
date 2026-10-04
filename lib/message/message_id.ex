defmodule Sovite.Message.MessageID do
  @moduledoc """
  Builds `Message-ID:` values (RFC 5322 §3.6.4).

      iex> id = Sovite.Message.MessageID.generate("mx.example.com")
      iex> String.ends_with?(id, "@mx.example.com>")
      true
  """

  @doc """
  Returns a new, globally unique message ID in angle brackets: the time
  and 80 random bits, at `domain`.
  """
  @spec generate(String.t()) :: String.t()
  def generate(domain) do
    time = System.os_time(:microsecond) |> Integer.to_string(36) |> String.downcase()
    random = 10 |> :crypto.strong_rand_bytes() |> Base.encode32(case: :lower, padding: false)
    "<#{time}.#{random}@#{domain}>"
  end
end
