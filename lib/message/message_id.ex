defmodule Sovite.Message.MessageID do
  @moduledoc """
  Builds and parses `Message-ID:` values (RFC 5322 §3.6.4).

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

  @atext "[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
  @id ~r/\A<((?:#{@atext}(?:\.#{@atext})*)|"(?:[^"\\]|\\.)*")@((?:#{@atext}(?:\.#{@atext})*)|\[[^\[\]\\]*\])>\z/

  @doc """
  Parses a message ID: `{:ok, left, right}` for `<left@right>`, with
  comments and white space around it, or `:error`.

      iex> Sovite.Message.MessageID.parse(" <abc.123@mx.example.com> (sent)")
      {:ok, "abc.123", "mx.example.com"}
      iex> Sovite.Message.MessageID.parse("abc@mx.example.com")
      :error
  """
  @spec parse(String.t()) :: {:ok, String.t(), String.t()} | :error
  def parse(value) when is_binary(value) do
    text = value |> uncomment() |> String.trim()

    case Regex.run(@id, text) do
      [_, left, right] -> {:ok, left, right}
      nil -> :error
    end
  end

  # Comments nest: the innermost go first.
  defp uncomment(text) do
    case Regex.replace(~r/\([^()]*\)/, text, "") do
      ^text -> text
      shorter -> uncomment(shorter)
    end
  end
end
