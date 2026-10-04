defmodule Sovite.SMTP.Reply do
  @moduledoc """
  An SMTP reply: a code, an optional enhanced status code (RFC 3463), and
  one or more text lines.

      iex> Sovite.SMTP.Reply.new(250, "2.1.0", "Ok") |> Sovite.SMTP.Reply.encode() |> IO.iodata_to_binary()
      "250 2.1.0 Ok\\r\\n"
  """

  @enforce_keys [:code, :lines]
  defstruct [:code, :lines, enhanced: nil]

  @type t :: %__MODULE__{
          code: 200..599,
          enhanced: String.t() | nil,
          lines: [String.t(), ...]
        }

  @doc """
  Builds a reply. `text` is a string or a list of lines. CR and LF in the
  text are replaced with spaces, so text can never end a reply early.
  """
  @spec new(200..599, String.t() | nil, String.t() | [String.t()]) :: t()
  def new(code, enhanced \\ nil, text) when code in 200..599 do
    lines = text |> List.wrap() |> Enum.map(&String.replace(&1, ["\r", "\n"], " "))
    %__MODULE__{code: code, enhanced: enhanced, lines: if(lines == [], do: [""], else: lines)}
  end

  @doc "Returns `true` for 2xx and 3xx replies."
  @spec positive?(t()) :: boolean()
  def positive?(%__MODULE__{code: code}), do: code < 400

  @doc "Returns `true` for 4xx and 5xx replies."
  @spec negative?(t()) :: boolean()
  def negative?(%__MODULE__{code: code}), do: code >= 400

  @doc """
  Encodes a reply for the wire. The enhanced code, when present, starts
  every line (RFC 2034 §4).
  """
  @spec encode(t()) :: iodata()
  def encode(%__MODULE__{code: code, enhanced: enhanced, lines: lines}) do
    prefix = if enhanced, do: [enhanced, ?\s], else: []
    last = length(lines) - 1

    lines
    |> Enum.with_index()
    |> Enum.map(fn {line, index} ->
      separator = if index == last, do: ?\s, else: ?-
      [Integer.to_string(code), separator, prefix, line, "\r\n"]
    end)
  end

  @doc "Returns the reply as a single line of text, for logs."
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{code: code, enhanced: enhanced, lines: lines}) do
    Enum.join([Integer.to_string(code), enhanced | lines] |> Enum.reject(&is_nil/1), " ")
  end
end
