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

  @doc """
  Returns the enhanced status code, or a generic one for the reply class
  (`"2.0.0"`, `"4.0.0"`, `"5.0.0"`) when the reply has none.
  """
  @spec status(t()) :: String.t()
  def status(%__MODULE__{enhanced: enhanced}) when is_binary(enhanced), do: enhanced
  def status(%__MODULE__{code: code}), do: "#{div(code, 100)}.0.0"

  @typedoc "Why `decode/2` rejected a reply."
  @type decode_error :: :line_too_long | :too_many_lines | :malformed

  @doc """
  Decodes one reply from the start of `buffer`, as received from a
  server.

    * `{:ok, reply, rest}` - a complete reply and the bytes after it.
    * `:more` - the reply is not complete yet.
    * `{:error, reason}` - not a valid reply, or over a limit.

  Lines end in CRLF; a bare LF is tolerated. Every line must have the same
  code. When the first line starts with an enhanced status code of the
  same class (RFC 2034), it is moved to `enhanced` and stripped from every
  line that carries it.

  ## Options

    * `:max_line_length` - bytes per line, including the line ending.
      Defaults to 2048 (RFC 5321 §4.5.3.1.5 allows 512).
    * `:max_lines` - lines per reply. Defaults to 100.

      iex> Sovite.SMTP.Reply.decode("250-mx.example\\r\\n250 SIZE 100\\r\\nrest")
      {:ok, %Sovite.SMTP.Reply{code: 250, enhanced: nil, lines: ["mx.example", "SIZE 100"]}, "rest"}
      iex> Sovite.SMTP.Reply.decode("550 5.1.1 Unknown user\\r\\n")
      {:ok, %Sovite.SMTP.Reply{code: 550, enhanced: "5.1.1", lines: ["Unknown user"]}, ""}
  """
  @spec decode(binary(), keyword()) :: {:ok, t(), binary()} | :more | {:error, decode_error()}
  def decode(buffer, opts \\ []) when is_binary(buffer) do
    max_line = Keyword.get(opts, :max_line_length, 2048)
    max_lines = Keyword.get(opts, :max_lines, 100)
    decode_lines(buffer, 0, [], nil, max_line, max_lines)
  end

  defp decode_lines(buffer, offset, acc, code, max_line, max_lines) do
    case :binary.match(buffer, "\n", scope: {offset, byte_size(buffer) - offset}) do
      :nomatch ->
        if byte_size(buffer) - offset > max_line, do: {:error, :line_too_long}, else: :more

      {index, 1} when index + 1 - offset > max_line ->
        {:error, :line_too_long}

      {index, 1} ->
        line = buffer |> binary_part(offset, index - offset) |> String.trim_trailing("\r")
        next = index + 1

        case parse_line(line, code) do
          {:last, code, text} ->
            rest = binary_part(buffer, next, byte_size(buffer) - next)
            {:ok, build(code, Enum.reverse([text | acc])), rest}

          {:continue, _code, _text} when length(acc) + 1 >= max_lines ->
            {:error, :too_many_lines}

          {:continue, code, text} ->
            decode_lines(buffer, next, [text | acc], code, max_line, max_lines)

          :error ->
            {:error, :malformed}
        end
    end
  end

  defp parse_line(<<digits::binary-size(3), rest::binary>>, expected) do
    with {code, ""} when code in 200..599 <- Integer.parse(digits),
         true <- expected in [nil, code],
         {kind, text} <- separator(rest) do
      {kind, code, text}
    else
      _ -> :error
    end
  end

  defp parse_line(_line, _expected), do: :error

  defp separator(""), do: {:last, ""}
  defp separator(<<" ", text::binary>>), do: {:last, text}
  defp separator(<<"-", text::binary>>), do: {:continue, text}
  defp separator(_), do: :error

  @enhanced ~r/\A([245])\.(\d{1,3})\.(\d{1,3})(?: |\z)/

  defp build(code, [first | _] = lines) do
    class = Integer.to_string(div(code, 100))

    case Regex.run(@enhanced, first) do
      [_, ^class, subject, detail] ->
        enhanced = "#{class}.#{subject}.#{detail}"
        %__MODULE__{code: code, enhanced: enhanced, lines: Enum.map(lines, &strip(&1, enhanced))}

      _ ->
        %__MODULE__{code: code, lines: lines}
    end
  end

  defp strip(line, enhanced) do
    with [{0, length} | _] <- Regex.run(@enhanced, line, return: :index),
         [_, class, subject, detail] <- Regex.run(@enhanced, line),
         ^enhanced <- "#{class}.#{subject}.#{detail}" do
      binary_part(line, length, byte_size(line) - length)
    else
      _ -> line
    end
  end
end
