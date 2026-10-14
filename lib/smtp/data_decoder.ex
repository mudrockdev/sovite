defmodule Sovite.SMTP.DataDecoder do
  @moduledoc """
  Streaming decoder for SMTP `DATA` content (RFC 5321 §4.1.1.4, §4.5.2).

  It removes dot-stuffing and finds the end of data without buffering the
  message: feed it bytes as they arrive and it returns the decoded content
  as iodata.

  Only `<CRLF>.<CRLF>` ends the data. A bare LF or bare CR (one not part
  of a CRLF pair) is handled by the policy, so it can never be read as a
  line ending by one MTA and as content by another (SMTP smuggling):

    * `:reject` - stop with `{:error, :bare_lf | :bare_cr}`.
    * `:normalize` - convert it to CRLF in the output. The line it ends
      cannot end the data, even if it is a single dot.

  The decoded content keeps CRLF line endings, and the final CRLF before
  the terminating dot is part of the content.

  ## BDAT

  With `dots: false` it checks the content of `BDAT` chunks (RFC 3030)
  instead: there is no dot-stuffing and no terminator, the chunk sizes
  delimit the message, but bare line endings get the same policy. Call
  `finish/1` after the last chunk. `BINARYMIME` content is binary and
  needs no decoder.
  """

  defstruct policy: :reject, dots: true, line_start: true, pending: <<>>

  @type policy :: :reject | :normalize
  @opaque t :: %__MODULE__{
            policy: policy(),
            dots: boolean(),
            line_start: boolean() | :normalized,
            pending: binary()
          }

  @doc """
  Returns a decoder for content right after the `354` reply, or with
  `dots: false` for `BDAT` content.
  """
  @spec new(policy(), keyword()) :: t()
  def new(policy \\ :reject, opts \\ []) when policy in [:reject, :normalize],
    do: %__MODULE__{policy: policy, dots: Keyword.get(opts, :dots, true)}

  @doc """
  Ends `BDAT` content: a CR left at the end is a bare one. Returns the
  content still held back.
  """
  @spec finish(t()) :: {:ok, iodata()} | {:error, :bare_cr, iodata()}
  def finish(%__MODULE__{pending: "\r", policy: :reject}), do: {:error, :bare_cr, []}
  def finish(%__MODULE__{pending: "\r"}), do: {:ok, "\r\n"}
  def finish(%__MODULE__{}), do: {:ok, []}

  @doc """
  Decodes `bytes`.

    * `{:more, content, decoder}` - the data has not ended yet.
    * `{:done, content, rest}` - the data ended; `rest` is the input after
      the terminating `.<CRLF>`, such as pipelined commands.
    * `{:error, reason, content}` - a bare line ending under `:reject`.
      `content` is what was decoded before it.
  """
  @spec decode(t(), binary()) ::
          {:more, iodata(), t()}
          | {:done, iodata(), binary()}
          | {:error, :bare_lf | :bare_cr, iodata()}
  def decode(%__MODULE__{pending: pending} = decoder, bytes) do
    scan(%{decoder | pending: <<>>}, pending <> bytes, [])
  end

  # At the start of a line, a leading dot is either the end of the data or
  # stuffing. Wait for enough bytes to tell.
  defp scan(%{dots: true, line_start: true}, <<".\r\n", rest::binary>>, acc),
    do: {:done, Enum.reverse(acc), rest}

  defp scan(%{dots: true, line_start: true} = d, buffer, acc) when buffer in [".", ".\r"],
    do: {:more, Enum.reverse(acc), %{d | pending: buffer}}

  # After a normalized bare line ending, a dot is still unstuffed, but the
  # line cannot end the data.
  defp scan(%{dots: true, line_start: start} = d, <<".", rest::binary>>, acc)
       when start in [true, :normalized],
       do: scan(%{d | line_start: false}, rest, acc)

  defp scan(d, <<>>, acc), do: {:more, Enum.reverse(acc), d}

  defp scan(d, buffer, acc) do
    case :binary.match(buffer, ["\r", "\n"]) do
      :nomatch ->
        {:more, Enum.reverse([buffer | acc]), %{d | line_start: false}}

      {index, 1} ->
        <<content::binary-size(^index), ending, rest::binary>> = buffer
        line_end(d, content, ending, rest, acc)
    end
  end

  defp line_end(d, content, ?\r, <<?\n, rest::binary>>, acc),
    do: scan(%{d | line_start: true}, rest, ["\r\n", content | acc])

  # A CR at the end of the input may be followed by LF in the next chunk.
  defp line_end(d, content, ?\r, <<>>, acc),
    do: {:more, Enum.reverse([content | acc]), %{d | line_start: false, pending: "\r"}}

  defp line_end(%{policy: :reject}, content, ending, _rest, acc),
    do: {:error, if(ending == ?\n, do: :bare_lf, else: :bare_cr), Enum.reverse([content | acc])}

  defp line_end(%{policy: :normalize} = d, content, _ending, rest, acc),
    do: scan(%{d | line_start: :normalized}, rest, ["\r\n", content | acc])
end
