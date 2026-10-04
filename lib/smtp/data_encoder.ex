defmodule Sovite.SMTP.DataEncoder do
  @moduledoc """
  Streaming encoder for SMTP `DATA` content, the inverse of
  `Sovite.SMTP.DataDecoder`.

  It dot-stuffs the message (RFC 5321 §4.5.2) as chunks are fed in, and
  `finish/1` returns the terminating `<CRLF>.<CRLF>`, adding a CRLF first
  if the message does not end with one.

      encoder = DataEncoder.new()
      {data, encoder} = DataEncoder.encode(encoder, "Subject: hi\\r\\n\\r\\n.dot\\r\\n")
      IO.iodata_to_binary([data, DataEncoder.finish(encoder)])
      #=> "Subject: hi\\r\\n\\r\\n..dot\\r\\n.\\r\\n"

  The message must use CRLF line endings, as `Sovite.Queue.Spool` stores
  it. A dot is stuffed after every LF, so a bare LF can never produce a
  line that ends the data early.
  """

  defstruct line_start: true, last: nil

  @opaque t :: %__MODULE__{line_start: boolean(), last: byte() | nil}

  @doc "Returns an encoder for the start of a message."
  @spec new() :: t()
  def new, do: %__MODULE__{}

  @doc "Encodes the next chunk of the message."
  @spec encode(t(), iodata()) :: {iodata(), t()}
  def encode(%__MODULE__{} = encoder, chunk) do
    case IO.iodata_to_binary(chunk) do
      "" ->
        {[], encoder}

      binary ->
        stuffed = :binary.replace(binary, "\n.", "\n..", [:global])

        stuffed =
          if encoder.line_start and :binary.first(binary) == ?., do: [?. | stuffed], else: stuffed

        last = :binary.last(binary)
        {stuffed, %{encoder | line_start: last == ?\n, last: last}}
    end
  end

  @doc "Returns the end-of-data sequence."
  @spec finish(t()) :: iodata()
  def finish(%__MODULE__{last: ?\n}), do: ".\r\n"
  def finish(%__MODULE__{last: nil}), do: ".\r\n"
  def finish(%__MODULE__{last: ?\r}), do: "\n.\r\n"
  def finish(%__MODULE__{}), do: "\r\n.\r\n"
end
