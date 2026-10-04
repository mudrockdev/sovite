defmodule Sovite.Queue.Spool do
  @moduledoc """
  Durable storage for received messages.

  A message is streamed into `tmp/`, then committed: the file is
  `fsync`ed, renamed into `incoming/`, and `incoming/` itself is
  `fsync`ed. Only after `commit/1` returns may the server reply `250`.
  A crash at any earlier point leaves at most a file in `tmp/`, which
  `init/1` deletes.

      <directory>/tmp/<queue_id>        being received
      <directory>/incoming/<queue_id>   accepted, waiting for delivery

  ## File format

  Each queue file is a header line, the envelope as one line of JSON, and
  the message:

      SOVITE-QUEUE 1 <envelope bytes:10> <message bytes:20> <sha256:64>\\n
      {"queue_id":"...","sender":"...","recipients":[...],...}\\n
      <message, CRLF line endings, as received>

  The header has a fixed length. It is written last, so a file whose
  header does not parse was never committed. The SHA-256 covers everything
  after the header. Files are created with mode `0600`.
  """

  alias Sovite.Queue.Envelope

  @magic "SOVITE-QUEUE 1 "
  @header_size byte_size(@magic) + 10 + 1 + 20 + 1 + 64 + 1

  @enforce_keys [:fd, :tmp_path, :path, :envelope, :hash]
  defstruct [:fd, :tmp_path, :path, :envelope, :hash, envelope_size: 0, message_size: 0]

  @typedoc "A message being written. Use the returned writer after each call."
  @opaque writer :: %__MODULE__{}

  @doc """
  Creates the spool directories with mode `0700` and deletes files left
  in `tmp/` by an earlier crash.
  """
  @spec init(Path.t()) :: :ok | {:error, File.posix()}
  def init(directory) do
    tmp = Path.join(directory, "tmp")

    with :ok <- make_private_dir(directory),
         :ok <- make_private_dir(tmp),
         :ok <- make_private_dir(Path.join(directory, "incoming")),
         {:ok, leftovers} <- File.ls(tmp) do
      Enum.each(leftovers, &File.rm(Path.join(tmp, &1)))
    end
  end

  defp make_private_dir(path) do
    with :ok <- File.mkdir_p(path), do: File.chmod(path, 0o700)
  end

  @doc "Starts writing a message for `envelope` in `directory`."
  @spec open(Path.t(), Envelope.t()) :: {:ok, writer()} | {:error, File.posix()}
  def open(directory, %Envelope{queue_id: id} = envelope) do
    tmp_path = Path.join([directory, "tmp", id])
    envelope_line = [envelope |> Envelope.to_map() |> JSON.encode!(), ?\n]

    with {:ok, fd} <- :file.open(tmp_path, [:write, :exclusive, :raw, :binary]) do
      writer = %__MODULE__{
        fd: fd,
        tmp_path: tmp_path,
        path: Path.join([directory, "incoming", id]),
        envelope: envelope,
        hash: :crypto.hash_init(:sha256)
      }

      with :ok <- File.chmod(tmp_path, 0o600),
           # Reserve the header; it is filled in on commit.
           :ok <- :file.write(fd, :binary.copy(" ", @header_size)),
           {:ok, writer} <- append(writer, envelope_line) do
        {:ok, %{writer | envelope_size: IO.iodata_length(envelope_line), message_size: 0}}
      else
        {:error, reason} ->
          abort(writer)
          {:error, reason}
      end
    end
  end

  @doc "Appends message data."
  @spec write(writer(), iodata()) :: {:ok, writer()} | {:error, File.posix()}
  def write(%__MODULE__{} = writer, data), do: append(writer, data)

  defp append(writer, data) do
    case :file.write(writer.fd, data) do
      :ok ->
        {:ok,
         %{
           writer
           | hash: :crypto.hash_update(writer.hash, data),
             message_size: writer.message_size + IO.iodata_length(data)
         }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Makes the message durable and moves it to `incoming/`. Returns the
  final path and the message size in bytes.

  On error the temporary file is deleted.
  """
  @spec commit(writer()) :: {:ok, Path.t(), non_neg_integer()} | {:error, File.posix()}
  def commit(%__MODULE__{} = writer) do
    digest = writer.hash |> :crypto.hash_final() |> Base.encode16(case: :lower)
    header = header(writer.envelope_size, writer.message_size, digest)

    with :ok <- :file.pwrite(writer.fd, 0, header),
         :ok <- :file.datasync(writer.fd),
         :ok <- :file.close(writer.fd),
         :ok <- :file.rename(writer.tmp_path, writer.path),
         :ok <- sync_dir(Path.dirname(writer.path)) do
      :telemetry.execute(
        [:sovite, :queue, :message, :enqueued],
        %{size: writer.message_size, recipients: length(writer.envelope.recipients)},
        %{
          queue_id: writer.envelope.queue_id,
          session_id: writer.envelope.session_id,
          sender: writer.envelope.sender
        }
      )

      {:ok, writer.path, writer.message_size}
    else
      {:error, reason} ->
        abort(writer)
        {:error, reason}
    end
  end

  @doc "Discards a message that is being written."
  @spec abort(writer()) :: :ok
  def abort(%__MODULE__{} = writer) do
    _ = :file.close(writer.fd)
    _ = File.rm(writer.tmp_path)
    :ok
  end

  @doc """
  Reads and verifies the queue file at `path`. Returns the envelope and
  the byte offset at which the message starts. The checksum is verified
  without loading the message into memory.
  """
  @spec read(Path.t()) ::
          {:ok, Envelope.t(), non_neg_integer()}
          | {:error, File.posix() | :invalid_header | :checksum_mismatch | :invalid_envelope}
  def read(path) do
    with {:ok, fd} <- :file.open(path, [:read, :raw, :binary]) do
      try do
        read_open(fd)
      after
        :file.close(fd)
      end
    end
  end

  defp read_open(fd) do
    with {:ok, header} <- :file.read(fd, @header_size),
         {:ok, envelope_size, message_size, digest} <- parse_header(header),
         {:ok, envelope_line} <- :file.read(fd, envelope_size),
         :ok <-
           verify(
             fd,
             :crypto.hash_update(:crypto.hash_init(:sha256), envelope_line),
             message_size,
             digest
           ),
         {:ok, map} <- decode_envelope(envelope_line),
         {:ok, envelope} <- Envelope.from_map(map) do
      {:ok, envelope, @header_size + envelope_size}
    else
      :eof -> {:error, :invalid_header}
      {:error, reason} -> {:error, reason}
    end
  end

  defp header(envelope_size, message_size, digest) do
    [
      @magic,
      String.pad_leading(Integer.to_string(envelope_size), 10, "0"),
      " ",
      String.pad_leading(Integer.to_string(message_size), 20, "0"),
      " ",
      digest,
      ?\n
    ]
  end

  defp parse_header(
         <<@magic, envelope::binary-10, " ", message::binary-20, " ", digest::binary-64, ?\n>>
       ) do
    if digits?(envelope) and digits?(message) and String.match?(digest, ~r/\A[0-9a-f]{64}\z/),
      do: {:ok, String.to_integer(envelope), String.to_integer(message), digest},
      else: {:error, :invalid_header}
  end

  defp parse_header(_header), do: {:error, :invalid_header}

  defp digits?(string), do: String.match?(string, ~r/\A[0-9]+\z/)

  defp verify(fd, hash, remaining, digest) when remaining > 0 do
    case :file.read(fd, min(remaining, 65_536)) do
      {:ok, data} ->
        verify(fd, :crypto.hash_update(hash, data), remaining - byte_size(data), digest)

      :eof ->
        {:error, :checksum_mismatch}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp verify(fd, hash, 0, digest) do
    actual = hash |> :crypto.hash_final() |> Base.encode16(case: :lower)

    # Trailing bytes mean the file was modified after commit.
    if actual == digest and :file.read(fd, 1) == :eof,
      do: :ok,
      else: {:error, :checksum_mismatch}
  end

  defp decode_envelope(line) do
    case JSON.decode(line) do
      {:ok, map} -> {:ok, map}
      {:error, _} -> {:error, :invalid_envelope}
    end
  end

  defp sync_dir(path) do
    with {:ok, fd} <- :file.open(path, [:read, :raw, :directory]) do
      result = :file.sync(fd)
      _ = :file.close(fd)
      result
    end
  end
end
