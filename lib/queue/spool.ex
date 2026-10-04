defmodule Sovite.Queue.Spool do
  @moduledoc """
  Durable storage for queued messages.

  A message is streamed into `tmp/`, then committed: the file is
  `fsync`ed, renamed into `incoming/`, and `incoming/` itself is
  `fsync`ed. Only after `commit/1` returns may the server reply `250`.
  A crash at any earlier point leaves at most a file in `tmp/`, which
  `init/1` deletes.

  Each message is one file, named by its queue ID, in one of these
  queues:

      <directory>/tmp/        being received
      <directory>/incoming/   accepted, not yet picked up for delivery
      <directory>/active/     being delivered
      <directory>/deferred/   waiting for the next attempt
      <directory>/hold/       held by the administrator, not delivered
      <directory>/corrupt/    failed verification, kept for inspection

  `move/4` moves a file between queues with an atomic rename, so after a
  crash every message is in exactly one queue. `recover/1` puts messages
  that were being delivered back in `incoming/`.

  ## File format

  Each queue file is a header line, the envelope as one line of JSON, the
  message, and any number of delivery records:

      SOVITE-QUEUE 2 <envelope bytes:10> <message bytes:20> <sha256:64>\\n
      {"queue_id":"...","sender":"...","recipients":[...],...}\\n
      <message, CRLF line endings, as received>
      R <sha256:64> {"type":"recipient",...}\\n
      R <sha256:64> {"type":"retry",...}\\n

  The header has a fixed length. It is written last, so a file whose
  header does not parse was never committed. The SHA-256 in the header
  covers the envelope and message. Files are created with mode `0600`.

  Records (`Sovite.Queue.Record`) are appended with `append/3` and
  `fsync`ed; each line carries the SHA-256 of its JSON. Only the last
  line can be incomplete, after a crash during an append: it is ignored
  and overwritten by the next append. Version 1 files have no records.
  """

  alias Sovite.Queue.{Envelope, ID, Record}

  @version "2"
  @magic "SOVITE-QUEUE "
  @header_size byte_size(@magic) + 2 + 10 + 1 + 20 + 1 + 64 + 1
  @queues [:incoming, :active, :deferred, :hold, :corrupt]

  @enforce_keys [:fd, :tmp_path, :path, :envelope, :hash]
  defstruct [:fd, :tmp_path, :path, :envelope, :hash, envelope_size: 0, message_size: 0]

  @typedoc "A message being written. Use the returned writer after each call."
  @opaque writer :: %__MODULE__{}

  @type queue :: :incoming | :active | :deferred | :hold | :corrupt

  @typedoc """
  A queue file read by `load/2`. The message is the `message_size` bytes
  at `message_offset`; `end_offset` is where the next record goes.
  """
  @type loaded :: %{
          envelope: Envelope.t(),
          message_offset: non_neg_integer(),
          message_size: non_neg_integer(),
          records: [Record.t()],
          end_offset: non_neg_integer()
        }

  @type read_error ::
          File.posix()
          | :invalid_header
          | :checksum_mismatch
          | :invalid_envelope
          | :invalid_record

  @doc "The queues, in the order a message normally passes through them."
  @spec queues() :: [queue()]
  def queues, do: @queues

  @doc """
  Creates the spool directories with mode `0700` and deletes files left
  in `tmp/` by an earlier crash.
  """
  @spec init(Path.t()) :: :ok | {:error, File.posix()}
  def init(directory) do
    tmp = Path.join(directory, "tmp")

    with :ok <- make_private_dir(directory),
         :ok <- make_private_dir(tmp),
         :ok <- each_ok(@queues, &make_private_dir(Path.join(directory, Atom.to_string(&1)))),
         {:ok, leftovers} <- File.ls(tmp) do
      Enum.each(leftovers, &File.rm(Path.join(tmp, &1)))
    end
  end

  defp make_private_dir(path) do
    with :ok <- File.mkdir_p(path), do: File.chmod(path, 0o700)
  end

  @doc "Returns the path of message `id` in `queue`."
  @spec path(Path.t(), queue(), String.t()) :: Path.t()
  def path(directory, queue, id) when queue in @queues,
    do: Path.join([directory, Atom.to_string(queue), id])

  ## Writing

  @doc "Starts writing a message for `envelope` in `directory`."
  @spec open(Path.t(), Envelope.t()) :: {:ok, writer()} | {:error, File.posix()}
  def open(directory, %Envelope{queue_id: id} = envelope) do
    tmp_path = Path.join([directory, "tmp", id])
    envelope_line = [envelope |> Envelope.to_map() |> JSON.encode!(), ?\n]

    with {:ok, fd} <- :file.open(tmp_path, [:write, :exclusive, :raw, :binary]) do
      writer = %__MODULE__{
        fd: fd,
        tmp_path: tmp_path,
        path: path(directory, :incoming, id),
        envelope: envelope,
        hash: :crypto.hash_init(:sha256)
      }

      with :ok <- File.chmod(tmp_path, 0o600),
           # Reserve the header; it is filled in on commit.
           :ok <- :file.write(fd, :binary.copy(" ", @header_size)),
           {:ok, writer} <- append_data(writer, envelope_line) do
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
  def write(%__MODULE__{} = writer, data), do: append_data(writer, data)

  defp append_data(writer, data) do
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
  Appends delivery records to the queue file at `path` and `fsync`s it.
  `end_offset` comes from `load/2` or the previous `append/3`; anything
  after it (an incomplete record from a crash) is overwritten. Returns the
  new end offset.
  """
  @spec append(Path.t(), non_neg_integer(), [Record.t()]) ::
          {:ok, non_neg_integer()} | {:error, File.posix()}
  def append(_path, end_offset, []), do: {:ok, end_offset}

  def append(path, end_offset, records) do
    data = Enum.map(records, &encode_record/1)

    with {:ok, fd} <- :file.open(path, [:read, :write, :raw, :binary]) do
      try do
        with :ok <- :file.pwrite(fd, end_offset, data),
             {:ok, _} <- :file.position(fd, end_offset + IO.iodata_length(data)),
             :ok <- :file.truncate(fd),
             :ok <- :file.datasync(fd) do
          {:ok, end_offset + IO.iodata_length(data)}
        end
      after
        :file.close(fd)
      end
    end
  end

  defp encode_record(record) do
    json = record |> Record.to_map() |> JSON.encode!()
    ["R ", sha256(json), " ", json, ?\n]
  end

  ## Reading

  @doc """
  Reads and verifies the queue file at `path`. Returns the envelope and
  the byte offset at which the message starts. The checksum is verified
  without loading the message into memory. Records are not read; use
  `load/2` for those.
  """
  @spec read(Path.t()) :: {:ok, Envelope.t(), non_neg_integer()} | {:error, read_error()}
  def read(path) do
    with {:ok, loaded} <- load(path, records: false) do
      {:ok, loaded.envelope, loaded.message_offset}
    end
  end

  @doc """
  Reads the queue file at `path`: envelope, message position, and
  delivery records.

  ## Options

    * `:verify` - check the message checksum. Defaults to `true`. Without
      it, only the header, envelope, and records are read, which is much
      faster for large messages.
    * `:records` - read the records. Defaults to `true`.
  """
  @spec load(Path.t(), keyword()) :: {:ok, loaded()} | {:error, read_error()}
  def load(path, opts \\ []) do
    with {:ok, fd} <- :file.open(path, [:read, :raw, :binary, read_ahead: 65_536]) do
      try do
        load_open(fd, Keyword.get(opts, :verify, true), Keyword.get(opts, :records, true))
      after
        :file.close(fd)
      end
    end
  end

  defp load_open(fd, verify?, records?) do
    with {:ok, header} <- :file.read(fd, @header_size),
         {:ok, version, envelope_size, message_size, digest} <- parse_header(header),
         {:ok, envelope_line} <- read_exactly(fd, envelope_size),
         message_offset = @header_size + envelope_size,
         end_offset = message_offset + message_size,
         :ok <- verify_message(fd, verify?, envelope_line, message_size, digest),
         {:ok, map} <- decode_envelope(envelope_line),
         {:ok, envelope} <- Envelope.from_map(map),
         {:ok, records, end_offset} <- read_records(fd, version, records?, end_offset) do
      {:ok,
       %{
         envelope: envelope,
         message_offset: message_offset,
         message_size: message_size,
         records: records,
         end_offset: end_offset
       }}
    else
      :eof -> {:error, :invalid_header}
      {:error, reason} -> {:error, reason}
    end
  end

  # A committed file is never shorter than its header says.
  defp read_exactly(fd, size) do
    case :file.read(fd, size) do
      {:ok, data} when byte_size(data) == size -> {:ok, data}
      {:ok, _short} -> {:error, :checksum_mismatch}
      :eof when size == 0 -> {:ok, <<>>}
      :eof -> {:error, :checksum_mismatch}
      {:error, reason} -> {:error, reason}
    end
  end

  defp verify_message(fd, true, envelope_line, message_size, digest) do
    hash = :crypto.hash_update(:crypto.hash_init(:sha256), envelope_line)
    verify(fd, hash, message_size, digest)
  end

  defp verify_message(_fd, false, _envelope_line, _message_size, _digest), do: :ok

  defp header(envelope_size, message_size, digest) do
    [
      @magic,
      @version,
      " ",
      String.pad_leading(Integer.to_string(envelope_size), 10, "0"),
      " ",
      String.pad_leading(Integer.to_string(message_size), 20, "0"),
      " ",
      digest,
      ?\n
    ]
  end

  defp parse_header(
         <<@magic, version, " ", envelope::binary-10, " ", message::binary-20, " ",
           digest::binary-64, ?\n>>
       )
       when version in [?1, ?2] do
    if digits?(envelope) and digits?(message) and String.match?(digest, ~r/\A[0-9a-f]{64}\z/),
      do: {:ok, version - ?0, String.to_integer(envelope), String.to_integer(message), digest},
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

  defp verify(_fd, hash, 0, digest) do
    actual = hash |> :crypto.hash_final() |> Base.encode16(case: :lower)
    if actual == digest, do: :ok, else: {:error, :checksum_mismatch}
  end

  # Version 1 files end with the message: trailing bytes mean the file was
  # modified after commit.
  defp read_records(fd, 1, _records?, end_offset) do
    case :file.pread(fd, end_offset, 1) do
      :eof -> {:ok, [], end_offset}
      {:ok, _} -> {:error, :checksum_mismatch}
      {:error, reason} -> {:error, reason}
    end
  end

  defp read_records(_fd, 2, false, end_offset), do: {:ok, [], end_offset}

  defp read_records(fd, 2, true, end_offset) do
    with {:ok, _} <- :file.position(fd, end_offset) do
      read_record_lines(fd, end_offset, [])
    end
  end

  # Records are short; a longer line is damage, not a record.
  @max_record 65_536

  defp read_record_lines(fd, offset, acc) do
    case :file.read_line(fd) do
      :eof ->
        {:ok, Enum.reverse(acc), offset}

      {:ok, line} ->
        case decode_record(line) do
          {:ok, record} -> read_record_lines(fd, offset + byte_size(line), [record | acc])
          :error -> damaged_record(fd, offset, acc)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # A crash during an append can only damage the last line.
  defp damaged_record(fd, offset, acc) do
    if :file.read(fd, 1) == :eof,
      do: {:ok, Enum.reverse(acc), offset},
      else: {:error, :invalid_record}
  end

  defp decode_record(<<"R ", digest::binary-64, " ", rest::binary>>)
       when byte_size(rest) <= @max_record do
    with true <- String.ends_with?(rest, "\n"),
         json = binary_part(rest, 0, byte_size(rest) - 1),
         true <- sha256(json) == digest,
         {:ok, map} <- JSON.decode(json),
         {:ok, record} <- Record.from_map(map) do
      {:ok, record}
    else
      _ -> :error
    end
  end

  defp decode_record(_line), do: :error

  defp decode_envelope(line) do
    case JSON.decode(line) do
      {:ok, map} -> {:ok, map}
      {:error, _} -> {:error, :invalid_envelope}
    end
  end

  @doc """
  Streams the message of the queue file at `path`, as returned by
  `load/2`, in chunks of up to 64 KiB.
  """
  @spec stream_message(Path.t(), non_neg_integer(), non_neg_integer()) :: Enumerable.t(binary())
  def stream_message(path, offset, size) do
    Stream.resource(
      fn ->
        {:ok, fd} = :file.open(path, [:read, :raw, :binary])
        {fd, offset, size}
      end,
      fn
        {_fd, _position, 0} = acc ->
          {:halt, acc}

        {fd, position, remaining} ->
          case :file.pread(fd, position, min(remaining, 65_536)) do
            {:ok, data} ->
              {[data], {fd, position + byte_size(data), remaining - byte_size(data)}}

            :eof ->
              raise File.Error, reason: :eof, action: "read queue file", path: path

            {:error, reason} ->
              raise File.Error, reason: reason, action: "read queue file", path: path
          end
      end,
      fn {fd, _, _} -> :file.close(fd) end
    )
  end

  @doc """
  Returns the header fields of the message in the queue file at `path`,
  up to the empty line that ends them (not included), and at most `limit`
  bytes, cut at the end of a line.
  """
  @spec read_headers(Path.t(), non_neg_integer(), non_neg_integer(), pos_integer()) ::
          {:ok, binary()} | {:error, File.posix()}
  def read_headers(path, offset, size, limit \\ 65_536) do
    with {:ok, fd} <- :file.open(path, [:read, :raw, :binary]) do
      try do
        case :file.pread(fd, offset, min(size, limit)) do
          {:ok, data} -> {:ok, header_section(data)}
          :eof -> {:ok, ""}
          {:error, reason} -> {:error, reason}
        end
      after
        :file.close(fd)
      end
    end
  end

  defp header_section("\r\n" <> _body), do: ""

  defp header_section(data) do
    case :binary.match(data, "\r\n\r\n") do
      {index, _} ->
        binary_part(data, 0, index + 2)

      # No end of the header section within the limit: keep whole lines.
      :nomatch ->
        case :binary.matches(data, "\r\n") do
          [] -> ""
          matches -> binary_part(data, 0, elem(List.last(matches), 0) + 2)
        end
    end
  end

  ## Queues

  @doc "Lists the queue IDs in `queue`, oldest first."
  @spec list(Path.t(), queue()) :: {:ok, [String.t()]} | {:error, File.posix()}
  def list(directory, queue) when queue in @queues do
    with {:ok, names} <- File.ls(Path.join(directory, Atom.to_string(queue))) do
      {:ok, names |> Enum.filter(&ID.valid?/1) |> Enum.sort()}
    end
  end

  @doc "Moves message `id` from one queue to another."
  @spec move(Path.t(), String.t(), queue(), queue()) :: :ok | {:error, File.posix()}
  def move(directory, id, from, to) when from in @queues and to in @queues,
    do: :file.rename(path(directory, from, id), path(directory, to, id))

  @doc """
  Deletes message `id` from `queue`, for example after delivery, and
  emits `[:sovite, :queue, :message, :removed]` with `reason`.
  """
  @spec remove(Path.t(), queue(), String.t(), atom()) :: :ok | {:error, File.posix()}
  def remove(directory, queue, id, reason) do
    with :ok <- File.rm(path(directory, queue, id)) do
      :telemetry.execute([:sovite, :queue, :message, :removed], %{}, %{
        queue_id: id,
        reason: reason
      })
    end
  end

  @doc """
  Moves every message in `active/` back to `incoming/`. Run at startup:
  those messages were being delivered when the previous run stopped.
  Returns the number of messages moved.
  """
  @spec recover(Path.t()) :: {:ok, non_neg_integer()} | {:error, File.posix()}
  def recover(directory) do
    with {:ok, ids} <- list(directory, :active),
         :ok <- each_ok(ids, &move(directory, &1, :active, :incoming)) do
      {:ok, length(ids)}
    end
  end

  defp each_ok(items, fun) do
    Enum.reduce_while(items, :ok, fn item, :ok ->
      case fun.(item) do
        :ok -> {:cont, :ok}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp sha256(data), do: :sha256 |> :crypto.hash(data) |> Base.encode16(case: :lower)

  defp sync_dir(path) do
    with {:ok, fd} <- :file.open(path, [:read, :raw, :directory]) do
      result = :file.sync(fd)
      _ = :file.close(fd)
      result
    end
  end
end
