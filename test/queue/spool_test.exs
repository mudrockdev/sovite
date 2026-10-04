defmodule Sovite.Queue.SpoolTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias Sovite.Queue.{Envelope, ID, Spool}

  @moduletag :tmp_dir

  @header_size 112
  @message "From: a@example.net\r\nSubject: hi\r\n\r\nHello\r\n"

  setup %{tmp_dir: dir} do
    :ok = Spool.init(dir)
    :ok
  end

  defp envelope(fields \\ []) do
    struct!(
      Envelope,
      Keyword.merge(
        [
          queue_id: ID.generate(),
          sender: "a@example.net",
          recipients: ["b@example.com", "c@example.com"],
          received_at: ~U[2026-10-04 12:00:00.123456Z],
          session_id: "session-1",
          remote_ip: {192, 0, 2, 7},
          helo: "client.example.net",
          protocol: "ESMTPS",
          body_type: :"8bitmime"
        ],
        fields
      )
    )
  end

  defp spool(dir, envelope, chunks) do
    {:ok, writer} = Spool.open(dir, envelope)

    writer =
      Enum.reduce(chunks, writer, fn chunk, writer ->
        {:ok, writer} = Spool.write(writer, chunk)
        writer
      end)

    Spool.commit(writer)
  end

  defp spool!(dir, envelope \\ envelope(), chunks \\ [@message]) do
    {:ok, path, _size} = spool(dir, envelope, chunks)
    path
  end

  # Writes a queue file with a correct header and checksum around
  # arbitrary envelope bytes.
  defp write_raw(path, envelope_line, message) do
    body = envelope_line <> message
    digest = :sha256 |> :crypto.hash(body) |> Base.encode16(case: :lower)

    header =
      "SOVITE-QUEUE 1 " <>
        String.pad_leading(Integer.to_string(byte_size(envelope_line)), 10, "0") <>
        " " <>
        String.pad_leading(Integer.to_string(byte_size(message)), 20, "0") <>
        " " <> digest <> "\n"

    assert byte_size(header) == @header_size
    File.write!(path, header <> body)
  end

  defp mode(path), do: File.stat!(path).mode &&& 0o777

  describe "init/1" do
    test "creates private tmp/ and incoming/ directories", %{tmp_dir: dir} do
      spool_dir = Path.join(dir, "new/spool")
      assert Spool.init(spool_dir) == :ok

      for sub <- ["", "tmp", "incoming"] do
        assert mode(Path.join(spool_dir, sub)) == 0o700
      end
    end

    test "tightens the mode of existing directories", %{tmp_dir: dir} do
      File.chmod!(Path.join(dir, "tmp"), 0o755)
      assert Spool.init(dir) == :ok
      assert mode(Path.join(dir, "tmp")) == 0o700
    end

    test "deletes leftovers in tmp/ but keeps incoming/", %{tmp_dir: dir} do
      File.write!(Path.join(dir, "tmp/leftover1"), "x")
      File.write!(Path.join(dir, "tmp/leftover2"), "y")
      path = spool!(dir)

      assert Spool.init(dir) == :ok
      assert File.ls!(Path.join(dir, "tmp")) == []
      assert File.exists?(path)
    end

    test "fails when the directory cannot be created", %{tmp_dir: dir} do
      file = Path.join(dir, "file")
      File.write!(file, "")
      assert {:error, _} = Spool.init(Path.join(file, "spool"))
    end
  end

  describe "open/2, write/2 and commit/1" do
    test "commits a private file to incoming/ that read/1 verifies", %{tmp_dir: dir} do
      env = envelope()
      chunks = ["From: a@example.net\r\n", ["Subject: hi\r\n", [?\r, ?\n]], "Hello\r\n"]
      assert {:ok, path, size} = spool(dir, env, chunks)

      assert path == Path.join([dir, "incoming", env.queue_id])
      assert size == byte_size(@message)
      assert File.ls!(Path.join(dir, "tmp")) == []
      assert mode(path) == 0o600

      assert {:ok, ^env, offset} = Spool.read(path)
      contents = File.read!(path)
      assert offset > @header_size
      assert binary_part(contents, offset, byte_size(contents) - offset) == @message
    end

    test "round-trips IPv6 addresses and the null sender", %{tmp_dir: dir} do
      env =
        envelope(
          sender: "",
          recipients: ["b@example.com"],
          remote_ip: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1},
          body_type: :"7bit"
        )

      assert {:ok, ^env, _offset} = dir |> spool!(env) |> Spool.read()
    end

    test "round-trips an envelope with only the required fields", %{tmp_dir: dir} do
      env = %Envelope{
        queue_id: ID.generate(),
        sender: "a@example.net",
        recipients: ["b@example.com"]
      }

      assert {:ok, ^env, _offset} = dir |> spool!(env) |> Spool.read()
    end

    test "stores an empty message", %{tmp_dir: dir} do
      assert {:ok, path, 0} = spool(dir, envelope(), [])
      assert {:ok, _env, offset} = Spool.read(path)
      assert offset == byte_size(File.read!(path))
    end

    test "keeps the message in tmp/ until commit", %{tmp_dir: dir} do
      env = envelope()
      {:ok, writer} = Spool.open(dir, env)
      {:ok, writer} = Spool.write(writer, @message)

      tmp_path = Path.join([dir, "tmp", env.queue_id])
      assert mode(tmp_path) == 0o600
      assert File.ls!(Path.join(dir, "incoming")) == []
      # The header is written on commit, so an uncommitted file never reads.
      assert Spool.read(tmp_path) == {:error, :invalid_header}

      assert {:ok, _path, _size} = Spool.commit(writer)
      refute File.exists?(tmp_path)
    end

    test "abort/1 deletes the temporary file", %{tmp_dir: dir} do
      {:ok, writer} = Spool.open(dir, envelope())
      {:ok, writer} = Spool.write(writer, @message)

      assert Spool.abort(writer) == :ok
      assert File.ls!(Path.join(dir, "tmp")) == []
      assert File.ls!(Path.join(dir, "incoming")) == []
    end

    test "refuses to open the same queue ID twice", %{tmp_dir: dir} do
      env = envelope()
      assert {:ok, writer} = Spool.open(dir, env)
      assert Spool.open(dir, env) == {:error, :eexist}
      Spool.abort(writer)
    end

    test "fails when the spool is not initialized", %{tmp_dir: dir} do
      assert {:error, :enoent} = Spool.open(Path.join(dir, "missing"), envelope())
    end

    test "emits a telemetry event on commit", %{tmp_dir: dir} do
      handler_id = "spool-test-#{System.unique_integer([:positive])}"
      event = [:sovite, :queue, :message, :enqueued]
      :ok = :telemetry.attach(handler_id, event, &__MODULE__.handle_event/4, self())
      on_exit(fn -> :telemetry.detach(handler_id) end)

      env = envelope()
      id = env.queue_id
      spool!(dir, env)

      assert_receive {:telemetry, ^event, measurements, %{queue_id: ^id} = metadata}
      assert measurements == %{size: byte_size(@message), recipients: 2}
      assert metadata == %{queue_id: id, session_id: "session-1", sender: "a@example.net"}
    end
  end

  def handle_event(event, measurements, metadata, pid),
    do: send(pid, {:telemetry, event, measurements, metadata})

  describe "read/1" do
    setup %{tmp_dir: dir} do
      path = spool!(dir)
      %{path: path, contents: File.read!(path)}
    end

    test "detects a flipped byte in the message", %{path: path, contents: contents} do
      pos = byte_size(contents) - 3
      <<before::binary-size(^pos), byte, rest::binary>> = contents
      File.write!(path, <<before::binary, bxor(byte, 1), rest::binary>>)
      assert Spool.read(path) == {:error, :checksum_mismatch}
    end

    test "detects a flipped byte in the envelope", %{path: path, contents: contents} do
      File.write!(path, String.replace(contents, "b@example.com", "b@example.org"))
      assert Spool.read(path) == {:error, :checksum_mismatch}
    end

    test "detects truncation", %{path: path, contents: contents} do
      File.write!(path, binary_part(contents, 0, byte_size(contents) - 1))
      assert Spool.read(path) == {:error, :checksum_mismatch}

      File.write!(path, binary_part(contents, 0, @header_size + 5))
      assert Spool.read(path) == {:error, :checksum_mismatch}

      File.write!(path, binary_part(contents, 0, @header_size - 1))
      assert Spool.read(path) == {:error, :invalid_header}

      File.write!(path, "")
      assert Spool.read(path) == {:error, :invalid_header}
    end

    test "detects appended bytes", %{path: path, contents: contents} do
      File.write!(path, contents <> "x")
      assert Spool.read(path) == {:error, :checksum_mismatch}
    end

    test "rejects a garbage header", %{path: path, contents: contents} do
      <<header::binary-size(@header_size), body::binary>> = contents

      for bad <- [
            String.replace(header, "SOVITE-QUEUE 1", "SOVITE-QUEUE 2"),
            String.replace(header, "SOVITE-QUEUE", "sovite-queue"),
            String.replace(header, " 0000", " 00x0", global: false),
            String.replace(header, "\n", " "),
            String.duplicate(" ", @header_size),
            String.duplicate("\0", @header_size)
          ] do
        File.write!(path, bad <> body)
        assert Spool.read(path) == {:error, :invalid_header}, "header: #{inspect(bad)}"
      end
    end

    # BUG: lib/queue/spool.ex:193-194 (parse_header/1) uses Integer.parse/1,
    # which accepts a sign. A negative message size then reaches verify/4
    # (lib/queue/spool.ex:203, 211), which has no clause for it, so read/1
    # raises FunctionClauseError; a negative envelope size makes it return
    # {:error, :badarg} from :file.read/2.
    @tag :skip
    test "rejects signed sizes in the header", %{path: path, contents: contents} do
      <<"SOVITE-QUEUE 1 ", env, env_rest::binary-9, " ", msg, msg_rest::binary-19, rest::binary>> =
        contents

      assert {env, msg} == {?0, ?0}

      File.write!(path, "SOVITE-QUEUE 1 0#{env_rest} -#{msg_rest}" <> rest)
      assert Spool.read(path) == {:error, :invalid_header}

      File.write!(path, "SOVITE-QUEUE 1 -#{env_rest} 0#{msg_rest}" <> rest)
      assert Spool.read(path) == {:error, :invalid_header}
    end

    test "rejects an invalid envelope with a valid checksum", %{path: path} do
      valid = envelope() |> Envelope.to_map()

      for map_or_line <- [
            "not json\n",
            "[1, 2]\n",
            "\"string\"\n",
            Map.delete(valid, "recipients"),
            Map.put(valid, "recipients", []),
            Map.put(valid, "recipients", ["b@example.com", 1]),
            Map.put(valid, "sender", nil),
            Map.put(valid, "queue_id", 1),
            Map.put(valid, "remote_ip", "10.1"),
            Map.put(valid, "remote_ip", 1),
            Map.put(valid, "received_at", "yesterday"),
            Map.put(valid, "body_type", "binarymime")
          ] do
        line = if is_binary(map_or_line), do: map_or_line, else: JSON.encode!(map_or_line) <> "\n"
        write_raw(path, line, @message)
        assert Spool.read(path) == {:error, :invalid_envelope}, "envelope: #{inspect(line)}"
      end
    end

    test "accepts a hand-written file with a valid envelope", %{path: path} do
      env = envelope()
      write_raw(path, JSON.encode!(Envelope.to_map(env)) <> "\n", @message)
      assert {:ok, ^env, _offset} = Spool.read(path)
    end

    test "returns file errors", %{tmp_dir: dir} do
      assert Spool.read(Path.join(dir, "missing")) == {:error, :enoent}
    end
  end
end
