defmodule Sovite.Queue.SpoolTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.Test.TelemetryForwarder

  @moduletag :tmp_dir

  @header_size 123
  @old_header_size 112
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

  # Writes a version 1 queue file with a correct header and checksum
  # around arbitrary envelope bytes.
  defp write_raw(path, envelope_line, message) do
    body = envelope_line <> message
    digest = :sha256 |> :crypto.hash(body) |> Base.encode16(case: :lower)

    header =
      "SOVITE-QUEUE 1 " <>
        String.pad_leading(Integer.to_string(byte_size(envelope_line)), 10, "0") <>
        " " <>
        String.pad_leading(Integer.to_string(byte_size(message)), 20, "0") <>
        " " <> digest <> "\n"

    assert byte_size(header) == @old_header_size
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

    test "detects appended bytes in a version 1 file", %{path: path} do
      write_raw(path, JSON.encode!(Envelope.to_map(envelope())) <> "\n", @message)
      assert {:ok, _env, _offset} = Spool.read(path)

      File.write!(path, "x", [:append])
      assert Spool.read(path) == {:error, :checksum_mismatch}
    end

    test "rejects a garbage header", %{path: path, contents: contents} do
      <<header::binary-size(@header_size), body::binary>> = contents

      for bad <- [
            String.replace(header, "SOVITE-QUEUE 3", "SOVITE-QUEUE 4"),
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

    test "rejects signed sizes in the header", %{path: path, contents: contents} do
      <<"SOVITE-QUEUE 3 ", env, env_rest::binary-9, " ", msg, msg_rest::binary-19, " ", prefix,
        prefix_rest::binary-9, rest::binary>> = contents

      assert {env, msg, prefix} == {?0, ?0, ?0}

      File.write!(path, "SOVITE-QUEUE 3 0#{env_rest} -#{msg_rest} 0#{prefix_rest}" <> rest)
      assert Spool.read(path) == {:error, :invalid_header}

      File.write!(path, "SOVITE-QUEUE 3 -#{env_rest} 0#{msg_rest} 0#{prefix_rest}" <> rest)
      assert Spool.read(path) == {:error, :invalid_header}

      File.write!(path, "SOVITE-QUEUE 3 0#{env_rest} 0#{msg_rest} -#{prefix_rest}" <> rest)
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
            Map.put(valid, "body_type", "binarymime"),
            Map.put(valid, "requiretls", "yes"),
            Map.put(valid, "auth_user", 1)
          ] do
        line = if is_binary(map_or_line), do: map_or_line, else: JSON.encode!(map_or_line) <> "\n"
        write_raw(path, line, @message)
        assert Spool.read(path) == {:error, :invalid_envelope}, "envelope: #{inspect(line)}"
      end
    end

    test "accepts a hand-written file with a valid envelope", %{path: path} do
      env = envelope(requiretls: true, auth_user: "alice")
      write_raw(path, JSON.encode!(Envelope.to_map(env)) <> "\n", @message)
      assert {:ok, ^env, _offset} = Spool.read(path)

      # Files from before REQUIRETLS do not have the flag.
      map = env |> Envelope.to_map() |> Map.delete("requiretls")
      write_raw(path, JSON.encode!(map) <> "\n", @message)
      assert {:ok, %Envelope{requiretls: false}, _} = Spool.read(path)
    end

    test "returns file errors", %{tmp_dir: dir} do
      assert Spool.read(Path.join(dir, "missing")) == {:error, :enoent}
    end
  end

  describe "records" do
    @at ~U[2026-10-04 12:00:00Z]

    defp details(status),
      do: %{status: status, reply: "250 2.0.0 Ok", remote: "mx[192.0.2.25]", smtp: true, at: @at}

    setup %{tmp_dir: dir} do
      %{path: spool!(dir)}
    end

    test "load/2 returns appended records", %{path: path} do
      {:ok, loaded} = Spool.load(path)
      assert loaded.records == []
      assert loaded.end_offset == File.stat!(path).size

      records = [
        {:recipient, "b@example.com", :delivered, details("2.0.0")},
        {:recipient, "c@example.com", :deferred, details("4.2.1")}
      ]

      assert {:ok, end_offset} = Spool.append(path, loaded.end_offset, records)
      assert {:ok, end_offset} = Spool.append(path, end_offset, [{:retry, 1, @at}])
      assert {:ok, ^end_offset} = Spool.append(path, end_offset, [])

      assert {:ok, reloaded} = Spool.load(path)
      assert reloaded.records == records ++ [{:retry, 1, @at}]
      assert reloaded.end_offset == end_offset
      assert reloaded.message_offset == loaded.message_offset
      assert reloaded.message_size == byte_size(@message)

      # read/1 still verifies the message.
      assert {:ok, _env, _offset} = Spool.read(path)
    end

    test "ignores an incomplete last record and overwrites it", %{path: path} do
      {:ok, loaded} = Spool.load(path)
      {:ok, end_offset} = Spool.append(path, loaded.end_offset, [{:retry, 1, @at}])

      # A crash in the middle of an append.
      File.write!(path, ~s(R 0123 {"type":"ret), [:append])
      assert {:ok, %{records: [{:retry, 1, @at}], end_offset: ^end_offset}} = Spool.load(path)

      {:ok, new_end} = Spool.append(path, end_offset, [:warned])

      assert {:ok, %{records: [{:retry, 1, @at}, :warned], end_offset: ^new_end}} =
               Spool.load(path)

      assert File.stat!(path).size == new_end
    end

    test "rejects a damaged record that is not the last", %{path: path} do
      {:ok, loaded} = Spool.load(path)
      {:ok, _} = Spool.append(path, loaded.end_offset, [{:retry, 1, @at}, :warned])

      File.write!(path, String.replace(File.read!(path), ~s("attempts":1), ~s("attempts":2)))
      assert Spool.load(path) == {:error, :invalid_record}
    end

    test "load/2 can skip the checksum and the records", %{path: path, tmp_dir: _} do
      {:ok, loaded} = Spool.load(path)
      {:ok, _} = Spool.append(path, loaded.end_offset, [:warned])
      contents = File.read!(path)
      pos = loaded.message_offset
      <<before::binary-size(^pos), byte, rest::binary>> = contents
      File.write!(path, <<before::binary, bxor(byte, 1), rest::binary>>)

      assert Spool.load(path) == {:error, :checksum_mismatch}
      assert {:ok, %{records: [:warned]}} = Spool.load(path, verify: false)
      assert {:ok, %{records: []}} = Spool.load(path, verify: false, records: false)
    end
  end

  describe "queues" do
    test "move/4, list/2, and recover/1", %{tmp_dir: dir} do
      env1 = envelope()
      env2 = envelope()
      spool!(dir, env1)
      spool!(dir, env2)

      assert Spool.list(dir, :incoming) == {:ok, Enum.sort([env1.queue_id, env2.queue_id])}
      assert Spool.move(dir, env1.queue_id, :incoming, :active) == :ok
      assert Spool.move(dir, env2.queue_id, :incoming, :hold) == :ok
      assert Spool.move(dir, env2.queue_id, :incoming, :active) == {:error, :enoent}

      assert Spool.list(dir, :active) == {:ok, [env1.queue_id]}
      assert {:ok, ^env1, _} = Spool.read(Spool.path(dir, :active, env1.queue_id))

      assert Spool.recover(dir) == {:ok, 1}
      assert Spool.list(dir, :incoming) == {:ok, [env1.queue_id]}
      assert Spool.list(dir, :active) == {:ok, []}
      assert Spool.list(dir, :hold) == {:ok, [env2.queue_id]}
    end

    test "list/2 skips files that are not queue files", %{tmp_dir: dir} do
      File.write!(Path.join([dir, "incoming", "README"]), "")
      assert Spool.list(dir, :incoming) == {:ok, []}
    end

    test "init/1 creates every queue", %{tmp_dir: dir} do
      for queue <- Spool.queues() do
        assert mode(Path.join(dir, Atom.to_string(queue))) == 0o700
      end
    end

    test "remove/4 deletes the file and emits an event", %{tmp_dir: dir} do
      TelemetryForwarder.attach([[:sovite, :queue, :message, :removed]])
      env = envelope()
      spool!(dir, env)
      id = env.queue_id

      assert Spool.remove(dir, :incoming, id, :delivered) == :ok
      assert Spool.list(dir, :incoming) == {:ok, []}

      assert_received {:telemetry, _, %{}, %{queue_id: ^id, reason: :delivered}}
      assert Spool.remove(dir, :incoming, id, :delivered) == {:error, :enoent}
    end
  end

  describe "message access" do
    test "stream_message/3 streams exactly the message", %{tmp_dir: dir} do
      big = String.duplicate("0123456789abcdef", 10_000) <> "\r\n"
      path = spool!(dir, envelope(), [@message, big])
      {:ok, loaded} = Spool.load(path)
      {:ok, _} = Spool.append(path, loaded.end_offset, [:warned])

      chunks =
        path |> Spool.stream_message(loaded.message_offset, loaded.message_size) |> Enum.to_list()

      assert length(chunks) > 1
      assert IO.iodata_to_binary(chunks) == @message <> big

      assert Spool.stream_message(path, loaded.message_offset, 0) |> Enum.to_list() == []
    end

    test "a prefix given to commit/2 comes first", %{tmp_dir: dir} do
      {:ok, writer} = Spool.open(dir, envelope())
      {:ok, writer} = Spool.write(writer, @message)
      prefix = "Authentication-Results: mx; none\r\n"
      assert {:ok, path, size} = Spool.commit(writer, [prefix])
      assert size == byte_size(prefix <> @message)

      assert {:ok, loaded} = Spool.load(path)
      assert loaded.prefix == prefix
      assert loaded.message_size == size

      stream = Spool.stream_message(path, loaded.message_offset, loaded.message_size, prefix)
      assert Enum.join(stream) == prefix <> @message

      assert Spool.read_headers(path, loaded.message_offset, size, prefix: prefix) ==
               {:ok, prefix <> "From: a@example.net\r\nSubject: hi\r\n"}

      assert Spool.read_headers(path, loaded.message_offset, size, prefix: prefix, limit: 40) ==
               {:ok, prefix}

      # The checksum covers the prefix.
      File.write!(path, String.replace(File.read!(path), "mx; none", "mx; pass"))
      assert Spool.read(path) == {:error, :checksum_mismatch}
    end

    test "read_headers/4 returns the header section", %{tmp_dir: dir} do
      path = spool!(dir)
      {:ok, loaded} = Spool.load(path)

      assert Spool.read_headers(path, loaded.message_offset, loaded.message_size) ==
               {:ok, "From: a@example.net\r\nSubject: hi\r\n"}

      # Cut at a line end when over the limit.
      assert Spool.read_headers(path, loaded.message_offset, loaded.message_size, limit: 25) ==
               {:ok, "From: a@example.net\r\n"}

      body_only = spool!(dir, envelope(), ["\r\nbody\r\n"])
      {:ok, loaded} = Spool.load(body_only)

      assert Spool.read_headers(body_only, loaded.message_offset, loaded.message_size) ==
               {:ok, ""}

      no_body = spool!(dir, envelope(), ["Subject: x\r\n"])
      {:ok, loaded} = Spool.load(no_body)

      assert Spool.read_headers(no_body, loaded.message_offset, loaded.message_size) ==
               {:ok, "Subject: x\r\n"}
    end
  end
end
