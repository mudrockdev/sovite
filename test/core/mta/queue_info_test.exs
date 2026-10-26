defmodule Sovite.Core.MTA.QueueInfoTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.MTA.QueueInfo
  alias Sovite.Queue.{Envelope, ID, Spool}

  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    :ok = Spool.init(dir)
    %{dir: dir}
  end

  defp spool(
         dir,
         fields,
         queue \\ :incoming,
         body \\ "Message-ID: <m1@example.org>\r\nSubject: Hi\r\n\r\nbody\r\n"
       ) do
    envelope =
      struct!(
        Envelope,
        [
          queue_id: ID.generate(),
          sender: "alice@example.org",
          recipients: ["bob@example.net", "carol@example.net"],
          received_at: ~U[2026-10-04 12:00:00Z],
          remote_ip: {192, 0, 2, 7},
          helo: "client.example",
          protocol: "ESMTPS"
        ] ++ fields
      )

    {:ok, writer} = Spool.open(dir, envelope)
    {:ok, writer} = Spool.write(writer, body)
    {:ok, _path, _size} = Spool.commit(writer)
    if queue != :incoming, do: :ok = Spool.move(dir, envelope.queue_id, :incoming, queue)
    envelope.queue_id
  end

  test "lists messages with their pending recipients and last error", %{dir: dir} do
    id = spool(dir, [], :deferred)
    path = Spool.path(dir, :deferred, id)
    {:ok, loaded} = Spool.load(path)
    at = ~U[2026-10-04 12:05:00Z]

    {:ok, _} =
      Spool.append(path, loaded.end_offset, [
        {:recipient, "bob@example.net", :delivered,
         %{status: "2.0.0", reply: "250 ok", remote: "mx", smtp: true, at: at}},
        {:recipient, "carol@example.net", :deferred,
         %{status: "4.2.2", reply: "452 mailbox full", remote: "mx", smtp: true, at: at}},
        {:retry, 1, ~U[2026-10-04 12:10:00Z]}
      ])

    held = spool(dir, [received_at: ~U[2026-10-04 13:00:00Z], priority: 3], :hold)

    assert [first, second] = QueueInfo.list(dir)

    assert %{
             queue_id: ^id,
             queue: "deferred",
             sender: "alice@example.org",
             recipients: 2,
             pending: ["carol@example.net"],
             attempts: 1,
             next_attempt: "2026-10-04T12:10:00Z",
             reason: "452 mailbox full",
             received_at: "2026-10-04T12:00:00Z"
           } = first

    assert %{queue_id: ^held, queue: "hold", priority: 3, reason: nil} = second
    assert [%{queue_id: ^held}] = QueueInfo.list(dir, queues: [:hold])
    assert [%{queue_id: ^id}] = QueueInfo.list(dir, limit: 1)
    assert QueueInfo.counts(dir) == %{incoming: 0, active: 0, deferred: 1, hold: 1, corrupt: 0}
  end

  test "shows a message", %{dir: dir} do
    id = spool(dir, auth_user: "alice", hold: {:until, ~U[2026-10-20 12:00:00Z]})

    assert QueueInfo.locate(dir, id) == :incoming
    assert {:ok, message} = QueueInfo.show(dir, id)

    assert %{
             queue: "incoming",
             client: "192.0.2.7",
             helo: "client.example",
             user: "alice",
             message_id: "<m1@example.org>",
             subject: "Hi",
             release_at: "2026-10-20T12:00:00Z",
             headers: "Message-ID: <m1@example.org>\r\nSubject: Hi\r\n",
             recipient_status: [
               %{address: "bob@example.net", status: "pending", reply: nil},
               %{address: "carol@example.net", status: "pending"}
             ]
           } = message

    assert JSON.encode!(message)
  end

  test "8-bit headers come back as valid UTF-8", %{dir: dir} do
    id = spool(dir, [], :incoming, "Subject: caf\xE9\r\n\r\nx\r\n")
    assert {:ok, %{subject: subject}} = QueueInfo.show(dir, id)
    assert String.valid?(subject)
  end

  test "unknown and unreadable messages", %{dir: dir} do
    assert QueueInfo.show(dir, "8CrIr95AD2x90M") == {:error, :not_found}
    assert QueueInfo.show(dir, "../../etc/passwd") == {:error, :not_found}
    assert QueueInfo.locate(dir, "../x") == nil

    id = ID.generate()
    File.write!(Spool.path(dir, :corrupt, id), "garbage")
    assert [%{queue_id: ^id, queue: "corrupt", error: _}] = QueueInfo.list(dir)
    assert {:error, :invalid_header} = QueueInfo.show(dir, id)
  end
end
