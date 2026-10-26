defmodule Sovite.Core.MTA.BounceTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.MTA.Bounce
  alias Sovite.Queue.{Entry, Envelope, ID, Spool}

  @moduletag :tmp_dir

  test "a notification about a REQUIRETLS message is sent with REQUIRETLS", %{tmp_dir: dir} do
    :ok = Spool.init(dir)

    envelope = %Envelope{
      queue_id: ID.generate(),
      sender: "alice@example.org",
      recipients: ["bob@example.net"],
      received_at: DateTime.utc_now(),
      requiretls: true,
      # RFC 8689 §5: as if RET=HDRS.
      ret: :full
    }

    {:ok, writer} = Spool.open(dir, envelope)
    {:ok, writer} = Spool.write(writer, "Subject: secret\r\n\r\nthe body\r\n")
    {:ok, path, _} = Spool.commit(writer)
    {:ok, source} = Spool.load(path)

    details = %{
      status: "5.7.30",
      reply: "REQUIRETLS support required",
      remote: nil,
      smtp: false,
      at: DateTime.utc_now()
    }

    opts = %{
      hostname: "mx.example.org",
      directory: dir,
      max_lifetime: 1000,
      double_bounce_recipient: nil
    }

    assert {:ok, id} =
             Bounce.notify(
               :failure,
               Entry.new(envelope, []),
               Map.put(source, :path, path),
               [{"bob@example.net", details}],
               opts
             )

    notification = Spool.path(dir, :incoming, id)
    {:ok, loaded} = Spool.load(notification)

    assert %Envelope{sender: "", recipients: ["alice@example.org"], requiretls: true} =
             loaded.envelope

    message =
      notification
      |> Spool.stream_message(loaded.message_offset, loaded.message_size, loaded.prefix)
      |> Enum.join()

    assert message =~ "Subject: secret"
    refute message =~ "the body"
  end

  defp queue(dir, envelope, message) do
    :ok = Spool.init(dir)
    {:ok, writer} = Spool.open(dir, envelope)
    {:ok, writer} = Spool.write(writer, message)
    {:ok, path, _} = Spool.commit(writer)
    {:ok, source} = Spool.load(path)
    Map.put(source, :path, path)
  end

  defp read(dir, id) do
    path = Spool.path(dir, :incoming, id)
    {:ok, loaded} = Spool.load(path)

    {loaded.envelope,
     path
     |> Spool.stream_message(loaded.message_offset, loaded.message_size, loaded.prefix)
     |> Enum.join()}
  end

  @details %{
    status: "5.1.1",
    reply: "550 5.1.1 unknown",
    remote: "mx[192.0.2.1]",
    smtp: true,
    at: ~U[2026-10-04 12:00:00Z]
  }

  defp opts(dir),
    do: %{
      hostname: "mx.example.org",
      directory: dir,
      max_lifetime: 1000,
      double_bounce_recipient: nil
    }

  test "a binary message is never returned whole", %{tmp_dir: dir} do
    envelope = %Envelope{
      queue_id: ID.generate(),
      sender: "alice@example.org",
      recipients: ["bob@example.net"],
      body_type: :binarymime,
      ret: :full
    }

    source = queue(dir, envelope, "Subject: bin\r\n\r\n\0body")

    assert {:ok, id} =
             Bounce.notify(
               :failure,
               Entry.new(envelope),
               source,
               [{"bob@example.net", @details}],
               opts(dir)
             )

    {_envelope, message} = read(dir, id)
    assert message =~ "Content-Type: text/rfc822-headers"
    refute message =~ "body"
  end

  test "success notifications go to real senders only", %{tmp_dir: dir} do
    envelope = %Envelope{queue_id: ID.generate(), sender: "", recipients: ["bob@example.net"]}
    source = queue(dir, envelope, "Subject: x\r\n\r\nbody\r\n")
    details = %{@details | status: "2.0.0", reply: "250 ok"} |> Map.put(:action, :relayed)

    assert Bounce.notify(
             :success,
             Entry.new(envelope),
             source,
             [{"bob@example.net", details}],
             opts(dir)
           ) ==
             {:ok, nil}

    envelope = %{envelope | sender: "alice@example.org", queue_id: ID.generate()}

    assert {:ok, id} =
             Bounce.notify(
               :success,
               Entry.new(envelope),
               source,
               [{"bob@example.net", details}],
               opts(dir)
             )

    {notification, message} = read(dir, id)
    assert %Envelope{sender: "", notification: :success} = notification
    assert message =~ "Action: relayed\r\n"
    assert message =~ "Status: 2.0.0\r\n"
  end
end
