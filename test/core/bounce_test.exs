defmodule Sovite.Core.BounceTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Bounce
  alias Sovite.Queue.{Entry, Envelope, ID, Spool}

  @moduletag :tmp_dir

  test "a notification about a REQUIRETLS message is sent with REQUIRETLS", %{tmp_dir: dir} do
    :ok = Spool.init(dir)

    envelope = %Envelope{
      queue_id: ID.generate(),
      sender: "alice@example.org",
      recipients: ["bob@example.net"],
      received_at: DateTime.utc_now(),
      requiretls: true
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
end
