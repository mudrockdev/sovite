defmodule Sovite.Core.FinalDeliveryTest do
  # Delivery.run for the final transports: LMTP, Maildir, and pipes.
  use ExUnit.Case, async: true

  alias Sovite.Core.Delivery
  alias Sovite.Core.Delivery.Local
  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.Test.{FakeDNS, FakeMTA}

  @moduletag :tmp_dir

  @body "Subject: hello\r\n\r\nbody\r\n"

  setup %{tmp_dir: dir} do
    queue = Path.join(dir, "queue")
    :ok = Spool.init(queue)

    # Unix socket paths are limited to about 100 bytes, too few for tmp_dir.
    socket = Path.join(System.tmp_dir!(), "sovite-lmtp-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm(socket) end)

    %{queue: queue, socket: socket}
  end

  defp opts(context, extra \\ %{}) do
    Map.merge(
      %{
        hostname: "mx.example.org",
        resolver: FakeDNS.resolver(%{{"lmtp.internal", :a} => [{127, 0, 0, 1}]}),
        port: 25,
        families: [:a],
        max_addresses: 5,
        client: [helo: "mx.example.org", command_timeout: 2_000, data_end_timeout: 2_000],
        tls: %{default: :none, policy: %{}, cacerts: nil},
        maildir: %{},
        pipes: %{},
        delimiter: "+",
        tmp_dir: Path.join(context.queue, "tmp")
      },
      extra
    )
  end

  defp job(context, destination, recipients, body \\ @body, sender \\ "alice@example.net") do
    envelope = %Envelope{
      queue_id: ID.generate(),
      sender: sender,
      recipients: recipients,
      received_at: DateTime.utc_now()
    }

    {:ok, writer} = Spool.open(context.queue, envelope)
    {:ok, writer} = Spool.write(writer, body)
    {:ok, path, _size} = Spool.commit(writer)
    {:ok, loaded} = Spool.load(path)

    %{
      queue_id: envelope.queue_id,
      destination: destination,
      recipients: recipients,
      sender: sender,
      body_type: nil,
      path: path,
      message_offset: loaded.message_offset,
      message_size: loaded.message_size,
      prefix: loaded.prefix
    }
  end

  defp outcomes(results),
    do: Enum.map(results, fn {rcpt, status, d} -> {rcpt, status, d.status} end)

  defp script(dir, body) do
    path = Path.join(dir, "pipe-#{System.unique_integer([:positive])}")
    File.write!(path, "#!/bin/sh\n" <> body)
    File.chmod!(path, 0o755)
    path
  end

  defp pipe(command, extra \\ %{}) do
    Map.merge(
      %{
        command: command,
        sandbox: nil,
        timeout: 5_000,
        directory: "/",
        env: %{},
        trace_headers: true
      },
      extra
    )
  end

  describe "LMTP" do
    test "gives each recipient its own status", %{socket: socket} = context do
      replies = fn
        "full@example.com" -> "452 4.2.2 Mailbox full"
        "gone@example.com" -> "550 5.1.1 No such user"
        _ -> "250 2.0.0 Saved"
      end

      mta =
        start_supervised!(
          {FakeMTA, owner: self(), lmtp: true, unix: socket, responses: %{lmtp_data_end: replies}}
        )

      recipients = ~w(a@example.com full@example.com gone@example.com)
      job = job(context, %{transport: :lmtp, nexthop: {:unix, socket}}, recipients)

      assert {results, {_client, ^socket} = connection} = Delivery.run(job, nil, opts(context))

      assert outcomes(results) == [
               {"a@example.com", :delivered, "2.0.0"},
               {"full@example.com", :deferred, "4.2.2"},
               {"gone@example.com", :failed, "5.1.1"}
             ]

      assert_receive {:fake_mta, ^mta, {:message, message}}
      assert message.delivered == ["a@example.com"]
      assert message.data == @body

      # The connection is reused for the next job.
      next = job(context, job.destination, ["b@example.com"])

      assert {[{"b@example.com", :delivered, _}], _} =
               Delivery.run(next, connection, opts(context))
    end

    test "connects to a host", context do
      mta = start_supervised!({FakeMTA, owner: self(), lmtp: true})
      host = %{host: "lmtp.internal", port: FakeMTA.port(mta), mx: false}
      job = job(context, %{transport: :lmtp, nexthop: {:host, host}}, ["a@example.com"])

      assert {[{"a@example.com", :delivered, details}], _} = Delivery.run(job, nil, opts(context))
      assert details.remote == "lmtp.internal[127.0.0.1]"
    end

    test "defers when the server is down", %{socket: socket} = context do
      job = job(context, %{transport: :lmtp, nexthop: {:unix, socket}}, ["a@example.com"])

      assert {[{"a@example.com", :deferred, %{status: "4.4.1", reply: reply}}], nil} =
               Delivery.run(job, nil, opts(context))

      assert reply =~ "connect to #{socket}: "
    end
  end

  describe "Maildir" do
    test "delivers with Return-Path and Delivered-To", %{tmp_dir: dir} = context do
      maildir = %{local: Path.join(dir, "mail/{domain}/{user}")}
      job = job(context, %{transport: :local}, ["Bob+lists@Example.COM", "carol@example.com"])

      assert {results, nil} = Delivery.run(job, nil, opts(context, %{maildir: maildir}))

      assert outcomes(results) == [
               {"Bob+lists@Example.COM", :delivered, "2.0.0"},
               {"carol@example.com", :delivered, "2.0.0"}
             ]

      [file] = File.ls!(Path.join(dir, "mail/example.com/bob/new"))

      assert File.read!(Path.join(dir, "mail/example.com/bob/new/" <> file)) ==
               "Return-Path: <alice@example.net>\r\nDelivered-To: Bob+lists@Example.COM\r\n" <>
                 @body

      assert [_] = File.ls!(Path.join(dir, "mail/example.com/carol/new"))
    end

    test "is deferred until configured", context do
      job = job(context, %{transport: :mailbox}, ["a@example.com"])

      assert {[{_, :deferred, %{status: "4.3.5", reply: reply}}], nil} =
               Delivery.run(job, nil, opts(context))

      assert reply =~ "maildir.mailbox"
    end

    test "refuses addresses that are not safe in a path" do
      assert {:ok, "/m/example.com/a.b"} =
               Local.maildir_path("/m/{domain}/{user}", "a.b@example.com", "")

      assert :error = Local.maildir_path("/m/{user}", "a/b@example.com", "")
      assert :error = Local.maildir_path("/m/{user}", "..@example.com", "")
      assert :error = Local.maildir_path("/m/{user}", "..+x@example.com", "+")

      assert {:ok, "/m/a@example.com"} =
               Local.maildir_path("/m/{address}", "A+x@example.com", "+")
    end
  end

  describe "loops" do
    test "a recipient in Delivered-To fails, the others are delivered",
         %{tmp_dir: dir} = context do
      body = "Delivered-To: bob@example.com\r\n" <> @body
      maildir = %{local: Path.join(dir, "{user}")}
      job = job(context, %{transport: :local}, ["BOB@example.com", "carol@example.com"], body)

      assert {results, nil} = Delivery.run(job, nil, opts(context, %{maildir: maildir}))

      assert [
               {"BOB@example.com", :failed, %{status: "5.4.6", reply: reply}},
               {"carol@example.com", :delivered, _}
             ] = results

      assert reply == "mail forwarding loop for BOB@example.com"
      refute File.exists?(Path.join(dir, "bob"))
    end
  end

  describe "pipe" do
    test "runs the command with the message on standard input", %{tmp_dir: dir} = context do
      out = Path.join(dir, "out")
      command = script(dir, ~s(cat > "$1"; env | sort > "$1.env"\n))
      pipes = %{"save" => pipe([command, out <> "-{user}-{extension}"], %{env: %{"X" => "y"}})}
      job = job(context, %{transport: :pipe, name: "save"}, ["bob+tag@example.com"])

      assert {[{"bob+tag@example.com", :delivered, %{reply: "delivered via pipe save"}}], nil} =
               Delivery.run(job, nil, opts(context, %{pipes: pipes}))

      assert File.read!(out <> "-bob-tag") ==
               "Return-Path: <alice@example.net>\r\nDelivered-To: bob+tag@example.com\r\n" <>
                 @body

      env = File.read!(out <> "-bob-tag.env")
      assert env =~ "RECIPIENT=bob+tag@example.com\n"
      assert env =~ "SENDER=alice@example.net\n"
      assert env =~ "EXTENSION=tag\n"
      assert env =~ "QUEUE_ID=#{job.queue_id}\n"
      assert env =~ "X=y\n"

      # The input file is gone.
      assert File.ls!(Path.join(context.queue, "tmp")) == []
    end

    test "maps exit statuses", %{tmp_dir: dir} = context do
      pipes = %{
        "nouser" => pipe([script(dir, "echo 'no such mailbox'; exit 67\n")]),
        "tempfail" => pipe([script(dir, "exit 75\n")]),
        "odd" => pipe([script(dir, "exit 3\n")]),
        "slow" => pipe([script(dir, "exec sleep 10\n")], %{timeout: 200}),
        "plain" => pipe([script(dir, "cat > /dev/null\n")], %{trace_headers: false})
      }

      run = fn name ->
        job = job(context, %{transport: :pipe, name: name}, ["a@example.com"])
        {[{_, status, details}], nil} = Delivery.run(job, nil, opts(context, %{pipes: pipes}))
        {status, details.status, details.reply}
      end

      assert run.("nouser") ==
               {:failed, "5.1.1",
                "command nouser failed with status 67 (user unknown): no such mailbox"}

      assert {:deferred, "4.3.0", _} = run.("tempfail")
      assert {:failed, "5.3.0", "command odd failed with status 3 (unknown error)"} = run.("odd")
      assert {:deferred, "4.3.0", "command slow ran too long and was killed"} = run.("slow")
      assert {:delivered, "2.0.0", _} = run.("plain")
      assert {:deferred, "4.3.5", "pipe missing is not configured"} = run.("missing")
    end
  end
end
