defmodule Sovite.Core.InternationalTest do
  # Internationalized mail end to end: SMTPUTF8 in and out, the bounce
  # when the next hop lacks it, and internationalized domains in the
  # config and the database.
  use ExUnit.Case, async: true

  alias Sovite.Core.{Config, QueueManager, SMTPHandler}
  alias Sovite.Core.Repo.Tables.{Aliases, Domains}
  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.Test.{Database, FakeDNS, FakeMTA, SMTPClient, TelemetryForwarder}

  @moduletag :tmp_dir
  @moduletag :capture_log

  @timeout 5_000

  describe "receiving" do
    setup %{tmp_dir: dir} do
      queue = Path.join(dir, "queue")
      :ok = Spool.init(queue)

      {:ok, config} =
        Config.parse("""
        [server]
        hostname = "mx.example.com"
        [queue]
        directory = "#{queue}"
        [domains]
        local = ["bücher.example"]
        local_recipients = ["jürgen@bücher.example", "info@bücher.example"]
        """)

      handler = SMTPHandler.opts(config, nil, resolver: FakeDNS.resolver(%{}))

      server =
        start_supervised!(
          {Sovite.SMTP.Server,
           [
             ip: {127, 0, 0, 1},
             port: 0,
             hostname: config.server.hostname,
             handler: {SMTPHandler, handler},
             smtputf8: config.smtp.smtputf8
           ]}
        )

      {:ok, {_ip, port}} = Sovite.Listener.sockname(server)
      {:ok, client} = SMTPClient.connect(port)
      on_exit(fn -> SMTPClient.close(client) end)
      {:ok, {220, _}} = SMTPClient.read_reply(client)
      %{client: client, queue: queue}
    end

    defp command(client, line) do
      {:ok, {code, lines}} = SMTPClient.command(client, line)
      {code, List.last(lines)}
    end

    test "a message with internationalized addresses and header fields", context do
      %{client: client} = context
      assert {250, "SMTPUTF8"} = command(client, "EHLO client.example")
      assert {250, _} = command(client, "MAIL FROM:<anna@straße.example> SMTPUTF8")
      assert {250, _} = command(client, "RCPT TO:<jürgen@Bücher.example>")
      assert {550, _} = command(client, "RCPT TO:<unbekannt@bücher.example>")
      assert {354, _} = command(client, "DATA")

      assert {:ok, {250, _}} =
               SMTPClient.send_data(
                 client,
                 "From: anna@straße.example\r\nSubject: Grüße\r\n\r\nHallo\r\n"
               )

      {:ok, [id]} = Spool.list(context.queue, :incoming)
      {:ok, loaded} = Spool.load(Spool.path(context.queue, :incoming, id))

      assert %Envelope{
               smtputf8: true,
               sender: "anna@xn--strae-oqa.example",
               recipients: ["jürgen@xn--bcher-kva.example"]
             } = loaded.envelope

      message =
        Spool.path(context.queue, :incoming, id)
        |> Spool.stream_message(loaded.message_offset, loaded.message_size, loaded.prefix)
        |> Enum.join()

      assert message =~ "with UTF8SMTP id #{id}"
      assert message =~ "for <jürgen@xn--bcher-kva.example>"
      assert message =~ "Subject: Grüße\r\n"
    end

    test "internationalized addresses need SMTPUTF8", %{client: client} do
      assert {250, _} = command(client, "EHLO client.example")

      assert {553, "5.6.7 Non-ASCII addresses need the SMTPUTF8 parameter"} =
               command(client, "MAIL FROM:<anna@straße.example>")

      assert {250, _} = command(client, "MAIL FROM:<anna@example.org>")
      assert {553, _} = command(client, "RCPT TO:<jürgen@bücher.example>")
      assert {250, _} = command(client, "RCPT TO:<info@xn--bcher-kva.example>")
    end
  end

  describe "delivering" do
    @dns %{
      {"example.net", :mx} => [{10, "mx.example.net"}],
      {"xn--bcher-kva.example", :mx} => [{10, "mx.example.net"}],
      {"sender.example", :mx} => [{10, "mx.example.net"}],
      {"mx.example.net", :a} => [{127, 0, 0, 1}]
    }

    setup %{tmp_dir: dir} do
      TelemetryForwarder.attach([
        [:sovite, :queue, :message, :removed],
        [:sovite, :queue, :notification, :sent],
        [:sovite, :queue, :notification, :discarded],
        [:sovite, :smtp, :client, :delivery, :stop]
      ])

      :ok = Spool.init(dir)
      %{dir: dir}
    end

    defp start(context, extensions) do
      mta = start_supervised!({FakeMTA, owner: self(), extensions: extensions}, id: make_ref())

      {:ok, config} =
        Config.parse("""
        [server]
        hostname = "mx.example.org"
        [queue]
        directory = "#{context.dir}"
        min_backoff = "50ms"
        max_backoff = "100ms"
        """)

      opts =
        QueueManager.opts(config) ++
          [
            name: nil,
            resolver: FakeDNS.resolver(@dns),
            port: FakeMTA.port(mta),
            client: [command_timeout: 2_000, data_end_timeout: 2_000]
          ]

      manager = start_supervised!({QueueManager, opts})
      Map.merge(context, %{mta: mta, manager: manager})
    end

    defp enqueue(context, sender, recipients, header, smtputf8) do
      envelope = %Envelope{
        queue_id: ID.generate(),
        sender: sender,
        recipients: recipients,
        received_at: DateTime.utc_now(),
        smtputf8: smtputf8
      }

      {:ok, writer} = Spool.open(context.dir, envelope)
      {:ok, writer} = Spool.write(writer, header <> "\r\nbody\r\n")
      {:ok, _path, _size} = Spool.commit(writer)
      QueueManager.notify(context.manager, envelope.queue_id)
      envelope.queue_id
    end

    @utf8 ["PIPELINING", "8BITMIME", "SMTPUTF8"]
    @ascii ["PIPELINING", "8BITMIME"]

    test "with SMTPUTF8 to a next hop that supports it", context do
      %{mta: mta} = context = start(context, @utf8)

      id =
        enqueue(
          context,
          "anna@sender.example",
          ["jürgen@xn--bcher-kva.example"],
          "Subject: x\r\n",
          true
        )

      assert_receive {:fake_mta, ^mta, {:message, message}}, @timeout
      assert message.mail_args == "FROM:<anna@sender.example> SMTPUTF8"
      assert message.rcpt_to == ["jürgen@xn--bcher-kva.example"]
      assert_receive {:telemetry, _, _, %{queue_id: ^id, reason: :delivered}}, @timeout
    end

    test "without SMTPUTF8 when nothing needs it", context do
      %{mta: mta} = context = start(context, @ascii)
      enqueue(context, "anna@sender.example", ["bob@example.net"], "Subject: x\r\n", true)

      assert_receive {:fake_mta, ^mta, {:message, %{mail_args: "FROM:<anna@sender.example>"}}},
                     @timeout
    end

    test "returns what cannot be downgraded, with an internationalized notification", context do
      context = start(context, @ascii)

      id =
        enqueue(
          context,
          "anna@sender.example",
          ["jürgen@xn--bcher-kva.example"],
          "Subject: x\r\n",
          false
        )

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{queue_id: ^id, status: :failed, reply: reply}},
                     @timeout

      assert reply =~ "non-ASCII addresses need SMTPUTF8, but host mx.example.net"
      assert_receive {:telemetry, _, _, %{queue_id: ^id, reason: :bounced}}, @timeout

      assert_receive {:telemetry, [:sovite, :queue, :notification, :sent], _,
                      %{queue_id: ^id, notification_id: dsn_id}},
                     @timeout

      # Its envelope and header fields are ASCII, so it needs no SMTPUTF8:
      # 8BITMIME carries the UTF-8 parts.
      assert_receive {:fake_mta, _mta, {:message, %{mail_from: "", data: dsn}}}, @timeout
      assert dsn =~ "report-type=global-delivery-status"
      assert dsn =~ "Final-Recipient: utf-8; jürgen@xn--bcher-kva.example\r\n"
      assert dsn =~ "Status: 5.6.7\r\n"
      assert_receive {:telemetry, _, _, %{queue_id: ^dsn_id, reason: :delivered}}, @timeout
    end

    test "returns UTF-8 header fields of an SMTPUTF8 message", context do
      context = start(context, @ascii)

      id =
        enqueue(context, "anna@sender.example", ["bob@example.net"], "Subject: Grüße\r\n", true)

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{queue_id: ^id, status: :failed, reply: reply}},
                     @timeout

      assert reply =~ "UTF-8 header fields, which need SMTPUTF8"
    end
  end

  test "internationalized domains in the database", %{tmp_dir: dir} do
    repo = Database.start!(dir)

    assert {:ok, %{name: "xn--bcher-kva.example"}} = Domains.add(repo, "Bücher.example", "hosted")
    assert {:ok, _} = Aliases.add(repo, "info@bücher.example", ["jürgen@münchen.example"])

    assert Aliases.lookup(%{repo: repo}, "info@xn--bcher-kva.example") ==
             {:ok, "jürgen@xn--mnchen-3ya.example"}

    assert {:ok, _} = Aliases.add(repo, "jürgen.müller", ["a@example.com"])
    assert Aliases.lookup(%{repo: repo}, "jürgen.müller") == {:ok, "a@example.com"}
    assert :ok = Domains.delete(repo, "bücher.example")
  end
end
