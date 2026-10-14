defmodule Sovite.Core.ExtensionsTest do
  # The ESMTP extensions of Phase 11 end to end: CHUNKING and BINARYMIME,
  # DSN, and ETRN, received by the MTA and relayed to a next hop.
  use ExUnit.Case, async: true

  alias Sovite.Core.{Config, QueueManager, SMTPHandler}
  alias Sovite.Core.Repo.Tables.{Aliases, Mailboxes}
  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.SMTP.Params
  alias Sovite.Test.{Database, FakeDNS, FakeMTA, SMTPClient, TelemetryForwarder}

  @moduletag :tmp_dir
  @moduletag :capture_log

  @timeout 5_000

  describe "receiving" do
    setup %{tmp_dir: dir} do
      queue = Path.join(dir, "queue")
      :ok = Spool.init(queue)
      repo = Database.start!(dir)
      {:ok, _} = Aliases.add(repo, "team@example.com", ["alice@example.com", "bob@example.com"])
      {:ok, _} = Aliases.add(repo, "fwd@example.com", ["alice@example.com"])
      {:ok, _} = Mailboxes.add(repo, "carol@hosted.example")

      {:ok, config} =
        Config.parse("""
        [server]
        hostname = "mx.example.com"
        [queue]
        directory = "#{queue}"
        [domains]
        local = ["example.com"]
        relay = ["backup.example"]
        hosted = ["hosted.example"]
        local_recipients = ["alice@example.com", "bob@example.com"]
        """)

      handler = SMTPHandler.opts(config, nil, repo: repo, resolver: FakeDNS.resolver(%{}))

      server =
        start_supervised!(
          {Sovite.SMTP.Server,
           [
             ip: {127, 0, 0, 1},
             port: 0,
             hostname: config.server.hostname,
             handler: {SMTPHandler, handler},
             chunking: config.smtp.chunking,
             binarymime: true,
             dsn: config.smtp.dsn,
             etrn: config.smtp.etrn,
             mt_priority: config.smtp.mt_priority,
             deliverby: config.smtp.deliverby,
             rrvs: config.smtp.rrvs,
             future_release: 3600
           ]}
        )

      {:ok, {_ip, port}} = Sovite.Listener.sockname(server)
      {:ok, client} = SMTPClient.connect(port)
      on_exit(fn -> SMTPClient.close(client) end)
      {:ok, {220, _}} = SMTPClient.read_reply(client)
      {:ok, {250, lines}} = SMTPClient.command(client, "EHLO client.example")
      %{client: client, queue: queue, extensions: lines}
    end

    defp command(client, line) do
      {:ok, {code, lines}} = SMTPClient.command(client, line)
      {code, List.last(lines)}
    end

    defp queued(queue) do
      {:ok, [id]} = Spool.list(queue, :incoming)
      path = Spool.path(queue, :incoming, id)
      {:ok, loaded} = Spool.load(path)

      message =
        path
        |> Spool.stream_message(loaded.message_offset, loaded.message_size, loaded.prefix)
        |> Enum.join()

      {loaded.envelope, message}
    end

    test "offers the extensions", %{extensions: extensions} do
      for extension <- ["CHUNKING", "BINARYMIME", "DSN", "ETRN"],
          do: assert(extension in extensions)
    end

    test "a message in BDAT chunks, with DSN parameters", %{client: client} = context do
      assert {250, _} = command(client, "MAIL FROM:<anna@example.org> RET=FULL ENVID=Q+2B1")

      assert {250, _} =
               command(
                 client,
                 "RCPT TO:<alice@example.com> NOTIFY=SUCCESS ORCPT=rfc822;Alice@example.com"
               )

      assert {250, _} = command(client, "RCPT TO:<bob@example.com> NOTIFY=NEVER")

      chunk = "Subject: chunks\r\n\r\n.first\r\n"
      assert :ok = SMTPClient.send_raw(client, ["BDAT #{byte_size(chunk)}\r\n", chunk])
      assert {:ok, {250, [text]}} = SMTPClient.read_reply(client)
      assert text =~ "#{byte_size(chunk)} octets received"
      assert :ok = SMTPClient.send_raw(client, ["BDAT 8 LAST\r\n", "second\r\n"])
      assert {:ok, {250, [text]}} = SMTPClient.read_reply(client)
      assert text =~ "queued as"

      {envelope, message} = queued(context.queue)
      assert message =~ ~r/\r\nReceived: .*\r\nSubject: chunks\r\n\r\n.first\r\nsecond\r\n\z/s

      assert %Envelope{ret: :full, envid: "Q+1", expanded: []} = envelope

      assert envelope.dsn == %{
               "alice@example.com" => %{
                 notify: [:success],
                 orcpt: {"rfc822", "Alice@example.com"}
               },
               "bob@example.com" => %{notify: :never, orcpt: nil}
             }
    end

    test "aliases pass the DSN parameters on", %{client: client} = context do
      assert {250, _} = command(client, "MAIL FROM:<anna@example.org>")
      assert {250, _} = command(client, "RCPT TO:<team@example.com> NOTIFY=SUCCESS,FAILURE")
      assert {250, _} = command(client, "RCPT TO:<fwd@example.com> NOTIFY=DELAY")
      assert {354, _} = command(client, "DATA")
      assert {:ok, {250, _}} = SMTPClient.send_data(client, "Subject: x\r\n\r\nbody\r\n")

      {envelope, _message} = queued(context.queue)
      assert envelope.recipients == ["alice@example.com", "bob@example.com"]
      assert envelope.expanded == ["team@example.com"]

      # Expanded to several: SUCCESS goes, the alias is reported as
      # expanded. The second RCPT adds no new recipient.
      assert envelope.dsn == %{
               "team@example.com" => %{
                 notify: [:success, :failure],
                 orcpt: {"rfc822", "team@example.com"}
               },
               "alice@example.com" => %{notify: [:failure], orcpt: {"rfc822", "team@example.com"}},
               "bob@example.com" => %{notify: [:failure], orcpt: {"rfc822", "team@example.com"}}
             }
    end

    test "a forwarding alias keeps the parameters, with the alias as ORCPT", context do
      %{client: client} = context
      assert {250, _} = command(client, "MAIL FROM:<anna@example.org>")
      assert {250, _} = command(client, "RCPT TO:<fwd@example.com> NOTIFY=SUCCESS")
      assert {354, _} = command(client, "DATA")
      assert {:ok, {250, _}} = SMTPClient.send_data(client, "Subject: x\r\n\r\nbody\r\n")

      {envelope, _message} = queued(context.queue)
      assert envelope.expanded == []

      assert envelope.dsn == %{
               "alice@example.com" => %{notify: [:success], orcpt: {"rfc822", "fwd@example.com"}}
             }
    end

    test "a binary message", %{client: client} = context do
      assert {250, _} = command(client, "MAIL FROM:<anna@example.org> BODY=BINARYMIME")
      assert {250, _} = command(client, "RCPT TO:<alice@example.com>")
      assert {503, _} = command(client, "DATA")
      body = "Subject: bin\r\n\r\n\0\xFF\n\r"
      assert :ok = SMTPClient.send_raw(client, ["BDAT #{byte_size(body)} LAST\r\n", body])
      assert {:ok, {250, _}} = SMTPClient.read_reply(client)

      {envelope, message} = queued(context.queue)
      assert envelope.body_type == :binarymime
      assert String.ends_with?(message, body)
    end

    test "priorities, deadlines, and RRVS", %{client: client} = context do
      assert {250, _} = command(client, "MAIL FROM:<anna@example.org> MT-PRIORITY=5 BY=600;N")
      assert {250, _} = command(client, "RCPT TO:<x@backup.example> RRVS=2014-04-03T23:01:00Z;C")
      assert {250, _} = command(client, "RCPT TO:<alice@example.com> RRVS=2014-04-03T23:01:00Z")

      # The mailbox was added just now.
      assert {550, "5.7.17 <carol@hosted.example>: Mailbox owner has changed"} =
               command(client, "RCPT TO:<carol@hosted.example> RRVS=2014-04-03T23:01:00Z")

      later = DateTime.utc_now() |> DateTime.add(60) |> Params.format_time()
      assert {250, _} = command(client, "RCPT TO:<carol@hosted.example> RRVS=#{later}")
      assert {354, _} = command(client, "DATA")
      assert {:ok, {250, _}} = SMTPClient.send_data(client, "Subject: x\r\n\r\nbody\r\n")

      {envelope, message} = queued(context.queue)
      # Not trusted: no higher priority.
      assert envelope.priority == 0
      assert message =~ "PRIORITY 0;"
      assert envelope.rrvs == %{"x@backup.example" => {~U[2014-04-03 23:01:00Z], :continue}}
      assert %{mode: :notify, trace: false, deadline: deadline} = envelope.deliver_by
      assert_in_delta DateTime.diff(deadline, envelope.received_at), 600, 1
    end

    test "future release needs authentication", %{client: client} do
      assert {550, "5.7.1 Future release needs authentication"} =
               command(client, "MAIL FROM:<anna@example.org> HOLDFOR=60")

      assert {250, _} = command(client, "MAIL FROM:<anna@example.org> MT-PRIORITY=-2")
    end

    test "ETRN for relay domains only", %{client: client} do
      # No queue manager here.
      assert {458, "4.3.0 Unable to queue messages for node backup.example"} =
               command(client, "ETRN backup.example")

      assert {459, "4.7.1 Node @example.com not allowed: not a relay domain"} =
               command(client, "ETRN @example.com")

      assert {459, "4.7.1 Node #deferred not allowed: unknown queue"} =
               command(client, "ETRN #deferred")
    end
  end

  describe "delivering" do
    @dns %{
      {"example.net", :mx} => [{10, "mx.example.net"}],
      {"sender.example", :mx} => [{10, "mx.example.net"}],
      {"mx.example.net", :a} => [{127, 0, 0, 1}]
    }

    setup %{tmp_dir: dir} do
      TelemetryForwarder.attach([
        [:sovite, :queue, :message, :removed],
        [:sovite, :queue, :message, :deferred],
        [:sovite, :queue, :notification, :sent],
        [:sovite, :smtp, :client, :delivery, :stop]
      ])

      :ok = Spool.init(dir)
      %{dir: dir}
    end

    defp start(context, mta_opts, config \\ "") do
      mta = start_supervised!({FakeMTA, [owner: self()] ++ mta_opts}, id: make_ref())

      {:ok, config} =
        Config.parse("""
        [server]
        hostname = "mx.example.org"
        [queue]
        directory = "#{context.dir}"
        min_backoff = "1h"
        max_backoff = "2h"
        #{config}
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

    defp enqueue(context, fields, body \\ "Subject: x\r\n\r\nbody\r\n") do
      envelope =
        struct!(
          %Envelope{
            queue_id: ID.generate(),
            sender: "anna@sender.example",
            recipients: ["bob@example.net"],
            received_at: DateTime.utc_now()
          },
          fields
        )

      {:ok, writer} = Spool.open(context.dir, envelope)
      {:ok, writer} = Spool.write(writer, body)
      {:ok, _path, _size} = Spool.commit(writer)
      QueueManager.notify(context.manager, envelope.queue_id)
      envelope.queue_id
    end

    @dsn ["PIPELINING", "8BITMIME", "DSN"]

    # Notifications to the sender still go through.
    defp reject_but_sender("anna@sender.example"), do: "250 2.1.5 OK"
    defp reject_but_sender(_rcpt), do: "550 5.1.1 unknown"

    test "relays the DSN parameters to a server that supports DSN", context do
      %{mta: mta} = context = start(context, extensions: @dsn)

      id =
        enqueue(context,
          ret: :hdrs,
          envid: "E 1",
          dsn: %{"bob@example.net" => %{notify: [:success], orcpt: {"rfc822", "b@example.net"}}}
        )

      assert_receive {:fake_mta, ^mta, {:message, message}}, @timeout
      assert message.mail_args == "FROM:<anna@sender.example> RET=HDRS ENVID=E+201"

      assert message.rcpt_args == [
               "TO:<bob@example.net> NOTIFY=SUCCESS ORCPT=rfc822;b@example.net"
             ]

      assert_receive {:telemetry, _, _, %{queue_id: ^id, reason: :delivered}}, @timeout
      # That server reports the delivery.
      refute_received {:telemetry, [:sovite, :queue, :notification, :sent], _, %{queue_id: ^id}}
    end

    test "reports relaying to a server without DSN, when asked to", context do
      %{mta: mta} = context = start(context, extensions: ["PIPELINING", "8BITMIME"])

      id =
        enqueue(context,
          envid: "E1",
          recipients: ["bob@example.net", "carol@example.net"],
          dsn: %{"bob@example.net" => %{notify: [:success], orcpt: {"rfc822", "B@example.net"}}}
        )

      assert_receive {:fake_mta, ^mta, {:message, %{mail_from: "anna@sender.example"} = message}},
                     @timeout

      assert message.rcpt_args == ["TO:<bob@example.net>", "TO:<carol@example.net>"]

      assert_receive {:telemetry, [:sovite, :queue, :notification, :sent], _,
                      %{queue_id: ^id, kind: :success}},
                     @timeout

      assert_receive {:fake_mta, ^mta, {:message, %{mail_from: "", data: dsn}}}, @timeout
      assert dsn =~ "Subject: Successful Mail Delivery Report\r\n"
      assert dsn =~ "Original-Envelope-Id: E1\r\n"

      assert dsn =~
               "Original-Recipient: rfc822; B@example.net\r\nFinal-Recipient: rfc822; bob@example.net\r\nAction: relayed\r\n"

      refute dsn =~ "carol@example.net"
      refute dsn =~ "\r\nbody\r\n"
    end

    test "reports expanded aliases", context do
      context = start(context, extensions: @dsn)

      id =
        enqueue(context,
          expanded: ["team@example.org"],
          dsn: %{"team@example.org" => %{notify: [:success], orcpt: nil}}
        )

      assert_receive {:telemetry, [:sovite, :queue, :notification, :sent], _,
                      %{queue_id: ^id, kind: :success}},
                     @timeout

      assert_receive {:fake_mta, _, {:message, %{mail_from: "", data: dsn}}}, @timeout
      assert dsn =~ "Final-Recipient: rfc822; team@example.org\r\nAction: expanded\r\n"
    end

    test "NOTIFY decides which failures are reported", context do
      context = start(context, extensions: @dsn, responses: %{rcpt: &reject_but_sender/1})

      id =
        enqueue(context,
          recipients: ["a@example.net", "b@example.net", "c@example.net"],
          dsn: %{
            "a@example.net" => %{notify: :never, orcpt: nil},
            "b@example.net" => %{notify: [:success, :delay], orcpt: nil}
          }
        )

      assert_receive {:telemetry, [:sovite, :queue, :notification, :sent], _,
                      %{queue_id: ^id, kind: :failure}},
                     @timeout

      assert_receive {:telemetry, _, _, %{queue_id: ^id, reason: :bounced}}, @timeout
      assert_receive {:fake_mta, _, {:message, %{mail_from: "", data: dsn}}}, @timeout
      assert dsn =~ "Final-Recipient: rfc822; c@example.net\r\n"
      refute dsn =~ "a@example.net"
      refute dsn =~ "b@example.net"

      # NOTIFY=NEVER for every failure: no notification at all.
      id = enqueue(context, dsn: %{"bob@example.net" => %{notify: :never, orcpt: nil}})
      assert_receive {:telemetry, _, _, %{queue_id: ^id, reason: :bounced}}, @timeout
      refute_received {:telemetry, [:sovite, :queue, :notification, :sent], _, %{queue_id: ^id}}
    end

    test "RET=FULL returns the whole message, up to bounce.size_limit", context do
      context =
        start(context, [extensions: @dsn, responses: %{rcpt: &reject_but_sender/1}], """
        [bounce]
        size_limit = 100
        """)

      enqueue(context, ret: :full)
      assert_receive {:fake_mta, _, {:message, %{mail_from: "", data: dsn}}}, @timeout
      assert dsn =~ "Content-Type: message/rfc822\r\n"
      assert dsn =~ "Subject: x\r\n\r\nbody\r\n"

      enqueue(
        context,
        [ret: :full],
        "Subject: big\r\n\r\n" <> String.duplicate("x", 200) <> "\r\n"
      )

      assert_receive {:fake_mta, _, {:message, %{mail_from: "", data: dsn}}}, @timeout
      assert dsn =~ "Content-Type: text/rfc822-headers\r\n"
      refute dsn =~ "xxxx"
    end

    test "sends with BDAT to a server that offers CHUNKING", context do
      %{mta: mta} = context = start(context, extensions: ["PIPELINING", "CHUNKING"])
      enqueue(context, [])
      assert_receive {:fake_mta, ^mta, {:message, %{chunked: true, data: data}}}, @timeout
      assert data == "Subject: x\r\n\r\nbody\r\n"
    end

    test "a binary message needs a next hop with BINARYMIME", context do
      context = start(context, extensions: ["PIPELINING", "8BITMIME", "CHUNKING"])
      id = enqueue(context, [body_type: :binarymime], "Subject: x\r\n\r\n\0\r")

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{queue_id: ^id, status: :failed, reply: reply}},
                     @timeout

      assert reply =~ "binary message, but mx.example.net[127.0.0.1] does not support BINARYMIME"
    end

    test "ETRN retries the deferred mail for a domain", context do
      {:ok, attempts} = Agent.start_link(fn -> 0 end)

      rcpt = fn _rcpt ->
        if Agent.get_and_update(attempts, &{&1, &1 + 1}) == 0,
          do: "451 4.3.0 try later",
          else: "250 2.1.5 OK"
      end

      %{mta: mta, manager: manager} =
        context = start(context, extensions: @dsn, responses: %{rcpt: rcpt})

      id = enqueue(context, [])

      assert_receive {:telemetry, [:sovite, :queue, :message, :deferred], _, %{queue_id: ^id}},
                     @timeout

      assert QueueManager.flush(manager, {:domain, "other.example"}) == {:ok, 0}
      assert QueueManager.flush(manager, {:subdomains, "net"}) == {:ok, 1}
      assert_receive {:fake_mta, ^mta, {:message, _}}, @timeout
      assert_receive {:telemetry, _, _, %{queue_id: ^id, reason: :delivered}}, @timeout

      assert QueueManager.flush(manager, {:subdomains, "net"}) == {:error, :too_soon}
    end

    test "a message on hold waits for its release", context do
      %{mta: mta, manager: manager} = context = start(context, extensions: @dsn)
      id = enqueue(context, hold: {:for, 2})
      refute_receive {:fake_mta, ^mta, {:message, _}}, 500

      # Not even a flush releases it early.
      :ok = QueueManager.flush(manager)
      refute_receive {:fake_mta, ^mta, {:message, _}}, 500
      assert_receive {:fake_mta, ^mta, {:message, _}}, @timeout
      assert_receive {:telemetry, _, _, %{queue_id: ^id, reason: :delivered}}, @timeout
    end

    test "DELIVERBY with R: returned when the time is up, or when no next hop supports it",
         context do
      context = start(context, extensions: ["PIPELINING", "DELIVERBY"])
      past = DateTime.add(DateTime.utc_now(), -1)
      id = enqueue(context, deliver_by: %{deadline: past, mode: :return, trace: false})
      assert_receive {:telemetry, _, _, %{queue_id: ^id, reason: :bounced}}, @timeout
      assert_receive {:fake_mta, _, {:message, %{mail_from: "", data: dsn}}}, @timeout
      assert dsn =~ "Status: 5.4.7\r\n"

      # BY goes along with the seconds left.
      %{mta: mta} = context
      soon = DateTime.add(DateTime.utc_now(), 600)
      enqueue(context, deliver_by: %{deadline: soon, mode: :return, trace: false}, priority: 4)

      assert_receive {:fake_mta, ^mta, {:message, %{mail_from: "anna@sender.example"} = message}},
                     @timeout

      assert message.mail_args =~ ~r/\AFROM:<anna@sender.example> BY=(599|600);R\z/
    end

    test "DELIVERBY with R needs a next hop that supports it", context do
      context = start(context, extensions: @dsn)
      soon = DateTime.add(DateTime.utc_now(), 600)
      id = enqueue(context, deliver_by: %{deadline: soon, mode: :return, trace: false})

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{queue_id: ^id, status: :failed, reply: reply}},
                     @timeout

      assert reply =~ "DELIVERBY required, but host mx.example.net[127.0.0.1] does not offer it"
    end

    test "DELIVERBY with N to a next hop without it is reported as relayed", context do
      %{mta: mta} = context = start(context, extensions: ["PIPELINING", "MT-PRIORITY"])
      soon = DateTime.add(DateTime.utc_now(), 600)

      id =
        enqueue(context, deliver_by: %{deadline: soon, mode: :notify, trace: false}, priority: -1)

      assert_receive {:fake_mta, ^mta,
                      {:message, %{mail_args: "FROM:<anna@sender.example> MT-PRIORITY=-1"}}},
                     @timeout

      assert_receive {:telemetry, [:sovite, :queue, :notification, :sent], _,
                      %{queue_id: ^id, kind: :success}},
                     @timeout

      assert_receive {:fake_mta, ^mta, {:message, %{mail_from: "", data: dsn}}}, @timeout
      assert dsn =~ "Action: relayed\r\n"
    end

    test "RRVS needs a next hop that supports it, unless C", context do
      context = start(context, extensions: @dsn)
      since = ~U[2014-04-03 23:01:00Z]

      id =
        enqueue(context,
          recipients: ["a@example.net", "b@example.net"],
          rrvs: %{"a@example.net" => {since, :reject}, "b@example.net" => {since, :continue}}
        )

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{queue_id: ^id, recipient: "a@example.net", status: :failed, reply: reply}},
                     @timeout

      assert reply =~ "RRVS required"

      assert_receive {:fake_mta, _,
                      {:message,
                       %{mail_from: "anna@sender.example", rcpt_args: ["TO:<b@example.net>"]}}},
                     @timeout
    end

    test "RRVS goes to a next hop that supports it", context do
      %{mta: mta} = context = start(context, extensions: ["PIPELINING", "RRVS"])
      enqueue(context, rrvs: %{"bob@example.net" => {~U[2014-04-03 23:01:00Z], :reject}})

      assert_receive {:fake_mta, ^mta,
                      {:message,
                       %{rcpt_args: ["TO:<bob@example.net> RRVS=2014-04-03T23:01:00Z;R"]}}},
                     @timeout
    end

    test "jobs run in MT-PRIORITY order", context do
      slow = fn data ->
        if data =~ "Subject: first", do: Process.sleep(500)
        "250 2.0.0 OK"
      end

      context =
        start(context, [extensions: @dsn, responses: %{data_end: slow}], """
        [delivery]
        max_deliveries = 1
        """)

      enqueue(context, [], "Subject: first\r\n\r\nbody\r\n")
      assert_receive {:fake_mta, _, :connected}, @timeout
      enqueue(context, [priority: -5], "Subject: low\r\n\r\nbody\r\n")
      enqueue(context, [], "Subject: normal\r\n\r\nbody\r\n")
      enqueue(context, [priority: 5], "Subject: high\r\n\r\nbody\r\n")

      subjects =
        for _ <- 1..4 do
          assert_receive {:fake_mta, _, {:message, %{data: "Subject: " <> rest}}}, @timeout
          rest |> String.split("\r\n") |> hd()
        end

      assert subjects == ["first", "high", "normal", "low"]
    end
  end
end
