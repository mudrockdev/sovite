defmodule Sovite.Core.QueueManagerTest do
  # End to end: the queue manager delivers spooled messages to a fake
  # remote MTA found through fake DNS.
  use ExUnit.Case, async: true

  alias Sovite.Abuse.{Cache, RateLimit}
  alias Sovite.Core.{Config, Outbound, QueueManager}
  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.Test.{FakeDNS, FakeMTA, TelemetryForwarder}

  @moduletag :tmp_dir
  @moduletag :capture_log

  @body "From: alice@sender.example\r\nSubject: hello\r\n\r\n.dot line\r\nbody\r\n"
  @timeout 5_000

  @dns %{
    {"example.net", :mx} => [{10, "mx.example.net"}],
    {"other.example", :mx} => [{10, "mx.example.net"}],
    {"sender.example", :mx} => [{10, "mx.example.net"}],
    {"admin.example", :mx} => [{10, "mx.example.net"}],
    {"mx.example.net", :a} => [{127, 0, 0, 1}]
  }

  setup %{tmp_dir: dir} do
    TelemetryForwarder.attach([
      [:sovite, :queue, :message, :removed],
      [:sovite, :queue, :message, :deferred],
      [:sovite, :queue, :message, :corrupt],
      [:sovite, :queue, :notification, :sent],
      [:sovite, :queue, :notification, :discarded],
      [:sovite, :smtp, :client, :delivery, :stop]
    ])

    :ok = Spool.init(dir)
    %{dir: dir}
  end

  defp start_mta(context, opts \\ []) do
    mta = start_supervised!({FakeMTA, Keyword.put(opts, :owner, self())}, id: make_ref())
    Map.put(context, :mta, mta)
  end

  defp start_manager(context, opts \\ []) do
    {:ok, config} =
      Config.parse("""
      [server]
      hostname = "mx.example.org"
      [queue]
      directory = "#{context.dir}"
      min_backoff = "50ms"
      max_backoff = "100ms"
      #{opts[:queue]}
      #{opts[:toml]}
      """)

    manager_opts =
      QueueManager.opts(config) ++
        [
          name: nil,
          resolver: FakeDNS.resolver(Map.merge(@dns, opts[:dns] || %{})),
          port: FakeMTA.port(context.mta),
          client: [command_timeout: 2_000, data_end_timeout: 2_000]
        ] ++ Keyword.get(opts, :manager, [])

    manager = start_supervised!({QueueManager, manager_opts})
    Map.put(context, :manager, manager)
  end

  # Writes a message into the spool. Without a manager it stays in
  # `incoming/` (or is moved to `queue`) until one starts.
  defp spool(context, sender, recipients, fields \\ [], queue \\ :incoming) do
    envelope =
      struct!(
        Envelope,
        [
          queue_id: ID.generate(),
          sender: sender,
          recipients: recipients,
          received_at: DateTime.utc_now()
        ] ++ fields
      )

    {:ok, writer} = Spool.open(context.dir, envelope)
    {:ok, writer} = Spool.write(writer, @body)
    {:ok, _path, _size} = Spool.commit(writer)
    if queue != :incoming, do: :ok = Spool.move(context.dir, envelope.queue_id, :incoming, queue)
    envelope.queue_id
  end

  defp enqueue(context, sender, recipients, fields \\ []) do
    id = spool(context, sender, recipients, fields)
    QueueManager.notify(context.manager, id)
    id
  end

  defp assert_removed(id, reason) do
    assert_receive {:telemetry, [:sovite, :queue, :message, :removed], _,
                    %{queue_id: ^id, reason: ^reason}},
                   @timeout
  end

  defp assert_message(mta) do
    assert_receive {:fake_mta, ^mta, {:message, message}}, @timeout
    message
  end

  defp queue_empty?(dir) do
    Enum.all?(Spool.queues(), fn queue -> Spool.list(dir, queue) == {:ok, []} end)
  end

  describe "delivery" do
    setup context do
      context |> start_mta() |> start_manager()
    end

    test "delivers a message and removes it from the queue", %{mta: mta, dir: dir} = context do
      id = enqueue(context, "alice@sender.example", ["bob@example.net"])

      message = assert_message(mta)
      assert message.mail_from == "alice@sender.example"
      assert message.rcpt_to == ["bob@example.net"]
      assert message.data == @body
      assert message.helo == "mx.example.org"

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], %{duration: _},
                      %{queue_id: ^id, recipient: "bob@example.net", status: :delivered} = meta},
                     @timeout

      assert meta.relay == "mx.example.net[127.0.0.1]"
      assert meta.reply =~ "250"
      assert_removed(id, :delivered)
      assert queue_empty?(dir)
    end

    test "sends one transaction per destination", %{mta: mta} = context do
      id =
        enqueue(context, "alice@sender.example", [
          "b@example.net",
          "c@other.example",
          "d@example.net"
        ])

      assert_removed(id, :delivered)

      messages = [assert_message(mta), assert_message(mta)]

      assert messages |> Enum.map(& &1.rcpt_to) |> Enum.sort() ==
               [["b@example.net", "d@example.net"], ["c@other.example"]]
    end

    test "forwards mail to other domains with its SRS sender", %{mta: mta} = context do
      srs = "SRS0=abcd=AB=sender.example=alice@mx.example.org"

      id =
        enqueue(context, "alice@sender.example", ["bob@example.net", "carol@other.example"],
          srs_sender: srs
        )

      messages = [assert_message(mta), assert_message(mta)]
      assert Enum.all?(messages, &(&1.mail_from == srs))
      assert_removed(id, :delivered)
    end

    test "delivers to address literals", %{mta: mta} = context do
      id = enqueue(context, "alice@sender.example", ["bob@[127.0.0.1]"])
      assert_removed(id, :delivered)
      assert %{rcpt_to: ["bob@[127.0.0.1]"]} = assert_message(mta)
    end

    test "defers local recipients without maildir.local", context do
      id = enqueue(context, "alice@sender.example", ["postmaster@mx.example.org"])

      assert_receive {:telemetry, [:sovite, :queue, :message, :deferred], %{attempts: 1},
                      %{queue_id: ^id}},
                     @timeout

      {:ok, loaded} = Spool.load(Spool.path(context.dir, :deferred, id))

      assert [{:recipient, _, :deferred, %{status: "4.3.5", reply: reply}} | _] =
               loaded.records

      assert reply =~ "maildir.local"
    end
  end

  describe "failures" do
    test "bounces rejected recipients and delivers the rest", context do
      rcpt = fn
        "unknown@example.net" -> "550 5.1.1 <unknown@example.net>: User unknown"
        _ -> "250 2.1.5 OK"
      end

      %{mta: mta} = context = context |> start_mta(responses: %{rcpt: rcpt}) |> start_manager()
      id = enqueue(context, "alice@sender.example", ["unknown@example.net", "bob@example.net"])

      assert %{rcpt_to: ["bob@example.net"]} = assert_message(mta)
      assert_removed(id, :bounced)

      assert_receive {:telemetry, [:sovite, :queue, :notification, :sent], %{recipients: 1},
                      %{
                        queue_id: ^id,
                        kind: :failure,
                        to: "alice@sender.example",
                        notification_id: dsn_id
                      }},
                     @timeout

      dsn = assert_message(mta)
      assert dsn.mail_from == ""
      assert dsn.rcpt_to == ["alice@sender.example"]
      assert dsn.data =~ "Subject: Undelivered Mail Returned to Sender\r\n"
      assert dsn.data =~ "Final-Recipient: rfc822; unknown@example.net\r\n"
      assert dsn.data =~ "Status: 5.1.1\r\n"
      assert dsn.data =~ "Remote-MTA: dns; mx.example.net\r\n"

      assert dsn.data =~
               "Diagnostic-Code: smtp; 550 5.1.1 <unknown@example.net>: User unknown\r\n"

      assert dsn.data =~ "X-Sovite-Queue-ID: #{id}\r\n"
      assert dsn.data =~ "\r\n\r\nFrom: alice@sender.example\r\nSubject: hello\r\n"
      refute dsn.data =~ "bob@example.net"
      refute dsn.data =~ "dot line"

      assert_removed(dsn_id, :delivered)
      assert queue_empty?(context.dir)
    end

    test "counts failures against the user who sent the message", context do
      TelemetryForwarder.attach([[:sovite, :outbound, :suspended]])
      rcpt = fn _ -> "550 5.1.1 User unknown" end
      unique = System.unique_integer([:positive])
      rate_limit = :"#{__MODULE__}.rate_limit#{unique}"
      cache = :"#{__MODULE__}.cache#{unique}"
      start_supervised!({RateLimit, name: rate_limit})
      start_supervised!({Cache, name: cache})

      {:ok, config} = Config.parse("[outbound]\nmin_failures = 2")
      outbound = Outbound.opts(config, rate_limit, cache)

      context =
        context
        |> start_mta(responses: %{rcpt: rcpt})
        |> start_manager(manager: [outbound: outbound])

      id =
        enqueue(context, "alice@sender.example", ["a@example.net", "b@example.net"],
          auth_user: "Alice"
        )

      assert_removed(id, :bounced)

      assert_receive {:telemetry, [:sovite, :outbound, :suspended], %{failed: 2, sent: 0},
                      %{user: "alice"}},
                     @timeout

      assert Outbound.suspended?(outbound, "alice")
    end

    test "retries temporary failures with backoff", context do
      {:ok, attempts} = Agent.start_link(fn -> 0 end)

      rcpt = fn _ ->
        if Agent.get_and_update(attempts, &{&1, &1 + 1}) < 2,
          do: "451 4.7.1 Greylisted, try again",
          else: "250 2.1.5 OK"
      end

      %{mta: mta} = context = context |> start_mta(responses: %{rcpt: rcpt}) |> start_manager()
      id = enqueue(context, "alice@sender.example", ["bob@example.net"])

      assert_receive {:telemetry, [:sovite, :queue, :message, :deferred], %{attempts: 1},
                      %{queue_id: ^id}},
                     @timeout

      assert_receive {:telemetry, [:sovite, :queue, :message, :deferred], %{attempts: 2},
                      %{queue_id: ^id}},
                     @timeout

      assert_removed(id, :delivered)
      assert %{rcpt_to: ["bob@example.net"]} = assert_message(mta)
      refute_received {:telemetry, [:sovite, :queue, :notification, :sent], _, %{queue_id: ^id}}
    end

    test "bounces what is still deferred after the maximum lifetime", context do
      rcpt = fn
        "alice@sender.example" -> "250 2.1.5 OK"
        _ -> "452 4.2.2 Mailbox full"
      end

      context = context |> start_mta(responses: %{rcpt: rcpt}) |> start_manager()
      old = DateTime.add(DateTime.utc_now(), -6, :day)
      id = enqueue(context, "alice@sender.example", ["bob@example.net"], received_at: old)

      assert_removed(id, :expired)
      dsn = assert_message(context.mta)
      assert dsn.rcpt_to == ["alice@sender.example"]
      assert dsn.data =~ "Status: 5.2.2\r\n"
      assert dsn.data =~ "Diagnostic-Code: smtp; 452 4.2.2 Mailbox full\r\n"
    end

    test "bounces domains with a Null MX or that do not exist", context do
      dns = %{{"nullmx.example", :mx} => [{0, ""}]}
      context = context |> start_mta() |> start_manager(dns: dns)
      id = enqueue(context, "alice@sender.example", ["a@nullmx.example", "b@missing.example"])

      assert_removed(id, :bounced)
      dsn = assert_message(context.mta)

      assert dsn.data =~
               "Final-Recipient: rfc822; a@nullmx.example\r\nAction: failed\r\nStatus: 5.1.10\r\n"

      assert dsn.data =~
               "Final-Recipient: rfc822; b@missing.example\r\nAction: failed\r\nStatus: 5.1.2\r\n"

      assert dsn.data =~ "<b@missing.example>: Host or domain name not found: missing.example\r\n"
    end

    test "defers on DNS errors", context do
      dns = %{{"broken.example", :mx} => {:error, :servfail}}
      context = context |> start_mta() |> start_manager(dns: dns)
      id = enqueue(context, "alice@sender.example", ["a@broken.example"])

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{queue_id: ^id, status: :deferred, reply: reply}},
                     @timeout

      assert reply =~ "lookup failed for broken.example: servfail"

      assert_receive {:telemetry, [:sovite, :queue, :message, :deferred], _, %{queue_id: ^id}},
                     @timeout
    end

    test "bounces a message larger than the remote SIZE limit", context do
      context = context |> start_mta(extensions: ["PIPELINING", "SIZE 10"]) |> start_manager()
      id = enqueue(context, "alice@sender.example", ["bob@example.net"])

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{queue_id: ^id, status: :failed, reply: reply}},
                     @timeout

      assert reply =~ "exceeds the limit of 10 bytes"
      assert_removed(id, :bounced)
    end

    test "detects mail that loops back to this server", context do
      context = context |> start_mta(hostname: "MX.example.org") |> start_manager()
      id = enqueue(context, "", ["bob@example.net"])

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{
                        queue_id: ^id,
                        status: :failed,
                        reply: "mail for example.net loops back to myself"
                      }},
                     @timeout

      assert_removed(id, :bounced)
    end

    test "never sends this server's own MX hosts mail they are best for", context do
      dns = %{{"self.example", :mx} => [{10, "mx.example.org"}, {20, "mx.example.net"}]}
      context = context |> start_mta() |> start_manager(dns: dns)
      id = enqueue(context, "", ["a@self.example"])

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{
                        queue_id: ^id,
                        status: :failed,
                        reply: "mail for self.example loops back to myself"
                      }},
                     @timeout
    end
  end

  describe "null sender" do
    test "never bounces a failed notification back", context do
      context = context |> start_mta(responses: %{rcpt: "550 5.1.1 no"}) |> start_manager()
      id = enqueue(context, "", ["bob@example.net"])

      assert_receive {:telemetry, [:sovite, :queue, :notification, :discarded], %{recipients: 1},
                      %{queue_id: ^id, kind: :failure}},
                     @timeout

      assert_removed(id, :bounced)
      refute_received {:telemetry, [:sovite, :queue, :notification, :sent], _, %{queue_id: ^id}}
    end

    test "reports double bounces to the configured address, once", context do
      rcpt = fn
        "postmaster@admin.example" -> "550 5.1.1 not even the postmaster"
        _ -> "550 5.1.1 no"
      end

      context =
        context
        |> start_mta(responses: %{rcpt: rcpt})
        |> start_manager(toml: ~s([bounce]\ndouble_bounce_recipient = "postmaster@admin.example"))

      id = enqueue(context, "", ["bob@example.net"])

      assert_receive {:telemetry, [:sovite, :queue, :notification, :sent], _,
                      %{
                        queue_id: ^id,
                        kind: :double_bounce,
                        to: "postmaster@admin.example",
                        notification_id: report
                      }},
                     @timeout

      # The report fails too, and is only logged.
      assert_receive {:telemetry, [:sovite, :queue, :notification, :discarded], _,
                      %{queue_id: ^report, kind: :failure}},
                     @timeout

      assert_removed(report, :bounced)

      refute_received {:telemetry, [:sovite, :queue, :notification, :sent], _,
                       %{queue_id: ^report}}
    end
  end

  test "sends one delay warning for a deferred message", context do
    context =
      context
      |> start_mta(
        responses: %{
          rcpt: fn
            "alice@sender.example" -> "250 2.1.5 OK"
            _ -> "451 4.3.0 later"
          end
        }
      )
      |> start_manager(queue: ~s(delay_warning = "1ms"))

    id = enqueue(context, "alice@sender.example", ["bob@example.net"])

    assert_receive {:telemetry, [:sovite, :queue, :notification, :sent], _,
                    %{queue_id: ^id, kind: :delay, notification_id: _}},
                   @timeout

    warning = assert_message(context.mta)
    assert warning.mail_from == ""
    assert warning.data =~ "Subject: Delayed Mail (still being retried)\r\n"
    assert warning.data =~ "Action: delayed\r\nStatus: 4.3.0\r\n"
    assert warning.data =~ "Will-Retry-Until: "

    assert_receive {:telemetry, [:sovite, :queue, :message, :deferred], %{attempts: 3},
                    %{queue_id: ^id}},
                   @timeout

    refute_received {:telemetry, [:sovite, :queue, :notification, :sent], _,
                     %{queue_id: ^id, kind: :delay}}
  end

  describe "hosts and addresses" do
    test "falls back from IPv6 to IPv4", context do
      dns = %{{"mx.example.net", :aaaa} => [{0, 0, 0, 0, 0, 0, 0, 1}]}
      context = context |> start_mta() |> start_manager(dns: dns)
      id = enqueue(context, "alice@sender.example", ["bob@example.net"])

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{queue_id: ^id, status: :delivered, relay: "mx.example.net[127.0.0.1]"}},
                     @timeout
    end

    test "uses only the configured IP versions", context do
      dns = %{
        {"mx.example.net", :a} => [],
        {"mx.example.net", :aaaa} => [{0, 0, 0, 0, 0, 0, 0, 1}]
      }

      context =
        context
        |> start_mta()
        |> start_manager(dns: dns, toml: ~s([delivery]\nip_versions = ["ipv4"]))

      id = enqueue(context, "alice@sender.example", ["bob@example.net"])

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{
                        queue_id: ^id,
                        status: :failed,
                        reply: "no mail host for example.net has an address"
                      }},
                     @timeout
    end

    test "tries the next MX host when one is down", context do
      dns = %{
        {"example.net", :mx} => [{10, "down.example.net"}, {20, "mx.example.net"}],
        {"down.example.net", :a} => [{127, 0, 0, 2}]
      }

      context = context |> start_mta() |> start_manager(dns: dns)
      id = enqueue(context, "alice@sender.example", ["bob@example.net"])

      assert_removed(id, :delivered)
      assert %{rcpt_to: ["bob@example.net"]} = assert_message(context.mta)
    end

    test "defers when no host can be reached", context do
      dns = %{{"mx.example.net", :a} => [{127, 0, 0, 2}]}
      context = context |> start_mta() |> start_manager(dns: dns)
      id = enqueue(context, "alice@sender.example", ["bob@example.net"])

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{queue_id: ^id, status: :deferred, reply: reply}},
                     @timeout

      assert reply =~ "connect to mx.example.net[127.0.0.2]"
    end

    test "sends everything to the relay host", context do
      context = start_mta(context)
      port = FakeMTA.port(context.mta)

      context =
        start_manager(context, dns: %{}, toml: ~s([delivery]\nrelayhost = "[127.0.0.1]:#{port}"))

      id = enqueue(context, "alice@sender.example", ["a@example.net", "b@anywhere.example"])
      assert_removed(id, :delivered)

      assert %{rcpt_to: ["a@example.net", "b@anywhere.example"]} = assert_message(context.mta)
    end
  end

  describe "delivery errors" do
    test "defers when the connection drops after the final dot", context do
      context = context |> start_mta(responses: %{data_end: :close}) |> start_manager()
      id = enqueue(context, "alice@sender.example", ["bob@example.net"])

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{queue_id: ^id, status: :deferred, reply: reply}},
                     @timeout

      assert reply =~ "lost connection with mx.example.net[127.0.0.1] while sending end of data"
      assert reply =~ "may be delivered more than once"
    end

    test "defers when every host rejects the greeting", context do
      context =
        context |> start_mta(responses: %{greeting: "554 5.7.1 go away"}) |> start_manager()

      id = enqueue(context, "alice@sender.example", ["bob@example.net"])

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{queue_id: ^id, status: :deferred, reply: reply}},
                     @timeout

      assert reply == "host mx.example.net[127.0.0.1] refused to talk to me: 554 5.7.1 go away"
    end

    test "bounces an 8-bit message to a server without 8BITMIME", context do
      context = context |> start_mta(extensions: ["PIPELINING"]) |> start_manager()
      id = enqueue(context, "", ["bob@example.net"], body_type: :"8bitmime")

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{queue_id: ^id, status: :failed, reply: reply}},
                     @timeout

      assert reply =~ "does not support 8BITMIME"
    end

    test "reconnects when a cached connection was closed", context do
      {:ok, calls} = Agent.start_link(fn -> 0 end)

      # The second MAIL, the first on the reused connection, finds it closed.
      mail = fn _ ->
        if Agent.get_and_update(calls, &{&1, &1 + 1}) == 1, do: :close, else: "250 2.1.0 OK"
      end

      context = start_mta(context, responses: %{mail: mail})
      ids = for _ <- 1..2, do: spool(context, "alice@sender.example", ["bob@example.net"])
      start_manager(context, toml: "[delivery]\nmax_deliveries = 1\ndestination_concurrency = 1")

      for id <- ids, do: assert_removed(id, :delivered)
      assert_message(context.mta)
      assert_message(context.mta)
    end
  end

  describe "content filter" do
    test "sends every recipient to the filter at once, with XFORWARD", context do
      context =
        start_mta(context,
          extensions: [
            "PIPELINING",
            "8BITMIME",
            "XFORWARD NAME ADDR PORT PROTO HELO IDENT SOURCE"
          ]
        )

      port = FakeMTA.port(context.mta)
      context = start_manager(context)

      id =
        enqueue(context, "alice@sender.example", ["bob@example.net", "carol@other.example"],
          content_filter: "smtp:[127.0.0.1]:#{port}",
          srs_sender: "SRS0=x=y=sender.example=alice@mx.example.org",
          remote_ip: {192, 0, 2, 7},
          helo: "client.example",
          protocol: "ESMTPS",
          requiretls: true
        )

      message = assert_message(context.mta)
      assert message.mail_from == "alice@sender.example"
      assert message.rcpt_to == ["bob@example.net", "carol@other.example"]
      assert message.data == @body

      assert message.xforward == [
               "ADDR=192.0.2.7 PROTO=ESMTP HELO=client.example IDENT=#{id} SOURCE=REMOTE"
             ]

      assert_removed(id, :delivered)
    end

    test "an LMTP filter and an unusable one", context do
      socket = Path.join(System.tmp_dir!(), "sovite-filter-#{System.unique_integer([:positive])}")
      on_exit(fn -> File.rm(socket) end)
      lmtp = start_supervised!({FakeMTA, owner: self(), lmtp: true, unix: socket}, id: :lmtp)
      context = context |> start_mta() |> start_manager()

      id = enqueue(context, "", ["bob@example.net"], content_filter: "lmtp:unix:#{socket}")
      assert_receive {:fake_mta, ^lmtp, {:message, %{rcpt_to: ["bob@example.net"]}}}, @timeout
      assert_removed(id, :delivered)

      id = enqueue(context, "a@sender.example", ["bob@example.net"], content_filter: "local")

      assert_receive {:telemetry, [:sovite, :queue, :message, :deferred], _, %{queue_id: ^id}},
                     @timeout
    end
  end

  describe "relay host" do
    test "looks up the MX hosts of a relay host without brackets", context do
      context = start_mta(context)
      port = FakeMTA.port(context.mta)
      dns = %{{"relay.example", :mx} => [{10, "mx.example.net"}]}

      context =
        start_manager(context,
          dns: dns,
          toml: ~s([delivery]\nrelayhost = "relay.example:#{port}")
        )

      id = enqueue(context, "alice@sender.example", ["a@anywhere.example"])
      assert_removed(id, :delivered)
    end

    test "keeps mail when the relay host cannot be found", context do
      dns = %{{"norelay.example", :txt} => ["x"]}

      context =
        context
        |> start_mta()
        |> start_manager(
          dns: dns,
          toml: ~s([delivery]\nrelayhost = "missing.example"\n)
        )

      id = enqueue(context, "alice@sender.example", ["a@anywhere.example"])

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{queue_id: ^id, status: :deferred, reply: reply}},
                     @timeout

      assert reply == "relay host missing.example: Host or domain name not found: missing.example"
    end

    test "keeps mail when a bracketed relay host has no address", context do
      dns = %{{"smtp.isp.example", :txt} => ["x"]}

      context =
        context
        |> start_mta()
        |> start_manager(dns: dns, toml: ~s([delivery]\nrelayhost = "[smtp.isp.example]"))

      id = enqueue(context, "alice@sender.example", ["a@anywhere.example"])

      assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                      %{
                        queue_id: ^id,
                        status: :deferred,
                        reply: "relay host smtp.isp.example has no address"
                      }},
                     @timeout
    end
  end

  describe "limits" do
    test "splits large recipient lists", context do
      context = context |> start_mta() |> start_manager(toml: "[delivery]\nmax_recipients = 2")

      id =
        enqueue(context, "alice@sender.example", [
          "a@example.net",
          "b@example.net",
          "c@example.net"
        ])

      assert_removed(id, :delivered)
      batches = [assert_message(context.mta).rcpt_to, assert_message(context.mta).rcpt_to]
      assert Enum.sort(batches) == [["a@example.net", "b@example.net"], ["c@example.net"]]
    end

    test "reuses a connection for messages to the same destination", context do
      context = start_mta(context)
      ids = for _ <- 1..3, do: spool(context, "alice@sender.example", ["bob@example.net"])

      context
      |> start_manager(toml: "[delivery]\nmax_deliveries = 1\ndestination_concurrency = 1")

      for id <- ids, do: assert_removed(id, :delivered)
      mta = context.mta
      assert_received {:fake_mta, ^mta, :connected}
      refute_received {:fake_mta, ^mta, :connected}
    end

    test "waits destination_rate_delay between deliveries to a destination", context do
      context = start_mta(context)
      ids = for _ <- 1..2, do: spool(context, "alice@sender.example", ["bob@example.net"])
      started = System.monotonic_time(:millisecond)
      start_manager(context, toml: ~s([delivery]\ndestination_rate_delay = "300ms"))

      for id <- ids, do: assert_removed(id, :delivered)
      assert System.monotonic_time(:millisecond) - started >= 300
    end
  end

  describe "recovery" do
    test "delivers messages left in active/ by a crash, skipping finished recipients", context do
      context = start_mta(context)

      id =
        spool(
          context,
          "alice@sender.example",
          ["done@example.net", "todo@example.net"],
          [],
          :active
        )

      path = Spool.path(context.dir, :active, id)
      {:ok, loaded} = Spool.load(path)

      details = %{
        status: "2.0.0",
        reply: "250 ok",
        remote: "mx",
        smtp: true,
        at: DateTime.utc_now()
      }

      {:ok, _} =
        Spool.append(path, loaded.end_offset, [
          {:recipient, "done@example.net", :delivered, details}
        ])

      start_manager(context)
      assert_removed(id, :delivered)
      assert %{rcpt_to: ["todo@example.net"]} = assert_message(context.mta)
    end

    test "keeps the retry time of deferred messages across restarts", context do
      context = start_mta(context)
      due = spool(context, "alice@sender.example", ["due@example.net"], [], :deferred)
      later = spool(context, "alice@sender.example", ["later@example.net"], [], :deferred)
      held = spool(context, "alice@sender.example", ["held@example.net"], [], :hold)

      path = Spool.path(context.dir, :deferred, later)
      {:ok, loaded} = Spool.load(path)
      next = DateTime.add(DateTime.utc_now(), 1, :hour)
      {:ok, _} = Spool.append(path, loaded.end_offset, [{:retry, 1, next}])

      context = start_manager(context)
      assert_removed(due, :delivered)
      assert %{rcpt_to: ["due@example.net"]} = assert_message(context.mta)
      assert %{active: 0, deferred: 1} = QueueManager.stats(context.manager)

      assert QueueManager.flush(context.manager) == :ok
      assert_removed(later, :delivered)
      assert Spool.list(context.dir, :hold) == {:ok, [held]}
    end

    test "moves unreadable files to corrupt/", context do
      context = start_mta(context)
      id = ID.generate()
      File.write!(Path.join([context.dir, "incoming", id]), "garbage")

      start_manager(context)

      assert_receive {:telemetry, [:sovite, :queue, :message, :corrupt], _,
                      %{queue_id: ^id, reason: :invalid_header}},
                     @timeout

      assert Spool.list(context.dir, :corrupt) == {:ok, [id]}
    end

    test "loses no mail when killed during a delivery", context do
      test = self()

      data_end = fn _data ->
        send(test, :sending)
        Process.sleep(300)
        "250 2.0.0 OK"
      end

      context = context |> start_mta(responses: %{data_end: data_end}) |> start_manager()
      id = enqueue(context, "alice@sender.example", ["bob@example.net"])

      assert_receive :sending, @timeout
      assert Spool.list(context.dir, :active) == {:ok, [id]}
      Process.exit(context.manager, :kill)

      # The supervisor restarts the manager, which finds the message in
      # active/ and delivers it again.
      assert_removed(id, :delivered)
      assert %{rcpt_to: ["bob@example.net"]} = assert_message(context.mta)
      assert queue_empty?(context.dir)
    end
  end
end
