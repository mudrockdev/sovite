defmodule Sovite.Core.EcosystemTest do
  # Milters, policy servers, XCLIENT/XFORWARD, and content filters, end
  # to end over TCP.
  use ExUnit.Case, async: true

  alias Sovite.Core.{Config, SMTPHandler}
  alias Sovite.Queue.Spool
  alias Sovite.Test.{FakeDNS, FakeMilter, SMTPClient}

  @moduletag :tmp_dir
  @moduletag :capture_log

  @body "From: alice@remote.test\r\nSubject: hello\r\n\r\nbody\r\n"

  defmodule Policy do
    @moduledoc false
    # A policy server: sends every request to the test, and answers by
    # recipient local part.
    @behaviour Sovite.Policy.Handler

    @impl true
    def init(_connection, test), do: {:ok, test}

    @impl true
    def handle_request(attributes, test) do
      send(test, {:policy, attributes})

      action =
        case attributes["recipient"] do
          "greylist@" <> _ -> "DEFER_IF_PERMIT Greylisted, see https://postgrey.example"
          "spam@" <> _ -> "REJECT no spam"
          "redirect@" <> _ -> "REDIRECT bob@example.com"
          "bcc@" <> _ -> "BCC archive@example.com"
          "filter@" <> _ -> "FILTER smtp:[127.0.0.1]:10024"
          "hold@" <> _ -> "HOLD"
          "" <> _ -> "PREPEND X-Policy: checked"
          nil -> "DUNNO"
        end

      {action, test}
    end
  end

  defp start_mta(context, toml, opts \\ []) do
    queue = Path.join(context.tmp_dir, "queue")
    :ok = Spool.init(queue)

    {:ok, config} =
      Config.parse("""
      [server]
      hostname = "mx.example.com"
      [queue]
      directory = "#{queue}"
      [domains]
      local = ["example.com"]
      local_recipients = ["bob@example.com", "carol@example.com", "archive@example.com",
        "greylist@example.com", "spam@example.com", "redirect@example.com", "bcc@example.com",
        "filter@example.com", "hold@example.com"]
      #{toml}
      """)

    handler =
      SMTPHandler.opts(
        config,
        nil,
        [
          resolver: FakeDNS.resolver(%{}),
          milters: Enum.map(config.milter, & &1.name)
        ] ++ Keyword.get(opts, :runtime, [])
      )

    server =
      start_supervised!(
        {Sovite.SMTP.Server,
         [
           ip: {127, 0, 0, 1},
           port: 0,
           hostname: config.server.hostname,
           handler: {SMTPHandler, handler},
           xclient_networks: config.smtp.xclient_networks,
           xforward_networks: config.smtp.xforward_networks
         ]},
        id: make_ref()
      )

    {:ok, {_ip, port}} = Sovite.Listener.sockname(server)
    %{port: port, queue: queue}
  end

  defp connect(mta) do
    {:ok, client} = SMTPClient.connect(mta.port)
    on_exit(fn -> SMTPClient.close(client) end)
    client
  end

  defp command(client, line) do
    {:ok, {code, lines}} = SMTPClient.command(client, line)
    {code, List.last(lines)}
  end

  defp send_message(mta, sender, recipients, body \\ @body) do
    client = connect(mta)
    {SMTPClient.send_message(client, sender, recipients, body), client}
  end

  defp queued(mta, queue \\ :incoming) do
    {:ok, ids} = Spool.list(mta.queue, queue)

    for id <- ids do
      path = Spool.path(mta.queue, queue, id)
      {:ok, loaded} = Spool.load(path)

      stream =
        Spool.stream_message(path, loaded.message_offset, loaded.message_size, loaded.prefix)

      {loaded.envelope, Enum.join(stream)}
    end
  end

  defp milter_toml(fake, extra \\ "") do
    {:inet, ip, port} = FakeMilter.address(fake)

    """
    [[milter]]
    name = "fake"
    address = "inet:#{:inet.ntoa(ip)}:#{port}"
    #{extra}
    """
  end

  defp closed_port do
    {:ok, listen} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(listen)
    :gen_tcp.close(listen)
    port
  end

  describe "milters" do
    test "see every step, with Postfix's macros, and change the message", context do
      modifications = [
        {:insert_header, 0, "DKIM-Signature", "v=1; d=example.com"},
        {:add_header, "X-Spam", "no"},
        {:change_header, 1, "Subject", "[checked] hello"}
      ]

      fake = start_supervised!({FakeMilter, owner: self(), modifications: modifications})
      mta = start_mta(context, milter_toml(fake))

      assert {{:ok, {250, ["2.0.0 Ok: queued as " <> id]}}, _} =
               send_message(mta, "alice@remote.test", ["bob@example.com"])

      assert_received {:milter, :connect, {"unknown", :inet, _port, "127.0.0.1"}}
      assert_received {:milter, :macro, {:connect, macros}}
      assert {"j", "mx.example.com"} in macros and {"{client_addr}", "127.0.0.1"} in macros
      assert_received {:milter, :helo, "client.test"}
      assert_received {:milter, :macro, {:mail, macros}}
      assert {"i", id} in macros and {"{mail_addr}", "alice@remote.test"} in macros
      assert_received {:milter, :mail, ["<alice@remote.test>"]}
      assert_received {:milter, :rcpt, ["<bob@example.com>"]}
      assert_received {:milter, :header, {"Received", _}}
      assert_received {:milter, :header, {"From", "alice@remote.test"}}
      assert_received {:milter, :header, {"Subject", "hello"}}
      assert_received {:milter, :body, "body\r\n"}
      assert_received {:milter, :end_of_message, nil}

      assert [{envelope, message}] = queued(mta)
      assert envelope.queue_id == id
      # Inserted at the top, above the Received field; the
      # Authentication-Results prefix goes above everything.
      assert message =~ ~r/\r\nDKIM-Signature: v=1; d=example.com\r\nReceived: from client.test/

      assert message =~
               ~r/\r\nFrom: alice@remote.test\r\nSubject: \[checked\] hello\r\nX-Spam: no\r\n\r\nbody\r\n\z/
    end

    test "refuse senders, recipients, and messages", context do
      replies = %{
        mail: fn ["<" <> sender | _] ->
          if sender == "spam@remote.test>", do: :reject, else: :continue
        end,
        rcpt: fn ["<" <> rcpt | _] ->
          if rcpt == "carol@example.com>",
            do: {:reply_code, "550 5.1.1 No such user here"},
            else: :continue
        end,
        end_of_message: fn _data, session ->
          if session.body =~ "virus", do: :tempfail, else: :default
        end
      }

      fake = start_supervised!({FakeMilter, owner: self(), replies: replies})
      mta = start_mta(context, milter_toml(fake))
      client = connect(mta)
      {:ok, {220, _}} = SMTPClient.read_reply(client)
      {250, _} = command(client, "EHLO client.test")
      assert {550, "5.7.1 Command rejected"} = command(client, "MAIL FROM:<spam@remote.test>")
      {250, _} = command(client, "MAIL FROM:<alice@remote.test>")
      assert {550, "5.1.1 No such user here"} = command(client, "RCPT TO:<carol@example.com>")
      {250, _} = command(client, "RCPT TO:<bob@example.com>")
      {354, _} = command(client, "DATA")

      assert {:ok, {451, ["4.7.1 Service unavailable - try again later"]}} =
               SMTPClient.send_data(client, "Subject: x\r\n\r\nvirus\r\n")

      assert queued(mta) == []
      assert_received {:milter, :abort, nil}
    end

    test "discard, quarantine, and envelope and body changes", context do
      replies = %{
        end_of_message: fn _data, session ->
          case session.mail do
            ["<discard@remote.test>" | _] ->
              :discard

            ["<quarantine@remote.test>" | _] ->
              [{:quarantine, "suspicious"}, :accept]

            ["<nobody@remote.test>" | _] ->
              [{:delete_recipient, "<bob@example.com>"}, :accept]

            _ ->
              [
                {:add_recipient, "<carol@example.com>"},
                {:delete_recipient, "<bob@example.com>"},
                {:change_sender, "<bounces@remote.test>", nil},
                {:replace_body, "new body\r\n"},
                :accept
              ]
          end
        end
      }

      fake = start_supervised!({FakeMilter, owner: self(), replies: replies})
      mta = start_mta(context, milter_toml(fake))

      assert {{:ok, {250, ["2.0.0 Ok: discarded as " <> _]}}, _} =
               send_message(mta, "discard@remote.test", ["bob@example.com"])

      assert queued(mta) == []

      assert {{:ok, {250, ["2.0.0 Ok: discarded as " <> _]}}, _} =
               send_message(mta, "nobody@remote.test", ["bob@example.com"])

      assert queued(mta) == []

      assert {{:ok, {250, _}}, _} =
               send_message(mta, "quarantine@remote.test", ["bob@example.com"])

      assert [{%{sender: "quarantine@remote.test"}, _}] = queued(mta, :hold)

      assert {{:ok, {250, _}}, _} = send_message(mta, "alice@remote.test", ["bob@example.com"])
      assert [{envelope, message}] = queued(mta)
      assert envelope.recipients == ["carol@example.com"]
      assert envelope.sender == "bounces@remote.test"
      assert String.ends_with?(message, "Subject: hello\r\n\r\nnew body\r\n")
      assert message =~ "Received: from client.test"
    end

    test "an unreachable milter fails safe, unless told to accept", context do
      port = closed_port()
      toml = "[[milter]]\naddress = \"inet:127.0.0.1:#{port}\"\nconnect_timeout = \"1s\"\n"
      mta = start_mta(context, toml)
      client = connect(mta)

      assert {:ok, {421, ["4.7.1 Service unavailable - try again later"]}} =
               SMTPClient.read_reply(client)

      context = %{context | tmp_dir: Path.join(context.tmp_dir, "accept")}
      mta = start_mta(context, toml <> "default_action = \"accept\"\n")
      assert {{:ok, {250, _}}, _} = send_message(mta, "alice@remote.test", ["bob@example.com"])
    end

    test "a milter that stops answering mid-session", context do
      fake = start_supervised!({FakeMilter, owner: self(), replies: %{rcpt: {:delay, 2_000}}})
      mta = start_mta(context, milter_toml(fake, ~s(command_timeout = "200ms")))
      client = connect(mta)
      {:ok, {220, _}} = SMTPClient.read_reply(client)
      {250, _} = command(client, "EHLO client.test")
      {250, _} = command(client, "MAIL FROM:<alice@remote.test>")
      assert {451, "4.7.1 " <> _} = command(client, "RCPT TO:<bob@example.com>")
      assert {451, "4.7.1 " <> _} = command(client, "RCPT TO:<carol@example.com>")
    end

    test "a milter refuses the client, or the message at its header or body", context do
      fake =
        start_supervised!(
          {FakeMilter,
           owner: self(),
           replies: %{
             connect: fn {_host, _family, _port, _address} -> :continue end,
             header: fn {name, value} ->
               if name == "Subject" and value == "spam",
                 do: {:reply_code, "554 5.7.1 Spam"},
                 else: :continue
             end,
             body: fn chunk -> if chunk =~ "virus", do: :reject, else: :continue end
           }}
        )

      mta = start_mta(context, milter_toml(fake))

      assert {{:ok, {554, ["5.7.1 Spam"]}}, _} =
               send_message(
                 mta,
                 "a@remote.test",
                 ["bob@example.com"],
                 "Subject: spam\r\n\r\nx\r\n"
               )

      assert {{:ok, {550, ["5.7.1 Command rejected"]}}, _} =
               send_message(
                 mta,
                 "a@remote.test",
                 ["bob@example.com"],
                 "Subject: x\r\n\r\nvirus\r\n"
               )

      # A message that ends inside its header has no body for the milter.
      assert {{:ok, {554, _}}, _} =
               send_message(mta, "a@remote.test", ["bob@example.com"], "Subject: spam\r\n")

      assert queued(mta) == []

      refuser =
        start_supervised!(
          {FakeMilter, owner: self(), replies: %{connect: {:reply_code, "554 5.7.1 Go away"}}},
          id: :refuser
        )

      context = %{context | tmp_dir: Path.join(context.tmp_dir, "refuser")}
      mta = start_mta(context, milter_toml(refuser))
      client = connect(mta)
      assert {:ok, {554, ["5.7.1 Go away"]}} = SMTPClient.read_reply(client)
    end

    test "a milter that fails at the end of the message, with default_action accept", context do
      fake = start_supervised!({FakeMilter, owner: self(), replies: %{end_of_message: :close}})
      mta = start_mta(context, milter_toml(fake, ~s(default_action = "accept")))
      assert {{:ok, {250, _}}, _} = send_message(mta, "alice@remote.test", ["bob@example.com"])
      assert [_message] = queued(mta)
    end

    test "a milter's shutdown closes the session", context do
      fake = start_supervised!({FakeMilter, owner: self(), replies: %{helo: :shutdown}})
      mta = start_mta(context, milter_toml(fake))
      client = connect(mta)
      {:ok, {220, _}} = SMTPClient.read_reply(client)
      assert {421, "4.7.0 " <> _} = command(client, "EHLO client.test")
      assert {:error, :closed} = SMTPClient.read_reply(client)
    end
  end

  describe "policy servers" do
    setup context do
      server =
        start_supervised!(
          {Sovite.Policy.Server, ip: {127, 0, 0, 1}, port: 0, handler: {Policy, self()}}
        )

      {:ok, {_ip, port}} = Sovite.Listener.sockname(server)
      Map.put(context, :policy_port, port)
    end

    test "greylist, reject, and prepend header fields", context do
      toml =
        ~s([restrictions]\nrcpt = ["check_policy_service inet:127.0.0.1:#{context.policy_port}"])

      mta = start_mta(context, toml)
      client = connect(mta)
      {:ok, {220, _}} = SMTPClient.read_reply(client)
      {250, _} = command(client, "EHLO client.test")
      {250, _} = command(client, "MAIL FROM:<alice@remote.test> SIZE=100")

      assert {450, "4.7.1 Greylisted, see https://postgrey.example"} =
               command(client, "RCPT TO:<greylist@example.com>")

      assert_received {:policy, attributes}

      assert %{
               "request" => "smtpd_access_policy",
               "protocol_state" => "RCPT",
               "protocol_name" => "ESMTP",
               "client_address" => "127.0.0.1",
               "client_name" => "unknown",
               "helo_name" => "client.test",
               "sender" => "alice@remote.test",
               "recipient" => "greylist@example.com",
               "size" => "100",
               "instance" => instance
             } = attributes

      assert instance =~ ~r/\.1$/
      assert {554, "5.7.1 no spam"} = command(client, "RCPT TO:<spam@example.com>")
      {250, _} = command(client, "RCPT TO:<bob@example.com>")
      {354, _} = command(client, "DATA")
      assert {:ok, {250, _}} = SMTPClient.send_data(client, @body)

      assert [{%{recipients: ["bob@example.com"]}, message}] = queued(mta)
      assert String.starts_with?(message, "X-Policy: checked\r\n")
    end

    test "redirect, copy, filter, and hold messages", context do
      toml =
        ~s([restrictions]\nrcpt = ["check_policy_service inet:127.0.0.1:#{context.policy_port}"])

      mta = start_mta(context, toml)

      for {rcpt, sender} <- [
            {"redirect@example.com", "r@remote.test"},
            {"bcc@example.com", "b@remote.test"},
            {"filter@example.com", "f@remote.test"}
          ] do
        assert {{:ok, {250, _}}, _} = send_message(mta, sender, [rcpt])
      end

      envelopes = mta |> queued() |> Map.new(fn {envelope, _} -> {envelope.sender, envelope} end)
      assert envelopes["r@remote.test"].recipients == ["bob@example.com"]
      assert envelopes["b@remote.test"].recipients == ["bcc@example.com", "archive@example.com"]
      assert envelopes["f@remote.test"].content_filter == "smtp:[127.0.0.1]:10024"

      assert {{:ok, {250, _}}, _} = send_message(mta, "h@remote.test", ["hold@example.com"])
      assert [{%{sender: "h@remote.test"}, _}] = queued(mta, :hold)
    end

    test "an unreachable server gets policy.default_action", context do
      toml = fn policy ->
        """
        [policy]
        timeout = "1s"
        #{policy}
        [restrictions]
        mail = ["check_policy_service inet:127.0.0.1:#{closed_port()}"]
        """
      end

      mta = start_mta(context, toml.(""))
      client = connect(mta)
      {:ok, {220, _}} = SMTPClient.read_reply(client)
      {250, _} = command(client, "EHLO client.test")

      assert {451, "4.3.5 Server configuration problem"} =
               command(client, "MAIL FROM:<alice@remote.test>")

      context = %{context | tmp_dir: Path.join(context.tmp_dir, "dunno")}
      mta = start_mta(context, toml.(~s(default_action = "DUNNO")))
      assert {{:ok, {250, _}}, _} = send_message(mta, "alice@remote.test", ["bob@example.com"])
    end

    test "a program on standard input and output, like policyd-spf", context do
      script = Path.join(context.tmp_dir, "policyd")

      File.write!(script, """
      #!/bin/sh
      while read -r line; do
        case "$line" in
          sender=spf-fail@*) action="550 5.7.23 SPF fail" ;;
          "") echo "action=${action:-PREPEND Received-SPF: pass}"; echo; action="" ;;
        esac
      done
      """)

      File.chmod!(script, 0o755)

      mta =
        start_mta(context, ~s([restrictions]\nrcpt = ["check_policy_service spawn:#{script}"]))

      assert {{:error, {{:rcpt, "bob@example.com"}, {550, ["5.7.23 SPF fail"]}}}, _} =
               send_message(mta, "spf-fail@remote.test", ["bob@example.com"])

      assert {{:ok, {250, _}}, _} = send_message(mta, "alice@remote.test", ["bob@example.com"])
      assert [{_envelope, "Received-SPF: pass\r\n" <> _}] = queued(mta)
    end
  end

  describe "XCLIENT and XFORWARD" do
    test "a proxy names the client, which then counts as logged in", context do
      mta = start_mta(context, ~s([smtp]\nxclient_networks = ["127.0.0.0/8"]))
      client = connect(mta)
      {:ok, {220, _}} = SMTPClient.read_reply(client)
      {250, _} = command(client, "EHLO proxy.test")

      assert {220, "mx.example.com ESMTP"} =
               command(
                 client,
                 "XCLIENT ADDR=192.0.2.1 NAME=client.example LOGIN=alice@example.com HELO=client.example"
               )

      # Relaying needs a login, which XCLIENT gave.
      {250, _} = command(client, "MAIL FROM:<alice@example.com>")
      {250, _} = command(client, "RCPT TO:<someone@remote.test>")
      {354, _} = command(client, "DATA")
      {:ok, {250, _}} = SMTPClient.send_data(client, @body)

      assert [{envelope, message}] = queued(mta)

      assert %{remote_ip: {192, 0, 2, 1}, helo: "client.example", auth_user: "alice@example.com"} =
               envelope

      assert message =~ "Received: from client.example"
    end

    test "a content filter's XFORWARD names the original client", context do
      mta =
        start_mta(context, ~s([smtp]\nxforward_networks = ["127.0.0.1"]),
          runtime: [reinjection: true]
        )

      client = connect(mta)
      {:ok, {220, _}} = SMTPClient.read_reply(client)
      {250, _} = command(client, "EHLO filter.test")
      {250, _} = command(client, "XFORWARD ADDR=192.0.2.9 HELO=origin.example IDENT=ABC")
      {250, _} = command(client, "MAIL FROM:<alice@remote.test>")
      {250, _} = command(client, "RCPT TO:<bob@example.com>")
      {354, _} = command(client, "DATA")
      {:ok, {250, _}} = SMTPClient.send_data(client, @body)

      assert [{envelope, message}] = queued(mta)
      assert %{remote_ip: {192, 0, 2, 9}, helo: "origin.example", content_filter: nil} = envelope
      # No email authentication on the way back.
      refute message =~ "Authentication-Results"
    end

    test "a listener with a content filter queues mail for it", context do
      mta =
        start_mta(context, "", runtime: [content_filter: "smtp:[127.0.0.1]:10024"])

      assert {{:ok, {250, _}}, _} = send_message(mta, "alice@remote.test", ["bob@example.com"])
      assert [{%{content_filter: "smtp:[127.0.0.1]:10024"}, message}] = queued(mta)
      assert message =~ "Authentication-Results"
    end
  end
end
