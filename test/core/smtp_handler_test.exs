defmodule Sovite.Core.SMTPHandlerTest do
  # End-to-end over TCP: relay control, recipient checks, and spooling.
  use ExUnit.Case, async: true

  alias Sovite.Core.{Config, SMTPHandler}
  alias Sovite.Queue.Spool
  alias Sovite.Test.{Certs, FakeDNS, SMTPClient}

  @moduletag :tmp_dir

  defp start_mta(context, toml \\ "") do
    queue = Path.join(context.tmp_dir, "queue")

    {:ok, config} =
      Config.parse("""
      [server]
      hostname = "mx.example.com"
      [queue]
      directory = "#{queue}"
      #{toml}
      """)

    :ok = Spool.init(queue)

    server =
      start_supervised!(
        {Sovite.SMTP.Server,
         ip: {127, 0, 0, 1},
         port: 0,
         hostname: config.server.hostname,
         handler: {SMTPHandler, SMTPHandler.opts(config, nil, resolver: FakeDNS.resolver(%{}))},
         max_message_size: config.smtp.max_message_size,
         vrfy: config.smtp.vrfy}
      )

    {:ok, {_ip, port}} = Sovite.Listener.sockname(server)
    {:ok, client} = SMTPClient.connect(port)
    on_exit(fn -> SMTPClient.close(client) end)
    {:ok, {220, _}} = SMTPClient.read_reply(client)
    {:ok, {250, _}} = SMTPClient.command(client, "EHLO client.test")
    {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<sender@remote.test>")
    %{client: client, queue: queue}
  end

  defp rcpt(%{client: client}, address) do
    {:ok, {code, [text]}} = SMTPClient.command(client, "RCPT TO:<#{address}>")
    {code, text}
  end

  defp deliver(%{client: client}, body) do
    {:ok, {354, _}} = SMTPClient.command(client, "DATA")
    SMTPClient.send_data(client, body)
  end

  defp queued(%{queue: queue}, queue_id) do
    path = Path.join([queue, "incoming", queue_id])
    {:ok, loaded} = Spool.load(path)
    stream = Spool.stream_message(path, loaded.message_offset, loaded.message_size, loaded.prefix)
    {loaded.envelope, Enum.join(stream)}
  end

  defp queue_files(%{queue: queue}, dir), do: File.ls!(Path.join(queue, dir))

  describe "open relay test" do
    # The default config trusts no network. None of these may be accepted.
    @attempts [
      "user@remote.test",
      "user@sub.mx.example.com",
      "user@mx.example.com.remote.test",
      "@mx.example.com:user@remote.test",
      "@mx.example.com,@other.test:user@remote.test",
      "user@[127.0.0.1]",
      "user@[IPv6:::1]"
    ]

    test "refuses every relay attempt from an untrusted client", context do
      mta = start_mta(context)

      for address <- @attempts do
        assert {554, "5.7.1 " <> _} = rcpt(mta, address), "accepted #{address}"
      end

      {:ok, {code, _}} = SMTPClient.command(mta.client, "DATA")
      assert code in [503, 554]
      assert queue_files(mta, "incoming") == []
    end

    test "refuses malformed relay tricks", context do
      mta = start_mta(context)

      for address <- ["user@remote.test@mx.example.com", "user@remote.test.", "remote.test!user"] do
        assert {501, "5.1.3 " <> _} = rcpt(mta, address), "accepted #{address}"
      end
    end

    test "treats %-hacks and quoted @ as local parts, never as relaying", context do
      mta = start_mta(context, ~s([domains]\nlocal_recipients = ["user@mx.example.com"]))

      assert {550, "5.1.1 " <> _} = rcpt(mta, "user%remote.test@mx.example.com")
      assert {550, "5.1.1 " <> _} = rcpt(mta, ~s("user@remote.test"@mx.example.com))
    end
  end

  test "refuses a message with too many hops", context do
    mta = start_mta(context, "[smtp]\nmax_hops = 3")
    assert {250, _} = rcpt(mta, "user@mx.example.com")

    received = String.duplicate("Received: from a by b; Mon, 1 Jan 2026 00:00:00 +0000\r\n", 4)

    assert {:ok, {554, ["5.4.6 Too many hops"]}} =
             deliver(mta, received <> "Subject: x\r\n\r\nbody\r\n")

    assert queue_files(mta, "incoming") == []

    {:ok, {250, _}} = SMTPClient.command(mta.client, "MAIL FROM:<sender@remote.test>")
    assert {250, _} = rcpt(mta, "user@mx.example.com")
    received = String.duplicate("Received: from a by b; Mon, 1 Jan 2026 00:00:00 +0000\r\n", 3)
    assert {:ok, {250, _}} = deliver(mta, received <> "Subject: x\r\n\r\nbody\r\n")
  end

  test "relays for trusted networks", context do
    mta = start_mta(context, ~s([smtp]\ntrusted_networks = ["127.0.0.0/8"]))
    assert {250, _} = rcpt(mta, "user@remote.test")
  end

  test "accepts relay domains from anyone", context do
    mta = start_mta(context, ~s([domains]\nrelay = ["backup.test"]))
    assert {250, _} = rcpt(mta, "user@Backup.TEST")
    assert {554, _} = rcpt(mta, "user@other.test")
  end

  test "checks local recipients case-insensitively", context do
    mta =
      start_mta(
        context,
        ~s([domains]\nlocal = ["example.com"]\nlocal_recipients = ["Alice@example.com"])
      )

    assert {250, _} = rcpt(mta, "alice@EXAMPLE.com")

    assert {550,
            "5.1.1 <bob@example.com>: Recipient address rejected: User unknown in local recipient table"} =
             rcpt(mta, "bob@example.com")
  end

  test "always accepts postmaster at local domains", context do
    mta = start_mta(context, ~s([domains]\nlocal = ["example.com"]\nlocal_recipients = []))

    assert {250, _} = rcpt(mta, "PostMaster@example.com")
    assert {250, _} = rcpt(mta, "Postmaster")
    assert {550, _} = rcpt(mta, "anyone@example.com")
    assert {554, _} = rcpt(mta, "postmaster@remote.test")

    assert {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} = deliver(mta, "x\r\n")

    assert {%{recipients: ["PostMaster@example.com", "postmaster@mx.example.com"]}, _} =
             queued(mta, id)
  end

  test "always accepts abuse at local domains", context do
    mta = start_mta(context, ~s([domains]\nlocal = ["example.com"]\nlocal_recipients = []))

    assert {250, _} = rcpt(mta, "Abuse@example.com")
    assert {501, _} = rcpt(mta, "Abuse")
    assert {554, _} = rcpt(mta, "abuse@remote.test")
  end

  test "queues the message durably with a Received header", context do
    mta = start_mta(context)
    assert {250, _} = rcpt(mta, "user@mx.example.com")

    assert {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} =
             deliver(mta, "Subject: hi\r\n\r\nbody\r\n")

    {envelope, message} = queued(mta, id)

    assert envelope.queue_id == id
    assert envelope.sender == "sender@remote.test"
    assert envelope.recipients == ["user@mx.example.com"]
    assert envelope.helo == "client.test"
    assert envelope.protocol == "ESMTP"
    assert envelope.remote_ip == {127, 0, 0, 1}
    assert is_binary(envelope.session_id)

    # Results of the checks on mail from outside come first.
    assert ["Authentication-Results: mx.example.com;" <> _, message] =
             String.split(message, ~r/(?<=\r\n)(?=Received:)/, parts: 2)

    assert [received, rest] = String.split(message, "Subject: hi", parts: 2)

    assert received =~
             ~r/\AReceived: from client.test \(\[127.0.0.1\]\)\r\n\tby mx.example.com with ESMTP id #{id}\r\n\tfor <user@mx.example.com>; \w{3}, .+ \+0000\r\n\z/

    assert rest == "\r\n\r\nbody\r\n"
    assert queue_files(mta, "tmp") == []
    assert File.stat!(Path.join([mta.queue, "incoming", id])).mode |> Bitwise.band(0o777) == 0o600
  end

  test "hides recipients in Received when there are several, and drops duplicates", context do
    mta = start_mta(context)
    assert {250, _} = rcpt(mta, "a@mx.example.com")
    assert {250, _} = rcpt(mta, "b@mx.example.com")
    assert {250, _} = rcpt(mta, "a@mx.example.com")

    {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} = deliver(mta, "x\r\n")
    {envelope, message} = queued(mta, id)

    assert envelope.recipients == ["a@mx.example.com", "b@mx.example.com"]
    refute message =~ "for <"
  end

  test "records BODY=8BITMIME and the null sender", context do
    mta = start_mta(context)
    {:ok, {250, _}} = SMTPClient.command(mta.client, "RSET")
    {:ok, {250, _}} = SMTPClient.command(mta.client, "MAIL FROM:<> BODY=8BITMIME")
    assert {250, _} = rcpt(mta, "user@mx.example.com")

    {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} = deliver(mta, "x\r\n")
    assert {%{sender: "", body_type: :"8bitmime"}, _} = queued(mta, id)
  end

  test "records REQUIRETLS, offered over TLS", context do
    queue = Path.join(context.tmp_dir, "queue")

    {:ok, config} =
      Config.parse(~s([server]\nhostname = "mx.example.com"\n[queue]\ndirectory = "#{queue}"))

    :ok = Spool.init(queue)
    ca = Certs.ca()
    cert = Certs.issue(ca, names: ["mx.example.com"])

    server =
      start_supervised!(
        {Sovite.SMTP.Server,
         ip: {127, 0, 0, 1},
         port: 0,
         hostname: "mx.example.com",
         handler: {SMTPHandler, SMTPHandler.opts(config, nil, resolver: FakeDNS.resolver(%{}))},
         tls: Sovite.TLS.server_options(certs_keys: [Certs.certs_keys(cert)]),
         requiretls: true}
      )

    {:ok, {_ip, port}} = Sovite.Listener.sockname(server)
    {:ok, client} = SMTPClient.connect(port)
    {:ok, {220, _}} = SMTPClient.read_reply(client)
    {:ok, {250, lines}} = SMTPClient.command(client, "EHLO client.test")
    refute "REQUIRETLS" in lines

    tls = Sovite.TLS.client_options(verify: :peer, hostname: "mx.example.com", cacerts: [ca.cert])
    {:ok, client} = SMTPClient.starttls(client, tls)
    {:ok, {250, lines}} = SMTPClient.command(client, "EHLO client.test")
    assert "REQUIRETLS" in lines

    {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<sender@remote.test> REQUIRETLS")
    {:ok, {250, _}} = SMTPClient.command(client, "RCPT TO:<user@mx.example.com>")
    {:ok, {354, _}} = SMTPClient.command(client, "DATA")
    {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} = SMTPClient.send_data(client, "x\r\n")
    assert {%{requiretls: true}, _} = queued(%{queue: queue}, id)
  end

  test "keeps nothing when the message is too large", context do
    mta = start_mta(context, ~s([smtp]\nmax_message_size = 1024))
    assert {250, _} = rcpt(mta, "user@mx.example.com")

    assert {:ok, {552, _}} = deliver(mta, String.duplicate("x", 2000) <> "\r\n")
    assert queue_files(mta, "incoming") == []
    assert queue_files(mta, "tmp") == []
  end

  test "replies 451 when the queue cannot be written", context do
    mta = start_mta(context)
    assert {250, _} = rcpt(mta, "user@mx.example.com")
    File.chmod!(Path.join(mta.queue, "tmp"), 0o500)
    on_exit(fn -> File.chmod(Path.join(mta.queue, "tmp"), 0o700) end)

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:ok, {451, ["4.3.0 Error: queue file write error"]}} =
                 SMTPClient.command(mta.client, "DATA")
      end)

    assert log =~ "remote_ip=127.0.0.1"
    assert log =~ "cannot write queue file: permission denied"
  end

  test "VRFY reports local recipients when enabled", context do
    mta =
      start_mta(
        context,
        ~s([smtp]\nvrfy = true\n[domains]\nlocal_recipients = ["alice@mx.example.com"])
      )

    assert {:ok, {250, ["2.1.5 <alice@mx.example.com>"]}} =
             SMTPClient.command(mta.client, "VRFY <alice@mx.example.com>")

    assert {:ok, {550, _}} = SMTPClient.command(mta.client, "VRFY bob@mx.example.com")
    assert {:ok, {252, _}} = SMTPClient.command(mta.client, "VRFY bob")
  end
end
