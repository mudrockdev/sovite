defmodule Sovite.Core.SubmissionTest do
  # Authenticated submission end to end: STARTTLS, AUTH against the
  # database, relaying, sender login maps, header fixes, and bans.
  use ExUnit.Case, async: true

  alias Sovite.Abuse.Penalty
  alias Sovite.Core.{Config, SMTPHandler, Users}
  alias Sovite.Queue.Spool
  alias Sovite.SMTP.Client
  alias Sovite.Test.{Certs, Database, SMTPClient, TelemetryForwarder}

  @moduletag :tmp_dir

  setup_all do
    ca = Certs.ca()
    cert = Certs.issue(ca, names: ["mx.example.com"])

    %{
      server_tls: Sovite.TLS.server_options(certs_keys: [Certs.certs_keys(cert)]),
      client_tls:
        Sovite.TLS.client_options(verify: :peer, hostname: "mx.example.com", cacerts: [ca.cert])
    }
  end

  setup %{tmp_dir: dir} do
    repo = Database.start!(dir)
    {:ok, _} = Users.create(repo, "alice@example.com", "secret")
    {:ok, _} = Users.add_sender(repo, "alice@example.com", "sales@example.com")
    queue = Path.join(dir, "queue")
    :ok = Spool.init(queue)
    penalty = :"penalty_#{System.unique_integer([:positive])}"
    start_supervised!({Penalty, name: penalty, max_failures: 3, window: 60_000, ban_time: 60_000})
    %{repo: repo, queue: queue, penalty: penalty}
  end

  defp start_server(context, toml \\ "", listener \\ [], auth \\ "") do
    {:ok, config} =
      Config.parse("""
      [server]
      hostname = "mx.example.com"
      [queue]
      directory = "#{context.queue}"
      [domains]
      local = ["example.com"]
      [auth]
      failure_delay = 1
      senders = { "alice@example.com" = ["@example.org"] }
      #{auth}
      [[tls.certificate]]
      cert_file = "/unused.crt"
      key_file = "/unused.key"
      [[listener]]
      mode = "submission"
      #{toml}
      """)

    {require_auth, listener} = Keyword.pop(listener, :require_auth, true)

    handler =
      SMTPHandler.opts(config, nil,
        repo: context.repo,
        penalty: context.penalty,
        require_auth: require_auth
      )

    server =
      start_supervised!(
        {Sovite.SMTP.Server,
         [
           ip: {127, 0, 0, 1},
           port: 0,
           hostname: "mx.example.com",
           handler: {SMTPHandler, handler},
           tls: context.server_tls,
           require_tls: true,
           auth: true,
           auth_required: true
         ]
         |> Keyword.merge(listener)},
        id: make_ref()
      )

    {:ok, {_, port}} = Sovite.Listener.sockname(server)
    port
  end

  defp connect(port) do
    {:ok, client} = SMTPClient.connect(port)
    on_exit(fn -> SMTPClient.close(client) end)
    client
  end

  defp secure_session(context, port) do
    client = connect(port)
    {:ok, {220, _}} = SMTPClient.read_reply(client)
    {:ok, {250, _}} = SMTPClient.command(client, "EHLO client.test")
    {:ok, client} = SMTPClient.starttls(client, context.client_tls)
    {:ok, {250, lines}} = SMTPClient.command(client, "EHLO client.test")
    {client, lines}
  end

  defp login(client, user \\ "alice@example.com", password \\ "secret") do
    SMTPClient.command(
      client,
      "AUTH PLAIN " <> Base.encode64(<<0, user::binary, 0, password::binary>>)
    )
  end

  defp queued(context, id) do
    path = Path.join([context.queue, "incoming", id])
    {:ok, envelope, offset} = Spool.read(path)
    data = File.read!(path)
    {envelope, binary_part(data, offset, byte_size(data) - offset)}
  end

  defp submit(client, from, to, body) do
    {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<#{from}>")
    {:ok, {250, _}} = SMTPClient.command(client, "RCPT TO:<#{to}>")
    {:ok, {354, _}} = SMTPClient.command(client, "DATA")
    {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} = SMTPClient.send_data(client, body)
    id
  end

  test "authenticates and relays, with ESMTPSA and TLS in Received", context do
    TelemetryForwarder.attach([[:sovite, :auth, :success]])
    port = start_server(context)
    {client, lines} = secure_session(context, port)
    assert "AUTH SCRAM-SHA-256 PLAIN LOGIN" in lines

    assert {:ok, {530, _}} = SMTPClient.command(client, "MAIL FROM:<alice@example.com>")
    assert {:ok, {235, _}} = login(client)

    assert_received {:telemetry, [:sovite, :auth, :success], _,
                     %{username: "alice@example.com", mechanism: "PLAIN"}}

    id =
      submit(
        client,
        "alice@example.com",
        "bob@remote.example",
        "Subject: hi\r\nDate: Sun, 4 Oct 2026 10:00:00 +0000\r\nMessage-ID: <keep@client>\r\n\r\nbody\r\n"
      )

    {envelope, data} = queued(context, id)
    assert envelope.protocol == "ESMTPSA"

    assert data =~
             ~r/\AReceived: from client.test \(\[127.0.0.1\]\)\r\n\t\(using TLSv1.3 with cipher TLS_\w+ \(\d+\/\d+ bits\)\)\r\n\tby mx.example.com with ESMTPSA id #{id}/

    assert data =~ "Message-ID: <keep@client>\r\n"

    assert String.ends_with?(
             data,
             "Subject: hi\r\nDate: Sun, 4 Oct 2026 10:00:00 +0000\r\nMessage-ID: <keep@client>\r\n\r\nbody\r\n"
           )
  end

  test "adds Date and Message-ID and strips configured headers", context do
    port = start_server(context, ~s([submission]\nstrip_headers = ["Return-Path", "X-Secret"]))
    {client, _} = secure_session(context, port)
    {:ok, {235, _}} = login(client)

    id =
      submit(
        client,
        "alice@example.com",
        "bob@remote.example",
        "Return-Path: <x@y>\r\nX-Secret: 1\r\n\tfolded\r\nSubject: hi\r\n\r\nbody\r\nReturn-Path: in body\r\n"
      )

    {_envelope, data} = queued(context, id)
    [_received, rest] = String.split(data, ~r/; \w{3}, [^\r]+\r\n/, parts: 2)

    assert rest =~
             ~r/\ASubject: hi\r\nDate: \w{3}, .+ \+0000\r\nMessage-ID: <[a-z0-9.]+@mx.example.com>\r\n\r\nbody\r\nReturn-Path: in body\r\n\z/

    # A message with only a header section, no body.
    id = submit(client, "alice@example.com", "bob@remote.example", "Subject: only headers")
    {_envelope, data} = queued(context, id)
    assert data =~ ~r/Subject: only headers\r\nDate: .+\r\nMessage-ID: .+\r\n\z/
  end

  test "enforces sender login maps from the config and the database", context do
    port = start_server(context)
    {client, _} = secure_session(context, port)
    {:ok, {235, _}} = login(client)

    for sender <- ["alice@example.com", "Sales@Example.com", "anyone@example.org", ""] do
      assert {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<#{sender}>"), sender
      {:ok, {250, _}} = SMTPClient.command(client, "RSET")
    end

    assert {:ok,
            {553,
             [
               "5.7.1 <bob@example.com>: Sender address rejected: not owned by user alice@example.com"
             ]}} =
             SMTPClient.command(client, "MAIL FROM:<bob@example.com>")
  end

  test "sender checks can be turned off", context do
    port = start_server(context, "", [], "sender_check = false")
    {client, _} = secure_session(context, port)
    {:ok, {235, _}} = login(client)
    assert {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<bob@example.com>")
  end

  test "bans an address after repeated failures", context do
    TelemetryForwarder.attach([[:sovite, :auth, :failure], [:sovite, :abuse, :penalty, :banned]])
    port = start_server(context)

    {client, _} = secure_session(context, port)

    assert {:ok, {535, ["5.7.8 Authentication credentials invalid"]}} =
             login(client, "alice@example.com", "wrong")

    assert {:ok, {535, _}} = login(client, "nobody@example.com", "x")

    assert_received {:telemetry, [:sovite, :auth, :failure], _,
                     %{username: "alice@example.com", reason: :invalid_credentials}}

    {client, _} = secure_session(context, port)
    assert {:ok, {535, _}} = login(client, "alice@example.com", "wrong")

    assert_received {:telemetry, [:sovite, :abuse, :penalty, :banned], %{failures: 3},
                     %{key: {127, 0, 0, 1}}}

    # Even the right password is refused now, and new connections are turned away.
    assert {:ok, {454, _}} = login(client)
    client = connect(port)
    assert {:ok, {421, [text]}} = SMTPClient.read_reply(client)
    assert text =~ "Too many failed logins"
  end

  test "groups IPv6 clients by /64" do
    assert SMTPHandler.penalty_key({0x2001, 0xDB8, 1, 2, 3, 4, 5, 6}) ==
             {0x2001, 0xDB8, 1, 2, 0, 0, 0, 0}

    assert SMTPHandler.penalty_key({192, 0, 2, 1}) == {192, 0, 2, 1}
  end

  test "authenticates with SCRAM-SHA-256 through the SMTP client", context do
    port =
      start_server(context, "",
        require_tls: false,
        auth_required: false,
        plaintext_auth: true,
        tls: nil
      )

    {:ok, client} = Client.connect({127, 0, 0, 1}, port, helo: "client.test")

    assert {:ok, client} =
             Client.authenticate(
               client,
               %{username: "alice@example.com", password: "secret"},
               ["SCRAM-SHA-256"]
             )

    assert {:ok, _, [{_, :data_end, %{code: 250}}]} =
             Client.deliver(client, "alice@example.com", ["bob@remote.example"], [
               "Subject: x\r\n\r\ny\r\n"
             ])
  end
end
