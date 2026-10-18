defmodule Sovite.Core.TenantsTest do
  # Tenants: who they are, their limits over TCP, and their DKIM keys.
  use ExUnit.Case, async: true

  alias Sovite.Abuse.RateLimit
  alias Sovite.Core.{Config, SMTPHandler, Tenants}
  alias Sovite.DKIM.SigningKey
  alias Sovite.Queue.Spool
  alias Sovite.Test.{FakeDNS, SMTPClient, TelemetryForwarder}

  @moduletag :tmp_dir

  @tenants """
  [[tenant]]
  name = "acme"
  domains = ["acme.example"]
  users = ["relay-user"]
  messages = "2/1h"
  recipients = "3/1h"
  max_message_size = "1K"
  max_recipients = 2

  [[tenant]]
  name = "sub"
  domains = ["eu.acme.example"]
  """

  defp tenants(toml \\ @tenants, rate_limit \\ nil) do
    {:ok, config} = Config.parse(toml)
    {config, Tenants.opts(config, rate_limit)}
  end

  describe "find/4" do
    test "by login, login domain, or sender domain of trusted clients" do
      {_config, opts} = tenants()

      assert Tenants.find(opts, "Relay-User", "x@other.example", false).name == "acme"
      assert Tenants.find(opts, "bob@acme.example", "x@other.example", false).name == "acme"
      assert Tenants.find(opts, "bob@mail.eu.acme.example", "", false).name == "sub"
      assert Tenants.find(opts, nil, "a@ACME.example", true).name == "acme"
      assert Tenants.find(opts, "nobody", "a@acme.example", false).name == "acme"

      # Untrusted clients that did not log in belong to no tenant.
      assert Tenants.find(opts, nil, "a@acme.example", false) == nil
      assert Tenants.find(opts, nil, "", true) == nil
      assert Tenants.find(opts, "bob@other.example", "bob@other.example", false) == nil
      assert Tenants.find(nil, "relay-user", "a@acme.example", true) == nil
      assert Tenants.opts(elem(tenants(""), 0), nil) == nil
    end

    test "owners and names" do
      {config, _opts} = tenants()
      assert Tenants.owner(config.tenant, "acme.example") == "acme"
      assert Tenants.owner(config.tenant, "x.EU.acme.example") == "sub"
      assert Tenants.owner(config.tenant, "example.org") == nil
      assert Tenants.get(config.tenant, "sub").domains == ["eu.acme.example"]
      assert Tenants.get(config.tenant, "gone") == nil
      assert Tenants.get(config.tenant, nil) == nil
    end
  end

  test "limits", %{tmp_dir: _dir} do
    TelemetryForwarder.attach([[:sovite, :tenant, :limited]])
    name = :"tenants_test_#{System.unique_integer([:positive])}"
    start_supervised!({RateLimit, name: name})
    {config, opts} = tenants(@tenants, name)
    [acme, sub] = config.tenant

    assert Tenants.message(opts, nil, 10_000) == :ok
    assert Tenants.message(opts, acme, 2_000) == {:limited, :max_message_size}
    assert_received {:telemetry, _, _, %{tenant: "acme", limit: :max_message_size}}
    assert Tenants.message(opts, acme, nil) == :ok
    assert Tenants.message(opts, acme, 100) == :ok
    assert Tenants.message(opts, acme, 100) == {:limited, :messages}
    assert Tenants.message(opts, sub, 10_000_000) == :ok

    assert Tenants.recipient(opts, nil, 100) == :ok
    assert Tenants.recipient(opts, acme, 3) == {:limited, :max_recipients}
    assert Tenants.recipient(opts, acme, 1) == :ok
    assert Tenants.recipient(opts, acme, 2) == :ok
    assert Tenants.recipient(opts, acme, 1) == :ok
    assert Tenants.recipient(opts, acme, 1) == {:limited, :recipients}
    assert Tenants.recipient(opts, sub, 1_000) == :ok

    refute Tenants.too_large?(nil, 10_000)
    refute Tenants.too_large?(sub, 10_000)
    refute Tenants.too_large?(acme, 1024)
    assert Tenants.too_large?(acme, 1025)
  end

  describe "over SMTP" do
    setup %{tmp_dir: dir} do
      queue = Path.join(dir, "queue")
      :ok = Spool.init(queue)
      rate_limit = :"tenants_smtp_#{System.unique_integer([:positive])}"
      start_supervised!({RateLimit, name: rate_limit})

      pem = SigningKey.generate(:ed25519)
      {:ok, key} = SigningKey.from_pem(pem, "acme.example", "s1")
      key_file = Path.join(dir, "acme.pem")
      File.write!(key_file, pem)

      {:ok, config} =
        Config.parse("""
        [server]
        hostname = "mx.example.com"
        [queue]
        directory = "#{queue}"
        [smtp]
        trusted_networks = ["127.0.0.0/8"]
        [domains]
        local = ["example.com"]
        [[dkim.key]]
        domain = "acme.example"
        selector = "s1"
        file = "#{key_file}"
        #{@tenants}
        """)

      dns = %{{SigningKey.dns_name(key), :txt} => [SigningKey.dns_record(key)]}

      handler =
        SMTPHandler.opts(config, nil, resolver: FakeDNS.resolver(dns), rate_limit: rate_limit)

      server =
        start_supervised!(
          {Sovite.SMTP.Server,
           ip: {127, 0, 0, 1},
           port: 0,
           hostname: "mx.example.com",
           handler: {SMTPHandler, handler}},
          id: make_ref()
        )

      {:ok, {_ip, port}} = Sovite.Listener.sockname(server)
      %{port: port, queue: queue}
    end

    defp session(mta) do
      {:ok, client} = SMTPClient.connect(mta.port)
      on_exit(fn -> SMTPClient.close(client) end)
      {:ok, {220, _}} = SMTPClient.read_reply(client)
      {:ok, {250, _}} = SMTPClient.command(client, "EHLO client.test")
      client
    end

    defp reply(client, line) do
      {:ok, {code, lines}} = SMTPClient.command(client, line)
      {code, List.last(lines)}
    end

    defp queued(mta, text) do
      [_, id] = Regex.run(~r/queued as (\S+)/, text)
      path = Path.join([mta.queue, "incoming", id])
      {:ok, loaded} = Spool.load(path)

      message =
        path
        |> Spool.stream_message(loaded.message_offset, loaded.message_size, loaded.prefix)
        |> Enum.join()

      {loaded.envelope, message}
    end

    test "tenant mail is tagged, signed with its keys, and limited", mta do
      client = session(mta)
      assert {250, _} = reply(client, "MAIL FROM:<a@acme.example>")
      assert {250, _} = reply(client, "RCPT TO:<x@example.net>")
      assert {250, _} = reply(client, "RCPT TO:<y@example.net>")
      assert {452, "4.5.3 Too many recipients"} = reply(client, "RCPT TO:<z@example.net>")
      assert {354, _} = reply(client, "DATA")

      {:ok, {250, [text]}} =
        SMTPClient.send_data(client, "From: a@acme.example\r\nSubject: hi\r\n\r\nHello\r\n")

      {envelope, message} = queued(mta, text)
      assert envelope.tenant == "acme"
      assert message =~ "DKIM-Signature: "
      assert message =~ "d=acme.example"

      # Too large for the tenant, by SIZE and by what was sent.
      assert {552, "5.3.4 Message size exceeds the limit of your account"} =
               reply(client, "MAIL FROM:<a@acme.example> SIZE=5000")

      assert {250, _} = reply(client, "MAIL FROM:<a@acme.example>")
      assert {250, _} = reply(client, "RCPT TO:<x@example.net>")
      assert {354, _} = reply(client, "DATA")

      assert {:ok, {552, ["5.3.4 Message size exceeds the limit of your account"]}} =
               SMTPClient.send_data(client, "Subject: big\r\n\r\n" <> String.duplicate("x", 2000))

      # Two messages counted already; recipients too.
      assert {450, "4.7.1 Too many messages from your account, try later"} =
               reply(client, "MAIL FROM:<a@acme.example>")
    end

    test "mail of no tenant is not signed with a tenant's keys", mta do
      client = session(mta)
      assert {250, _} = reply(client, "MAIL FROM:<a@other.example>")
      assert {250, _} = reply(client, "RCPT TO:<x@example.net>")
      assert {354, _} = reply(client, "DATA")

      {:ok, {250, [text]}} =
        SMTPClient.send_data(client, "From: a@acme.example\r\nSubject: hi\r\n\r\nHello\r\n")

      {envelope, message} = queued(mta, text)
      assert envelope.tenant == nil
      refute message =~ "DKIM-Signature"
    end

    test "limits count the tenant's messages, not other tenants'", mta do
      client = session(mta)

      for _ <- 1..2 do
        assert {250, _} = reply(client, "MAIL FROM:<a@acme.example>")
        assert {250, _} = reply(client, "RCPT TO:<x@example.net>")
        reply(client, "RSET")
      end

      assert {250, _} = reply(client, "MAIL FROM:<a@eu.acme.example>")
      assert {250, _} = reply(client, "RCPT TO:<x@example.net>")
      reply(client, "RSET")

      assert {450, "4.7.1 Too many messages from your account, try later"} =
               reply(client, "MAIL FROM:<a@acme.example>")
    end
  end
end
