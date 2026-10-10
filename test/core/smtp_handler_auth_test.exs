defmodule Sovite.Core.SMTPHandlerAuthTest do
  # AUTH through the MTA handler with the file and Dovecot backends.
  use ExUnit.Case, async: true

  alias Sovite.Core.{Config, SMTPHandler}
  alias Sovite.Queue.Spool
  alias Sovite.SASL.Password
  alias Sovite.Test.{FakeDNS, FakeDovecot, SMTPClient}

  @moduletag :tmp_dir

  defp start(context, auth_toml) do
    queue = Path.join(context.tmp_dir, "queue")
    :ok = Spool.init(queue)

    {:ok, config} =
      Config.parse("""
      [server]
      hostname = "mx.example.com"
      [queue]
      directory = "#{queue}"
      [[listener]]
      auth = true
      [auth]
      plaintext = true
      failure_delay = 1
      #{auth_toml}
      """)

    server =
      start_supervised!(
        {Sovite.SMTP.Server,
         ip: {127, 0, 0, 1},
         port: 0,
         hostname: "mx.example.com",
         handler: {SMTPHandler, SMTPHandler.opts(config, nil, resolver: FakeDNS.resolver(%{}))},
         auth: true,
         plaintext_auth: true},
        id: make_ref()
      )

    {:ok, {_, port}} = Sovite.Listener.sockname(server)
    {:ok, client} = SMTPClient.connect(port)
    on_exit(fn -> SMTPClient.close(client) end)
    {:ok, {220, _}} = SMTPClient.read_reply(client)
    {:ok, {250, lines}} = SMTPClient.command(client, "EHLO client.test")
    {client, lines}
  end

  defp plain(user, password),
    do: "AUTH PLAIN " <> Base.encode64(<<0, user::binary, 0, password::binary>>)

  test "authenticates against a users file", context do
    users = Path.join(context.tmp_dir, "users")
    File.write!(users, "bob@example.com:#{Password.hash("hunter2", :sha512_crypt)}\n")

    {client, lines} =
      start(context, ~s(backend = "file"\nsender_check = false\n[auth.file]\npath = "#{users}"))

    assert "AUTH SCRAM-SHA-256 PLAIN LOGIN" in lines
    assert {:ok, {535, _}} = SMTPClient.command(client, plain("bob@example.com", "nope"))
    assert {:ok, {235, _}} = SMTPClient.command(client, plain("bob@example.com", "hunter2"))
    assert {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<anyone@example.org>")
    assert {:ok, {250, _}} = SMTPClient.command(client, "RCPT TO:<x@remote.example>")
  end

  test "hands authentication to Dovecot, including challenges and cancel", context do
    socket = "/tmp/sovite-dovecot-#{System.unique_integer([:positive])}.sock"

    start_supervised!(
      {FakeDovecot, path: socket, owner: self(), users: %{"carol" => "pw", "tempfail" => "x"}}
    )

    on_exit(fn -> File.rm(socket) end)

    {client, lines} =
      start(context, ~s(backend = "dovecot"\n[auth.dovecot]\nsocket = "#{socket}"))

    assert "AUTH PLAIN LOGIN" in lines

    assert {:ok, {334, ["VXNlcm5hbWU6"]}} = SMTPClient.command(client, "AUTH LOGIN")
    assert {:ok, {501, _}} = SMTPClient.command(client, "*")

    assert {:ok, {454, ["4.7.0 Temporary authentication failure"]}} =
             SMTPClient.command(client, plain("tempfail", "x"))

    assert_receive {:dovecot, :auth, ["AUTH", "1", "PLAIN", "service=smtp", "rip=127.0.0.1" | _]}

    assert {:ok, {334, _}} = SMTPClient.command(client, "AUTH LOGIN")
    assert {:ok, {334, ["UGFzc3dvcmQ6"]}} = SMTPClient.command(client, Base.encode64("carol"))
    assert {:ok, {235, _}} = SMTPClient.command(client, Base.encode64("pw"))
  end

  test "builds LDAP and OAuth backend options" do
    {:ok, config} =
      Config.parse("""
      [auth]
      backend = "ldap"
      [auth.ldap]
      servers = ["ldap.example.com"]
      base = "dc=example"
      bind_dn = "cn=svc"
      [auth.oauth]
      introspection_url = "https://idp.example/introspect"
      client_id = "sovite"
      """)

    opts = SMTPHandler.opts(config)
    assert opts.auth.mechanisms == ["PLAIN", "LOGIN", "OAUTHBEARER"]
    assert {Sovite.SASL.Backend.LDAP, ldap} = opts.auth.opts[:backend]
    assert ldap[:base] == "dc=example"
    assert ldap[:bind_dn] == "cn=svc"
    refute Keyword.has_key?(ldap, :dn_template)
    assert {Sovite.SASL.Backend.Introspection, oauth} = opts.auth.opts[:token_backend]
    assert oauth[:client_id] == "sovite"

    {:ok, config} =
      Config.parse(~s([auth]\nbackend = "dovecot"\n[auth.dovecot]\nsocket = "127.0.0.1:12345"))

    assert SMTPHandler.opts(config).auth.opts[:socket] == {"127.0.0.1", 12_345}
  end
end
