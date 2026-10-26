defmodule Sovite.HandlerFuzzTest do
  # Fuzzing of Sovite's own SMTP handler (Sovite.Core.MTA.SMTPHandler)
  # behind the protocol session: recipient checks, aliases, SRS, header
  # fixes and rewriting, SPF, DKIM, and DMARC, and spooling. Whatever a
  # client sends, the session must not crash, nothing may be left half
  # written, and what is queued must load, with well-formed fields
  # added above the message.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.Core.Config
  alias Sovite.Core.MTA.SMTPHandler
  alias Sovite.DKIM.SigningKey
  alias Sovite.Message.Headers
  alias Sovite.Queue.Spool
  alias Sovite.SMTP.Server.Session
  alias Sovite.SRS
  alias Sovite.Test.{FakeDNS, Fuzz}
  alias Sovite.Test.Fuzz.SMTP, as: FuzzSMTP
  alias Sovite.Test.MemoryTable

  @moduletag :fuzz
  # `mix fuzz` runs each property many times.
  @moduletag timeout: :infinity
  @moduletag :tmp_dir

  @bodies [
    "From: a@example.com\r\nTo: alice@example.com\r\nSubject: hi\r\n\r\nbody\r\n",
    "Received: from x by y; Mon, 1 Jan 2026 00:00:00 +0000\r\nAuthentication-Results: mx.example.com; dkim=pass header.d=bank.example\r\nFrom: \"Doe, J\" <j@sub.example.com>\r\n\r\n..dot\r\n",
    "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=x; h=from; bh=; b=\r\nFrom: =?utf-8?q?J=C3=B6rg?= <jörg@exämple.com>\r\nDate: x\r\n\r\nbody\r\n",
    "Subject: no from\r\n\r\n" <> String.duplicate("long line ", 120) <> "\r\n",
    "\r\nno header at all\r\n"
  ]

  setup %{tmp_dir: dir} do
    key_file = Path.join(dir, "dkim.pem")
    File.write!(key_file, SigningKey.generate(:ed25519))
    users = Path.join(dir, "users")
    File.write!(users, "alice:{PLAIN}secret\n")

    {:ok, config} =
      Config.parse("""
      [server]
      hostname = "mx.example.com"
      [queue]
      directory = "#{Path.join(dir, "queue")}"
      [domains]
      local = ["example.com", "mx.example.com"]
      aliased = ["aliases.example"]
      [smtp]
      trusted_networks = ["192.0.2.0/25"]
      [routing]
      hide_subdomains = ["example.com"]
      [auth]
      backend = "file"
      plaintext = true
      failure_delay = "1ms"
      [auth.file]
      path = "#{users}"
      [auth.senders]
      alice = ["*"]
      [dkim]
      sign = true
      [[dkim.key]]
      domain = "example.com"
      selector = "s1"
      file = "#{key_file}"
      [dmarc]
      policy = "enforce"
      [srs]
      enabled = true
      secrets = ["fuzz secret, sixteen or more"]
      """)

    resolver =
      FakeDNS.resolver(%{
        {"example.com", :txt} => ["v=spf1 ip4:192.0.2.0/24 -all"],
        {"_dmarc.example.com", :txt} => ["v=DMARC1; p=reject; aspf=r"],
        {"remote.test", :txt} => ["v=spf1 ?all"],
        {"remote.test", :mx} => [{10, "mx.remote.test"}]
      })

    opts = SMTPHandler.opts(config, nil, resolver: resolver)

    aliases =
      MemoryTable.new(%{
        "sales@aliases.example" => "alice@example.com, bob@remote.test",
        "loop@aliases.example" => "loop@aliases.example, sales@aliases.example"
      })

    opts = put_in(opts.routing.aliases, [{"aliases", aliases}])

    {:ok, srs} =
      SRS.forward("bob@remote.test", "mx.example.com", secrets: ["fuzz secret, sixteen or more"])

    %{config: config, opts: opts, srs: srs}
  end

  property "sessions end cleanly, and what is queued loads with well-formed fields", %{
    tmp_dir: dir,
    config: config,
    opts: handler_opts,
    srs: srs
  } do
    mail = [
      "MAIL FROM:<sender@remote.test>",
      "MAIL FROM:<a@example.com> BODY=8BITMIME",
      "MAIL FROM:<> RET=HDRS ENVID=QQ314159",
      "MAIL FROM:<pelé@exämple.com> SMTPUTF8",
      "MAIL FROM:<bounce@remote.test> SIZE=500"
    ]

    rcpt = [
      "RCPT TO:<alice@example.com>",
      "RCPT TO:<alice+tag@sub.example.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;alice@example.com",
      "RCPT TO:<sales@aliases.example> NOTIFY=SUCCESS",
      "RCPT TO:<loop@aliases.example>",
      "RCPT TO:<Postmaster>",
      "RCPT TO:<bob@remote.test>",
      "RCPT TO:<#{srs}>",
      "RCPT TO:<ünïcode@example.com>"
    ]

    script = FuzzSMTP.script(mail: mail, rcpt: rcpt, bodies: @bodies)

    check all(
            script <- script,
            chunks <- Fuzz.chunked(script),
            remote_ip <- member_of([{192, 0, 2, 7}, {198, 51, 100, 7}]),
            max_runs: Fuzz.runs()
          ) do
      queue = Path.join(dir, "queue")
      File.rm_rf!(queue)
      :ok = Spool.init(queue)

      out = run_session(chunks, remote_ip, handler_opts, config)
      assert_replies(out)

      assert File.ls!(Path.join(queue, "tmp")) == [], "a message was left half written"

      for id <- File.ls!(Path.join(queue, "incoming")) do
        assert_queued(Path.join([queue, "incoming", id]))
      end
    end
  end

  defp run_session(chunks, remote_ip, handler_opts, config) do
    connection = %{remote_ip: remote_ip, remote_port: 40_000, session_id: "S1"}

    session_opts = [
      hostname: "mx.example.com",
      handler: {SMTPHandler, handler_opts},
      auth: true,
      plaintext_auth: true,
      chunking: true,
      binarymime: true,
      dsn: true,
      smtputf8: true,
      mt_priority: true,
      deliverby: true,
      rrvs: true,
      max_message_size: config.smtp.max_message_size,
      xclient_networks: [{{192, 0, 2, 0}, 25}],
      xforward_networks: [{{192, 0, 2, 0}, 25}]
    ]

    {result, out, session} = Session.new(connection, session_opts)
    {out, session} = feed(chunks, result, [out], session)
    :ok = Session.terminate(session, :closed)
    IO.iodata_to_binary(out)
  end

  defp feed([chunk | chunks], :continue, out, session) do
    {result, more, session} = Fuzz.quick(fn -> Session.handle_input(session, chunk) end, 5_000)
    feed(chunks, result, [out, more], session)
  end

  defp feed(_chunks, _result, out, session), do: {out, session}

  defp assert_replies(out) do
    for line <- String.split(out, "\r\n", trim: true) do
      assert line =~ ~r/\A[2-5][0-9][0-9][ -]/, inspect(line)
      assert String.valid?(line) and not String.contains?(line, ["\r", "\n", <<0>>])
    end
  end

  # The envelope is clean, and the fields this server put above the
  # message (Authentication-Results:, DKIM-Signature:, Received:) are
  # well-formed: each a field, folded only with CRLF and whitespace.
  defp assert_queued(path) do
    assert {:ok, loaded} = Spool.load(path)
    envelope = loaded.envelope

    for address <- [envelope.sender | envelope.recipients] do
      assert String.valid?(address) and not String.contains?(address, ["\r", "\n", <<0>>])
    end

    {:ok, received} = Spool.read_headers(path, loaded.message_offset, loaded.message_size)
    [first | _] = Headers.parse(received)
    added = Headers.parse(loaded.prefix) ++ [first]

    for {name, raw} <- added do
      assert name != nil, inspect(raw)
      assert String.valid?(raw), inspect(raw)
      assert raw =~ ~r/\A[^\r\n]*(\r\n[ \t][^\r\n]*)*\r\n\z/, inspect(raw)
    end

    assert {"received", _} = first
  end
end
