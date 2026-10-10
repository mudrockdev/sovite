defmodule Sovite.Core.MailAuthTest do
  # End-to-end over TCP: SPF, DKIM, ARC, and DMARC on received mail,
  # signing, sealing, SRS, and DMARC reports.
  use ExUnit.Case, async: true

  alias Sovite.{ARC, DKIM, SRS}
  alias Sovite.Core.{Config, DMARCReports, SMTPHandler}
  alias Sovite.Core.Repo.Tables.{Aliases, DMARCReportEntries}
  alias Sovite.DKIM.{Body, SigningKey}
  alias Sovite.Message.Headers
  alias Sovite.Queue.Spool
  alias Sovite.Test.{Database, FakeDNS, SMTPClient}

  @moduletag :tmp_dir

  @secret "a secret of sixteen characters"

  setup_all do
    keys = %{
      # A remote sender's key, a forwarder's, and this server's own.
      net: key(:rsa, "example.net", "sel"),
      lists: key(:ed25519, "lists.example", "arc"),
      rsa: key(:rsa, "example.com", "rsa"),
      ed: key(:ed25519, "example.com", "ed")
    }

    %{keys: keys}
  end

  defp key(type, domain, selector) do
    pem = SigningKey.generate(type, 1024)
    {:ok, key} = SigningKey.from_pem(pem, domain, selector)
    %{pem: pem, key: key}
  end

  defp dns(keys, extra \\ %{}) do
    keys
    |> Map.values()
    |> Map.new(&{{SigningKey.dns_name(&1.key), :txt}, [SigningKey.dns_record(&1.key)]})
    |> Map.merge(%{
      {"example.net", :txt} => ["v=spf1 ip4:127.0.0.1 -all"],
      {"_dmarc.example.net", :txt} => ["v=DMARC1; p=reject; rua=mailto:reports@example.net"],
      {"bad.example", :txt} => ["v=spf1 -all"],
      {"_dmarc.bad.example", :txt} => ["v=DMARC1; p=reject"],
      {"quarantine.example", :txt} => ["v=spf1 -all"],
      {"_dmarc.quarantine.example", :txt} => ["v=DMARC1; p=quarantine"]
    })
    |> Map.merge(extra)
    |> FakeDNS.resolver()
  end

  defp start_mta(context, toml, opts \\ []) do
    dir = context.tmp_dir
    queue = Path.join(dir, "queue")

    key_config =
      for {name, %{key: key, pem: pem}} <- context.keys, key.domain == "example.com" do
        file = Path.join(dir, "#{name}.pem")
        File.write!(file, pem)

        """
        [[dkim.key]]
        domain = "#{key.domain}"
        selector = "#{key.selector}"
        file = "#{file}"
        """
      end

    {:ok, config} =
      Config.parse("""
      [server]
      hostname = "mx.example.com"
      [queue]
      directory = "#{queue}"
      #{toml}
      #{Enum.join(key_config, "\n")}
      """)

    :ok = Spool.init(queue)
    repo = opts[:repo]

    handler =
      SMTPHandler.opts(config, nil, resolver: dns(context.keys), repo: repo)

    server =
      start_supervised!(
        {Sovite.SMTP.Server,
         ip: {127, 0, 0, 1}, port: 0, hostname: "mx.example.com", handler: {SMTPHandler, handler}},
        id: make_ref()
      )

    {:ok, {_ip, port}} = Sovite.Listener.sockname(server)
    %{port: port, queue: queue, config: config}
  end

  defp send_message(mta, from, recipients, message) do
    {:ok, client} = SMTPClient.connect(mta.port)
    on_exit(fn -> SMTPClient.close(client) end)
    SMTPClient.send_message(client, from, recipients, message)
  end

  defp queued(mta, id, queue \\ "incoming") do
    path = Path.join([mta.queue, queue, id])
    {:ok, loaded} = Spool.load(path)
    stream = Spool.stream_message(path, loaded.message_offset, loaded.message_size, loaded.prefix)
    {loaded.envelope, Enum.join(stream)}
  end

  defp results(message) do
    {:ok, header, _body} = Headers.split(message)

    for {"authentication-results", raw} <- Headers.parse(header) do
      [_, value] = :binary.split(raw, ":")
      value |> String.replace(~r/\r\n[ \t]+/, " ") |> String.trim()
    end
  end

  defp signed(message, key), do: Enum.join(DKIM.sign(message, [key])) <> message

  @message "From: Alice <a@example.net>\r\nTo: b@mx.example.com\r\nSubject: hi\r\n\r\nHello\r\n"

  describe "mail from outside" do
    test "is checked with SPF, DKIM, and DMARC", %{keys: keys} = context do
      mta = start_mta(context, "")

      forged =
        "Authentication-Results: MX.example.com; dkim=pass\r\n" <>
          "Authentication-Results: other.example; spf=fail\r\n"

      message = signed(@message, keys.net.key)

      assert {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} =
               send_message(mta, "a@example.net", ["b@mx.example.com"], forged <> message)

      {_envelope, queued} = queued(mta, id)
      assert [ours, theirs] = results(queued)
      assert theirs == "other.example; spf=fail"

      assert ours =~
               ~r/\Amx.example.com; spf=pass smtp.mailfrom=a@example.net; spf=none smtp.helo=client.test; dkim=pass header.d=example.net header.i=@example.net header.s=sel header.a=rsa-sha256 header.b=\S+; arc=none; dmarc=pass \(p=REJECT sp=REJECT dis=NONE\) header.from=example.net\z/

      refute queued =~ "MX.example.com; dkim=pass"
    end

    test "failing DMARC is reported, or refused and held with enforcement", context do
      unsigned = String.replace(@message, "a@example.net", "a@bad.example")

      mta = start_mta(context, "")

      assert {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} =
               send_message(mta, "a@bad.example", ["b@mx.example.com"], unsigned)

      {_envelope, queued} = queued(mta, id)
      [result] = results(queued)
      assert result =~ "spf=fail smtp.mailfrom=a@bad.example"
      assert result =~ "dkim=none"
      assert result =~ "dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=bad.example"

      enforcing = start_mta(context, ~s([dmarc]\npolicy = "enforce"))

      assert {:ok,
              {550,
               [
                 "5.7.26 Unauthenticated email from bad.example is not accepted due to its DMARC policy"
               ]}} =
               send_message(enforcing, "a@bad.example", ["b@mx.example.com"], unsigned)

      quarantined = String.replace(unsigned, "bad.example", "quarantine.example")

      assert {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} =
               send_message(enforcing, "a@quarantine.example", ["b@mx.example.com"], quarantined)

      {_envelope, held} = queued(enforcing, id, "hold")
      assert [result] = results(held)
      assert result =~ "dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE)"
    end

    test "a chain sealed by a trusted forwarder overrides the policy", %{keys: keys} = context do
      unsigned = String.replace(@message, "a@example.net", "a@bad.example")
      {:ok, header, body} = Headers.split(unsigned)
      fields = Headers.parse(header)

      {hash, _} =
        [DKIM.body_spec()]
        |> Body.new()
        |> Body.update(body)
        |> Body.finish()
        |> Map.fetch!(DKIM.body_spec())

      seal = ARC.seal(fields, hash, %ARC.Result{}, "lists.example; spf=pass", keys.lists.key)
      sealed = Enum.join(seal) <> unsigned

      config = ~s([dmarc]\npolicy = "enforce"\n[arc]\ntrusted_sealers = ["lists.example"])
      mta = start_mta(context, config)

      assert {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} =
               send_message(mta, "a@bad.example", ["b@mx.example.com"], sealed)

      {_envelope, queued} = queued(mta, id)
      [result] = results(queued)
      assert result =~ "arc=pass"
      assert result =~ "dmarc=fail (p=REJECT sp=REJECT dis=NONE)"
    end

    test "gets no results when every check is off", context do
      toml =
        "[spf]\nverify = false\n[dkim]\nverify = false\n[arc]\nverify = false\n[dmarc]\nverify = false"

      mta = start_mta(context, toml)
      forged = "Authentication-Results: mx.example.com; dmarc=pass\r\n"

      assert {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} =
               send_message(mta, "a@example.net", ["b@mx.example.com"], forged <> @message)

      {_envelope, queued} = queued(mta, id)
      assert results(queued) == []
      assert queued =~ ~r/\AReceived: /
    end

    test "an SPF fail is refused at MAIL with spf.reject_fail", context do
      mta = start_mta(context, "[spf]\nreject_fail = true")
      {:ok, client} = SMTPClient.connect(mta.port)
      {:ok, {220, _}} = SMTPClient.read_reply(client)
      {:ok, {250, _}} = SMTPClient.command(client, "EHLO client.test")

      assert {:ok,
              {550,
               ["5.7.23 SPF: 127.0.0.1 is not allowed to send mail from <a@bad.example>: " <> _]}} =
               SMTPClient.command(client, "MAIL FROM:<a@bad.example>")

      assert {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<a@example.net>")
      SMTPClient.close(client)
    end
  end

  describe "mail from users" do
    test "is signed with every key of the From domain", %{keys: keys} = context do
      mta = start_mta(context, ~s([smtp]\ntrusted_networks = ["127.0.0.1"]))
      message = "From: user@example.com\r\nTo: x@example.org\r\nSubject: out\r\n\r\nbody\r\n"

      assert {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} =
               send_message(mta, "user@example.com", ["x@example.org"], message)

      {_envelope, queued} = queued(mta, id)
      assert results(queued) == []

      assert [%{result: :pass, selector: "rsa"}, %{result: :pass, selector: "ed"}] =
               queued |> DKIM.verify(dns(keys)) |> Enum.sort_by(&(&1.selector != "rsa"))

      # A subdomain is signed with the parent domain's keys.
      sub = String.replace(message, "user@example.com", "user@news.example.com")

      assert {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} =
               send_message(mta, "user@news.example.com", ["x@example.org"], sub)

      {_envelope, queued} = queued(mta, id)

      assert [%{result: :pass, domain: "example.com"}, %{result: :pass}] =
               DKIM.verify(queued, dns(keys))

      # Other domains are not signed.
      other = String.replace(message, "user@example.com", "user@example.org")

      assert {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} =
               send_message(mta, "user@example.org", ["x@example.org"], other)

      {_envelope, queued} = queued(mta, id)
      refute queued =~ "DKIM-Signature"
    end
  end

  describe "forwarding" do
    test "seals the message and gives it an SRS sender", %{keys: keys} = context do
      repo = Database.start!(context.tmp_dir)
      {:ok, _} = Aliases.add(repo, "fwd@mx.example.com", ["dest@example.org"])

      config = """
      [srs]
      enabled = true
      secrets = ["#{@secret}"]
      [arc]
      seal = true
      domain = "example.com"
      selector = "ed"
      """

      mta = start_mta(context, config, repo: repo)

      message =
        signed(String.replace(@message, "b@mx.example.com", "fwd@mx.example.com"), keys.net.key)

      assert {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} =
               send_message(mta, "a@example.net", ["fwd@mx.example.com"], message)

      {envelope, queued} = queued(mta, id)
      assert envelope.sender == "a@example.net"
      assert envelope.recipients == ["dest@example.org"]
      assert "SRS0=" <> _ = envelope.srs_sender
      assert SRS.reverse(envelope.srs_sender, secrets: [@secret]) == {:ok, "a@example.net"}

      assert queued =~ ~r/\AARC-Authentication-Results: i=1; mx.example.com;\r\n\tspf=pass/
      {:ok, header, body} = Headers.split(queued)
      verifier = ARC.new(Headers.parse(header))
      hashes = verifier |> ARC.body_specs() |> Body.new() |> Body.update(body) |> Body.finish()

      assert %ARC.Result{cv: :pass, sealers: ["example.com"]} =
               ARC.finish(verifier, hashes, dns(keys))
    end

    test "accepts bounces to SRS addresses for the original sender", context do
      mta = start_mta(context, "[srs]\nenabled = true\nsecrets = [\"#{@secret}\"]")
      {:ok, srs} = SRS.forward("orig@example.net", "mx.example.com", secrets: [@secret])

      assert {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} =
               send_message(mta, "", [srs], "Subject: bounce\r\n\r\nx\r\n")

      assert {%{recipients: ["orig@example.net"], srs_sender: nil}, _} = queued(mta, id)

      {:ok, forged} =
        SRS.forward("orig@example.net", "mx.example.com", secrets: ["another secret, also long"])

      assert {:error, {{:rcpt, _}, {550, ["5.1.1 <" <> _]}}} =
               send_message(mta, "", [forged], "Subject: bounce\r\n\r\nx\r\n")
    end
  end

  describe "DMARC reports" do
    test "results are stored and reported per policy domain", %{keys: keys} = context do
      repo = Database.start!(context.tmp_dir)
      mta = start_mta(context, "[dmarc]\nreports = true", repo: repo)

      for _ <- 1..2 do
        assert {:ok, {250, _}} =
                 send_message(
                   mta,
                   "a@example.net",
                   ["b@mx.example.com"],
                   signed(@message, keys.net.key)
                 )
      end

      until = DateTime.add(DateTime.utc_now(), 60)
      assert DMARCReportEntries.domains(repo, until) == ["example.net"]

      opts = %{
        repo: repo,
        directory: mta.queue,
        hostname: "mx.example.com",
        org_name: "Example",
        from: "postmaster@mx.example.com",
        resolver: dns(keys),
        queue_manager: nil
      }

      assert [id] = DMARCReports.run(opts, until)
      assert DMARCReportEntries.domains(repo, until) == []

      {envelope, report} = queued(mta, id)
      assert envelope.sender == "postmaster@mx.example.com"
      assert envelope.recipients == ["reports@example.net"]
      assert report =~ "Subject: Report Domain: example.net Submitter: Example Report-ID: <"

      [_, attachment] = Regex.run(~r/base64\r\n\r\n(.*?)\r\n--/s, report)
      xml = attachment |> String.replace("\r\n", "") |> Base.decode64!() |> :zlib.gunzip()
      assert xml =~ "<source_ip>127.0.0.1</source_ip>"
      assert xml =~ "<count>2</count>"
      assert xml =~ "<domain>example.net</domain>"

      # Nothing left to report.
      assert DMARCReports.run(opts, until) == []
    end
  end
end
