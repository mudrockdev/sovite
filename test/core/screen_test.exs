defmodule Sovite.Core.ScreenTest do
  # The anti-abuse checks end to end over TCP. Each client connects from
  # its own loopback address, so the DNS lists can tell them apart.
  use ExUnit.Case, async: true

  alias Sovite.Abuse.{Cache, RateLimit}
  alias Sovite.Core.{Config, Greylist, Outbound, Repo, Screen, SMTPHandler}
  alias Sovite.Core.Repo.Tables.GreylistEntries
  alias Sovite.Queue.Spool
  alias Sovite.Test.{Database, FakeDNS, SMTPClient, TelemetryForwarder}

  @moduletag :tmp_dir

  # 127.0.0.2 is on the block list, 127.0.0.3 on the allow list, and
  # spam.test on the domain list.
  @dns %{
    {"2.0.0.127.bl.test", :a} => [{127, 0, 0, 2}],
    {"3.0.0.127.wl.test", :a} => [{127, 0, 10, 2}],
    {"spam.test.dbl.test", :a} => [{127, 0, 1, 2}],
    {"spam.test", :mx} => [{10, "mx.spam.test"}]
  }

  @screen """
  [screen]
  greet_delay = "300ms"
  [[screen.dnsbl]]
  zone = "bl.test"
  weight = 2
  [[screen.dnsbl]]
  zone = "wl.test"
  weight = -2
  codes = ["127.0.[0..255].[1..3]"]
  [[screen.rhsbl]]
  zone = "dbl.test"
  """

  setup %{tmp_dir: dir} do
    TelemetryForwarder.attach([[:sovite, :screen, :rejected], [:sovite, :outbound, :suspended]])
    queue = Path.join(dir, "queue")
    :ok = Spool.init(queue)
    unique = System.unique_integer([:positive])
    names = for kind <- [:rate_limit, :cache, :suspensions], do: :"#{__MODULE__}.#{kind}#{unique}"
    [rate_limit, cache, suspensions] = names
    start_supervised!({RateLimit, name: rate_limit})
    start_supervised!({Cache, name: cache})
    start_supervised!({Cache, name: suspensions})

    %{
      queue: queue,
      repo: Database.start!(dir),
      rate_limit: rate_limit,
      cache: cache,
      suspensions: suspensions
    }
  end

  defp start_mta(context, toml) do
    {:ok, config} =
      Config.parse("""
      [server]
      hostname = "mx.example.com"
      [queue]
      directory = "#{context.queue}"
      [domains]
      local = ["example.com"]
      #{toml}
      """)

    handler =
      SMTPHandler.opts(config, nil,
        repo: context.repo,
        resolver: FakeDNS.resolver(@dns),
        screen: true,
        screen_cache: context.cache,
        rate_limit: context.rate_limit,
        outbound: Outbound.opts(config, context.rate_limit, context.suspensions)
      )

    server =
      start_supervised!(
        {Sovite.SMTP.Server,
         ip: {127, 0, 0, 1},
         port: 0,
         hostname: config.server.hostname,
         handler: {SMTPHandler, handler},
         max_errors: config.smtp.max_errors,
         tarpit_after: config.smtp.tarpit_after,
         tarpit_delay: config.smtp.tarpit_delay,
         forbid_unauth_pipelining: config.smtp.forbid_unauth_pipelining},
        id: make_ref()
      )

    {:ok, {_ip, port}} = Sovite.Listener.sockname(server)
    context |> Map.put(:port, port) |> Map.put(:config, config)
  end

  defp connect(mta, last_octet) do
    {:ok, client} = SMTPClient.connect(mta.port, {127, 0, 0, 1}, ip: {127, 0, 0, last_octet})
    on_exit(fn -> SMTPClient.close(client) end)
    client
  end

  defp command(client, line) do
    {:ok, {code, lines}} = SMTPClient.command(client, line)
    {code, List.last(lines)}
  end

  defp greeted(mta, last_octet) do
    client = connect(mta, last_octet)
    assert {:ok, {220, _}} = SMTPClient.read_reply(client)
    client
  end

  describe "the screen" do
    test "refuses a listed client before the greeting", context do
      mta = start_mta(context, @screen)
      client = connect(mta, 2)

      assert {:ok, {554, [text]}} = SMTPClient.read_reply(client)
      assert text == "5.7.1 Service unavailable; client [127.0.0.2] blocked: listed by bl.test"
      assert {:error, :closed} = SMTPClient.read_reply(client)

      assert_received {:telemetry, [:sovite, :screen, :rejected], %{score: 2},
                       %{remote_ip: {127, 0, 0, 2}, stage: :connect}}
    end

    test "refuses a client that talks before the greeting", context do
      mta = start_mta(context, @screen)
      client = connect(mta, 20)
      :ok = SMTPClient.send_raw(client, "EHLO bot.test\r\n")

      assert {:ok, {554, [text]}} = SMTPClient.read_reply(client)
      assert text =~ "blocked: talked before the greeting"
    end

    test "remembers a client that passed", context do
      mta = start_mta(context, @screen)
      greeted(mta, 21)
      assert {:ok, %{score: 0, checked: true}} = Cache.get(mta.cache, {:passed, {127, 0, 0, 21}})

      # No delay this time: talking at once is fine.
      client = connect(mta, 21)
      :ok = SMTPClient.send_raw(client, "EHLO client.test\r\n")
      assert {:ok, {220, _}} = SMTPClient.read_reply(client)
      assert {:ok, {250, _}} = SMTPClient.read_reply(client)
    end

    test "checks the EHLO name and the sender's domain in the domain lists", context do
      mta = start_mta(context, @screen)
      client = greeted(mta, 22)

      assert {554, "5.7.1 <spam.test>: Helo command rejected: listed by dbl.test"} =
               command(client, "EHLO spam.test")

      assert {250, _} = command(client, "EHLO client.test")

      assert {554, "5.7.1 <a@spam.test>: Sender address rejected: listed by dbl.test"} =
               command(client, "MAIL FROM:<a@spam.test>")

      assert {250, _} = command(client, "MAIL FROM:<a@good.test>")
    end

    test "allow-listed clients skip the domain lists and greylisting", context do
      mta = start_mta(context, @screen <> "[greylist]\nenabled = true")
      client = greeted(mta, 3)
      assert {250, _} = command(client, "EHLO spam.test")
      assert {250, _} = command(client, "MAIL FROM:<a@spam.test>")
      assert {250, _} = command(client, "RCPT TO:<user@example.com>")
    end

    test "is off for trusted clients", context do
      mta = start_mta(context, @screen <> ~s([smtp]\ntrusted_networks = ["127.0.0.2"]))
      client = greeted(mta, 2)
      assert {250, _} = command(client, "EHLO spam.test")
    end
  end

  describe "rate limits" do
    test "count connections, messages, and recipients per client", context do
      mta =
        start_mta(context, """
        [rate_limit]
        client_connections = "2/1h"
        client_messages = "2/1h"
        client_recipients = "3/1h"
        """)

      client = greeted(mta, 30)
      assert {250, _} = command(client, "EHLO client.test")
      assert {250, _} = command(client, "MAIL FROM:<a@good.test>")
      assert {250, _} = command(client, "RCPT TO:<a@example.com>")
      assert {250, _} = command(client, "RCPT TO:<b@example.com>")
      assert {250, _} = command(client, "RSET")
      assert {250, _} = command(client, "MAIL FROM:<a@good.test>")
      assert {250, _} = command(client, "RCPT TO:<c@example.com>")

      assert {450, "4.7.1 Error: too many recipients from [127.0.0.30], try again later"} =
               command(client, "RCPT TO:<d@example.com>")

      assert {250, _} = command(client, "RSET")

      assert {450, "4.7.1 Error: too many messages from [127.0.0.30], try again later"} =
               command(client, "MAIL FROM:<a@good.test>")

      greeted(mta, 30)
      client = connect(mta, 30)

      assert {:ok, {421, ["4.7.0 mx.example.com Error: too many connections from your address"]}} =
               SMTPClient.read_reply(client)

      # Another client has its own counts.
      greeted(mta, 31)
    end
  end

  describe "greylisting" do
    test "defers a new triplet until the client retries after the delay", context do
      mta = start_mta(context, "[greylist]\nenabled = true\ndelay = \"2s\"")
      client = greeted(mta, 40)
      assert {250, _} = command(client, "EHLO client.test")
      assert {250, _} = command(client, "MAIL FROM:<news-1234@good.test>")

      assert {450, "4.7.1 <user@example.com>: Recipient address rejected: Greylisted" <> _} =
               command(client, "RCPT TO:<user@example.com>")

      # Too early. Times are kept in whole seconds.
      assert {450, _} = command(client, "RCPT TO:<user@example.com>")

      Process.sleep(2_100)
      assert {250, _} = command(client, "RCPT TO:<user@example.com>")

      # Passed: another host of the same network, with another bounce
      # address, passes at once.
      client = greeted(mta, 41)
      assert {250, _} = command(client, "EHLO client.test")
      assert {250, _} = command(client, "MAIL FROM:<news-5678@good.test>")
      assert {250, _} = command(client, "RCPT TO:<user@example.com>")

      assert [
               %{
                 client_network: "127.0.0.0/24",
                 sender: "news-#@good.test",
                 passed_at: %DateTime{}
               }
             ] =
               GreylistEntries.list(mta.repo)
    end

    test "a deferred recipient is not delivered with the others", context do
      mta =
        start_mta(
          context,
          @screen <> "[greylist]\nenabled = true\n[rate_limit]\nclient_recipients = \"1/1h\""
        )

      # Allow-listed, so not greylisted; the second recipient is over
      # the limit.
      client = greeted(mta, 3)
      assert {250, _} = command(client, "EHLO client.test")
      assert {250, _} = command(client, "MAIL FROM:<a@good.test>")
      assert {250, _} = command(client, "RCPT TO:<one@example.com>")
      assert {450, _} = command(client, "RCPT TO:<two@example.com>")
      assert {354, _} = command(client, "DATA")

      {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} =
        SMTPClient.send_data(client, "Subject: x\r\n\r\nx\r\n")

      {:ok, loaded} = Spool.load(Spool.path(mta.queue, :incoming, id))
      assert loaded.envelope.recipients == ["one@example.com"]
    end

    test "defers concurrent first attempts, and stores the triplet once", context do
      opts = %{repo: context.repo, delay: 60_000, retry_window: 86_400_000, max_age: 86_400_000}

      results =
        1..10
        |> Enum.map(fn _ ->
          Task.async(fn -> Greylist.check(opts, {192, 0, 2, 1}, "a@b.test", "c@d.test") end)
        end)
        |> Enum.map(&Task.await/1)

      assert Enum.all?(results, &match?({:defer, _}, &1))
      assert [_] = GreylistEntries.list(context.repo)
      assert GreylistEntries.counts(context.repo) == %{total: 1, passed: 0}
    end

    test "the cleaner deletes expired entries", context do
      opts = %{repo: context.repo, delay: 1, retry_window: 2, max_age: 3}
      {:defer, _} = Greylist.check(opts, {192, 0, 2, 1}, "a@b.test", "c@d.test")
      start_supervised!({Greylist, repo: context.repo, interval: 10})
      Process.sleep(1_100)
      assert GreylistEntries.list(context.repo) == []
      assert GreylistEntries.delete_all(context.repo) == 0
    end

    @tag :capture_log
    test "lets mail through when the database fails" do
      repo = {Repo.module(:sqlite), :"#{__MODULE__}.missing"}
      opts = %{repo: repo, delay: 1, retry_window: 2, max_age: 3}
      assert Greylist.check(opts, {192, 0, 2, 1}, "a@b.test", "c@d.test") == :pass
    end
  end

  describe "tarpit" do
    test "delays error replies", context do
      mta = start_mta(context, "[smtp]\ntarpit_after = 2\ntarpit_delay = \"200ms\"")
      client = greeted(mta, 50)

      {time, {500, _}} = :timer.tc(fn -> command(client, "FOO") end, :millisecond)
      assert time < 150
      {time, {500, _}} = :timer.tc(fn -> command(client, "FOO") end, :millisecond)
      assert time >= 200
    end
  end

  describe "replay corpus" do
    # Recorded behaviour of spam bots and of real mail servers, replayed
    # at once against one server with the defaults and the screen,
    # greylisting, and a few restrictions on. Every bot must be refused
    # before DATA, and every real server must get its message through.
    # The first line continues [domains] of start_mta/2.
    @corpus_config ~s(local_recipients = ["user@example.com"]\n) <>
                     @screen <>
                     """
                     [greylist]
                     enabled = true
                     delay = "1s"
                     [smtp]
                     tarpit_delay = "50ms"
                     [restrictions]
                     helo = ["reject_forged_helo", "require_fqdn_helo"]
                     """

    @message "Subject: hello\r\n\r\nHi.\r\n"

    defp bots do
      [
        # On a block list, otherwise well behaved.
        listed: {2, &polite(&1, "listed@good.test", retry: true)},
        # Sends the whole transaction without waiting for the greeting.
        early_talker:
          {60,
           raw(fn client ->
             SMTPClient.send_raw(client, "EHLO bot.test\r\nMAIL FROM:<early@good.test>\r\n")
             read_all(client)
           end)},
        # Waits for the greeting, then pipelines without PIPELINING.
        pipelining:
          {61,
           raw(fn client ->
             {:ok, {220, _}} = SMTPClient.read_reply(client)
             SMTPClient.send_raw(client, "HELO bot.test\r\nMAIL FROM:<pipeliner@good.test>\r\n")
             read_all(client)
           end)},
        # Sends the message right after DATA, without waiting for 354.
        data_pipelining:
          {62,
           raw(fn client ->
             {:ok, {220, _}} = SMTPClient.read_reply(client)
             {:ok, {250, _}} = SMTPClient.command(client, "EHLO bot.test")

             SMTPClient.send_raw(
               client,
               "MAIL FROM:<smuggler@good.test>\r\nRCPT TO:<user@example.com>\r\nDATA\r\n" <>
                 @message
             )

             read_all(client)
           end)},
        # A sender domain on the domain list.
        rhsbl_sender: {63, &polite(&1, "rhsbl@spam.test", retry: true)},
        # Claims to be this server.
        forged_helo: {64, &polite(&1, "forger@good.test", helo: "mx.example.com", retry: true)},
        # Not even SMTP.
        http:
          {65,
           raw(fn client ->
             {:ok, {220, _}} = SMTPClient.read_reply(client)
             SMTPClient.send_raw(client, "GET / HTTP/1.1\r\nHost: mx.example.com\r\n\r\n")
             read_all(client)
           end)},
        # Guesses recipients.
        dictionary:
          {66,
           raw(fn client ->
             {:ok, {220, _}} = SMTPClient.read_reply(client)
             {:ok, {250, _}} = SMTPClient.command(client, "EHLO bot.test")
             {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<guesser@good.test>")

             for name <- ~w(admin info sales test webmaster root john mary bob alice),
                 do: SMTPClient.command(client, "RCPT TO:<#{name}@example.com>")

             SMTPClient.command(client, "DATA")
             read_all(client)
           end)},
        # Greylisted, and never comes back.
        no_retry: {67, &polite(&1, "quitter@good.test", retry: false)}
      ]
    end

    defp real_servers do
      [
        # Greylisted, retries later.
        mta: {70, &polite(&1, "alice@good.test", retry: true)},
        # On the allow list: no greylisting.
        allow_listed: {3, &polite(&1, "bob@good.test", retry: false)},
        # Pipelines as RFC 2920 allows, and retries.
        pipelining_mta: {71, &pipelined(&1, "carol@good.test")}
      ]
    end

    # A well-behaved client: EHLO, MAIL, RCPT, DATA, with one retry on a
    # temporary failure (as from greylisting), over a new connection.
    defp polite(connect, sender, opts) do
      client = connect.()
      helo = Keyword.get(opts, :helo, "client.good.test")

      result =
        with {:ok, {220, _}} <- SMTPClient.read_reply(client),
             {:ok, {250, _}} <- SMTPClient.command(client, "EHLO #{helo}"),
             {:ok, {250, _}} <- SMTPClient.command(client, "MAIL FROM:<#{sender}>"),
             {:ok, {250, _}} <- SMTPClient.command(client, "RCPT TO:<user@example.com>"),
             {:ok, {354, _}} <- SMTPClient.command(client, "DATA") do
          SMTPClient.send_data(client, @message)
        end

      retry = Keyword.get(opts, :retry, false)

      case result do
        {:ok, {code, _}} when code in 400..499 and retry ->
          SMTPClient.close(client)
          Process.sleep(2_100)
          polite(connect, sender, Keyword.put(opts, :retry, false))

        result ->
          result
      end
    end

    defp pipelined(connect, sender, retry \\ true) do
      client = connect.()
      {:ok, {220, _}} = SMTPClient.read_reply(client)
      {:ok, {250, _}} = SMTPClient.command(client, "EHLO client.good.test")

      :ok =
        SMTPClient.send_raw(
          client,
          "MAIL FROM:<#{sender}>\r\nRCPT TO:<user@example.com>\r\nDATA\r\n"
        )

      replies = for _ <- 1..3, do: SMTPClient.read_reply(client)

      case replies do
        [{:ok, {250, _}}, {:ok, {250, _}}, {:ok, {354, _}}] ->
          SMTPClient.send_data(client, @message)

        [_, {:ok, {450, _}}, _] when retry ->
          SMTPClient.close(client)
          Process.sleep(2_100)
          pipelined(connect, sender, false)

        other ->
          {:error, other}
      end
    end

    defp raw(script), do: fn connect -> script.(connect.()) end

    # Every reply until the server closes the connection.
    defp read_all(client, acc \\ []) do
      case SMTPClient.read_reply(client, 2_000) do
        {:ok, reply} -> read_all(client, [reply | acc])
        {:error, _} -> {:closed, Enum.reverse(acc)}
      end
    end

    defp delivered?({:ok, {250, ["2.0.0 Ok: queued as " <> _]}}), do: true
    defp delivered?(_result), do: false

    defp got_354?({:closed, replies}), do: Enum.any?(replies, &match?({354, _}, &1))
    defp got_354?(result), do: delivered?(result)

    test "refuses every bot before DATA and lets every real server through", context do
      mta = start_mta(context, @corpus_config)

      results =
        (bots() ++ real_servers())
        |> Enum.map(fn {name, {octet, script}} ->
          connect = fn ->
            {:ok, client} =
              SMTPClient.connect(mta.port, {127, 0, 0, 1}, ip: {127, 0, 0, octet})

            client
          end

          {name, Task.async(fn -> script.(connect) end)}
        end)
        |> Map.new(fn {name, task} -> {name, Task.await(task, 15_000)} end)

      accepted_bots = for {name, _} <- bots(), got_354?(results[name]), do: name
      refused_servers = for {name, _} <- real_servers(), not delivered?(results[name]), do: name

      assert accepted_bots == [], "bots got to DATA: #{inspect(Map.take(results, accepted_bots))}"

      assert refused_servers == [],
             "real servers refused: #{inspect(Map.take(results, refused_servers))}"

      assert {:ok, ids} = Spool.list(mta.queue, :incoming)
      assert length(ids) == length(real_servers())
    end
  end

  describe "outbound" do
    defp user_state(context, toml) do
      {:ok, config} = Config.parse("[server]\nhostname = \"mx.example.com\"\n" <> toml)

      screen =
        Screen.opts(config,
          screen: false,
          rate_limit: context.rate_limit,
          outbound: Outbound.opts(config, context.rate_limit, context.suspensions)
        )

      %{
        screen: screen,
        score: Screen.new(),
        trusted: false,
        identity: "Alice@example.com",
        hostname: "mx.example.com",
        connection: %{remote_ip: {192, 0, 2, 1}, session_id: "S1"}
      }
    end

    test "user rate limits are sending quotas", context do
      state =
        user_state(context, "[rate_limit]\nuser_messages = \"1/1d\"\nuser_recipients = \"1/1d\"")

      assert {:ok, state} = Screen.mail("alice@example.com", state)
      assert {:ok, state} = Screen.rcpt("bob@example.net", state)

      assert {:reply, %{code: 450, lines: ["Sending limit exceeded for Alice@example.com" <> _]},
              _} =
               Screen.rcpt("carol@example.net", state)

      assert {:reply, %{code: 450}, _} = Screen.mail("alice@example.com", state)
    end

    test "suspends a user whose mail fails too often", context do
      state = user_state(context, "[outbound]\nmin_failures = 5\nmax_failure_percent = 50")
      opts = state.screen.outbound

      Outbound.sent(opts, "alice@example.com", 10)
      Outbound.failed(opts, "alice@example.com", 4)
      assert {:ok, _} = Screen.mail("alice@example.com", state)

      Outbound.failed(opts, "ALICE@example.com", 1)

      assert_received {:telemetry, [:sovite, :outbound, :suspended], %{sent: 10, failed: 5},
                       %{user: "alice@example.com"}}

      assert {:reply, %{code: 550, enhanced: "5.7.1"}, _} =
               Screen.mail("alice@example.com", state)

      # Others are not affected; nil options and users are ignored.
      assert {:ok, _} = Screen.mail("bob@example.com", %{state | identity: "bob@example.com"})
      assert Outbound.failed(nil, "alice@example.com", 1) == :ok
      assert Outbound.sent(opts, nil, 1) == :ok
    end
  end
end
