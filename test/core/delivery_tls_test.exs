defmodule Sovite.Core.DeliveryTLSTest do
  # Outbound TLS levels and relay host authentication, end to end.
  use ExUnit.Case, async: true

  alias Sovite.Core.{Config, QueueManager}
  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.Test.{Certs, FakeDNS, FakeMTA, TelemetryForwarder}

  @moduletag :tmp_dir
  @moduletag :capture_log
  @timeout 5_000

  setup_all do
    ca = Certs.ca()
    good = Certs.issue(ca, names: ["mx.example.net"])
    wrong = Certs.issue(ca, names: ["other.example"])

    %{
      ca: ca,
      good: good,
      good_tls: Sovite.TLS.server_options(certs_keys: [Certs.certs_keys(good)]),
      wrong_tls: Sovite.TLS.server_options(certs_keys: [Certs.certs_keys(wrong)])
    }
  end

  setup %{tmp_dir: dir} do
    TelemetryForwarder.attach([
      [:sovite, :queue, :message, :removed],
      [:sovite, :smtp, :client, :delivery, :stop]
    ])

    :ok = Spool.init(dir)
    %{dir: dir}
  end

  defp spki_sha256(der) do
    {:Certificate, tbs, _, _} = :public_key.pkix_decode_cert(der, :plain)
    :crypto.hash(:sha256, :public_key.der_encode(:SubjectPublicKeyInfo, elem(tbs, 7)))
  end

  # `dns` gets the fake MTA's port, since TLSA names include it.
  defp start(context, mta_opts, manager_opts, dns \\ fn _port -> %{} end) do
    mta = start_supervised!({FakeMTA, [owner: self()] ++ mta_opts}, id: make_ref())
    {extra_config, manager_opts} = Keyword.pop(manager_opts, :config, "")

    {:ok, config} =
      Config.parse("""
      [server]
      hostname = "mx.example.org"
      [queue]
      directory = "#{context.dir}"
      min_backoff = "1h"
      max_backoff = "1h"
      #{extra_config}
      """)

    base_dns = %{
      {"example.net", :mx} => [{10, "mx.example.net"}],
      {"mx.example.net", :a} => [{127, 0, 0, 1}]
    }

    opts =
      QueueManager.opts(config) ++
        [
          name: nil,
          resolver: FakeDNS.resolver(Map.merge(base_dns, dns.(FakeMTA.port(mta)))),
          port: FakeMTA.port(mta),
          client: [command_timeout: 2_000, data_end_timeout: 2_000, tls_timeout: 2_000],
          tls_cacerts: [context.ca.cert]
        ] ++ manager_opts

    manager = start_supervised!({QueueManager, opts}, id: make_ref())
    %{mta: mta, manager: manager, port: FakeMTA.port(mta)}
  end

  defp send_mail(context, %{manager: manager}, recipient \\ "bob@example.net") do
    envelope = %Envelope{
      queue_id: ID.generate(),
      sender: "alice@example.org",
      recipients: [recipient],
      received_at: DateTime.utc_now()
    }

    {:ok, writer} = Spool.open(context.dir, envelope)
    {:ok, writer} = Spool.write(writer, "Subject: hi\r\n\r\nbody\r\n")
    {:ok, _, _} = Spool.commit(writer)
    QueueManager.notify(manager, envelope.queue_id)
    envelope.queue_id
  end

  defp assert_delivered(id) do
    assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                    %{queue_id: ^id, status: :delivered} = meta},
                   @timeout

    meta
  end

  defp assert_deferred(id) do
    assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                    %{queue_id: ^id, status: :deferred, reply: reply}},
                   @timeout

    reply
  end

  defp assert_message(%{mta: mta}) do
    assert_receive {:fake_mta, ^mta, {:message, message}}, @timeout
    message
  end

  test "may: uses STARTTLS when offered", context do
    env = start(context, [tls: context.wrong_tls], [])
    id = send_mail(context, env)
    assert %{tls: "TLSv1.3 with cipher " <> _} = assert_delivered(id)
    assert %{tls: %{protocol: "TLSv1.3", sni: "mx.example.net"}} = assert_message(env)
  end

  test "may: delivers in plaintext without STARTTLS, or after a failed handshake", context do
    env = start(context, [], [])
    id = send_mail(context, env)
    assert %{tls: nil} = assert_delivered(id)

    # A server that demands a client certificate fails every handshake.
    broken =
      context.good_tls ++
        [verify: :verify_peer, fail_if_no_peer_cert: true, cacerts: [context.ca.cert]]

    env = start(context, [tls: broken], [])
    id = send_mail(context, env)
    assert %{tls: nil} = assert_delivered(id)
    assert %{tls: nil} = assert_message(env)
  end

  test "none: never starts TLS", context do
    env = start(context, [tls: context.good_tls], tls: :none)
    id = send_mail(context, env)
    assert %{tls: nil} = assert_delivered(id)
  end

  test "encrypt: requires STARTTLS but not a valid certificate", context do
    env = start(context, [], tls: :encrypt)
    id = send_mail(context, env)

    assert assert_deferred(id) =~
             "TLS is required, but was not offered by host mx.example.net[127.0.0.1]"

    env = start(context, [tls: context.wrong_tls], tls: :encrypt)
    id = send_mail(context, env)
    assert %{tls: "TLS" <> _} = assert_delivered(id)
  end

  test "verify: requires a certificate valid for the MX host", context do
    env = start(context, [tls: context.good_tls], tls: :verify)
    assert %{tls: "TLS" <> _} = assert_delivered(send_mail(context, env))

    env = start(context, [tls: context.wrong_tls], tls: :verify)

    assert assert_deferred(send_mail(context, env)) =~
             "TLS (verify) with host mx.example.net[127.0.0.1] failed"
  end

  test "the policy map overrides the default per domain", context do
    env = start(context, [], tls: :may, tls_policy: %{"example.net" => :encrypt})
    assert assert_deferred(send_mail(context, env)) =~ "TLS is required"
  end

  describe "dane" do
    defp tlsa(records), do: fn port -> %{{"_#{port}._tcp.mx.example.net", :tlsa} => records} end

    test "requires a matching certificate when TLSA records are authenticated", context do
      matching = [{3, 1, 1, spki_sha256(context.good.cert)}]
      other = [{3, 1, 1, :crypto.hash(:sha256, "other key")}]

      env = start(context, [tls: context.good_tls], [tls: :dane], tlsa({:secure, matching}))
      assert %{tls: "TLS" <> _} = assert_delivered(send_mail(context, env))

      env = start(context, [tls: context.good_tls], [tls: :dane], tlsa({:secure, other}))

      assert assert_deferred(send_mail(context, env)) =~
               "TLS (dane) with host mx.example.net[127.0.0.1] failed"
    end

    test "falls back to opportunistic TLS without authenticated records", context do
      other = [{3, 1, 1, :crypto.hash(:sha256, "other key")}]

      for dns <- [
            tlsa(other),
            tlsa({:secure, [{1, 1, 1, :crypto.hash(:sha256, "pkix")}]}),
            fn _ -> %{} end
          ] do
        env = start(context, [tls: context.good_tls], [tls: :dane], dns)
        assert %{tls: "TLS" <> _} = assert_delivered(send_mail(context, env))
      end
    end

    test "skips a host whose TLSA lookup fails", context do
      env = start(context, [tls: context.good_tls], [tls: :dane], tlsa({:error, :servfail}))

      assert assert_deferred(send_mail(context, env)) =~
               "TLSA lookup for mx.example.net failed: servfail"
    end
  end

  describe "relay host" do
    test "authenticates over TLS", context do
      mta =
        start_supervised!(
          {FakeMTA, owner: self(), tls: context.good_tls, auth: %{"alice" => "secret"}},
          id: :relay
        )

      port = FakeMTA.port(mta)

      env =
        start(context, [],
          config: """
          [delivery]
          relayhost = "[127.0.0.1]:#{port}"
          relayhost_username = "alice"
          relayhost_password = "secret"
          """
        )

      id = send_mail(context, env, "bob@anywhere.example")
      assert_delivered(id)
      assert_receive {:fake_mta, ^mta, {:message, %{auth: "alice", tls: %{}}}}, @timeout
    end

    test "never sends the password without TLS", context do
      mta = start_supervised!({FakeMTA, owner: self(), auth: %{"alice" => "secret"}}, id: :relay)
      port = FakeMTA.port(mta)

      env =
        start(context, [],
          config: """
          [delivery]
          relayhost = "[127.0.0.1]:#{port}"
          relayhost_username = "alice"
          relayhost_password = "secret"
          """
        )

      assert assert_deferred(send_mail(context, env, "bob@anywhere.example")) =~
               "will not send credentials"
    end

    test "defers on bad credentials", context do
      mta =
        start_supervised!(
          {FakeMTA, owner: self(), tls: context.good_tls, auth: %{"alice" => "secret"}},
          id: :relay
        )

      port = FakeMTA.port(mta)

      env =
        start(context, [],
          config: """
          [delivery]
          relayhost = "[127.0.0.1]:#{port}"
          relayhost_username = "alice"
          relayhost_password = "wrong"
          """
        )

      assert assert_deferred(send_mail(context, env, "bob@anywhere.example")) =~
               "authentication failed"
    end
  end
end
