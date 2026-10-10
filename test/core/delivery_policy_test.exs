defmodule Sovite.Core.DeliveryPolicyTest do
  # Recipient TLS policies end to end: MTA-STS, DANE over MTA-STS,
  # REQUIRETLS, TLS-Required: No, and the TLS-RPT records of sessions.
  use ExUnit.Case, async: true

  alias Sovite.Core.{Config, MTASTS, QueueManager}
  alias Sovite.Core.Repo.Tables.{MTASTSPolicies, TLSReportEntries}
  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.Test.{Certs, Database, FakeDNS, FakeMTA, TelemetryForwarder}

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
    TelemetryForwarder.attach([[:sovite, :smtp, :client, :delivery, :stop]])
    queue = Path.join(dir, "queue")
    :ok = Spool.init(queue)
    %{dir: queue, repo: Database.start!(dir)}
  end

  defp spki_sha256(der) do
    {:Certificate, tbs, _, _} = :public_key.pkix_decode_cert(der, :plain)
    :crypto.hash(:sha256, :public_key.der_encode(:SubjectPublicKeyInfo, elem(tbs, 7)))
  end

  # `policy` is the cached MTA-STS policy of example.net, if any; `dns`
  # adds records, given the fake MTA's port.
  defp start(context, mta_opts, opts \\ []) do
    mta = start_supervised!({FakeMTA, [owner: self()] ++ mta_opts}, id: make_ref())
    port = FakeMTA.port(mta)

    {:ok, config} =
      Config.parse("""
      [server]
      hostname = "mx.example.org"
      [queue]
      directory = "#{context.dir}"
      min_backoff = "1h"
      max_backoff = "1h"
      """)

    dns =
      Map.merge(
        %{
          {"example.net", :mx} => [{10, "mx.example.net"}],
          {"mx.example.net", :a} => [{127, 0, 0, 1}]
        },
        Keyword.get(opts, :dns, fn _port -> %{} end).(port)
      )

    dns =
      case Keyword.get(opts, :policy) do
        nil ->
          dns

        {mode, mx} ->
          text = Sovite.TLS.MTASTS.policy_text(mode, mx, 86_400)
          now = DateTime.truncate(DateTime.utc_now(), :second)

          {:ok, _} =
            MTASTSPolicies.put(context.repo, %{
              domain: "example.net",
              policy_id: "1",
              mode: mode,
              max_age: 86_400,
              policy: text,
              fetched_at: now,
              expires_at: DateTime.add(now, 86_400)
            })

          Map.put(dns, {"_mta-sts.example.net", :txt}, ["v=STSv1; id=1"])
      end

    resolver = FakeDNS.resolver(dns)
    mta_sts = start_supervised!({MTASTS, repo: context.repo, resolver: resolver}, id: make_ref())

    manager_opts =
      QueueManager.opts(config) ++
        [
          name: nil,
          resolver: resolver,
          port: port,
          client: [command_timeout: 2_000, data_end_timeout: 2_000, tls_timeout: 2_000],
          tls_cacerts: [context.ca.cert],
          mta_sts: mta_sts,
          tls_reports: context.repo
        ]

    manager = start_supervised!({QueueManager, manager_opts}, id: make_ref())
    %{mta: mta, manager: manager}
  end

  defp send_mail(context, %{manager: manager}, opts \\ []) do
    envelope = %Envelope{
      queue_id: ID.generate(),
      sender: "alice@example.org",
      recipients: ["bob@example.net"],
      received_at: DateTime.utc_now(),
      requiretls: Keyword.get(opts, :requiretls, false)
    }

    {:ok, writer} = Spool.open(context.dir, envelope)

    {:ok, writer} =
      Spool.write(writer, Keyword.get(opts, :header, "") <> "Subject: hi\r\n\r\nbody\r\n")

    {:ok, _, _} = Spool.commit(writer)
    QueueManager.notify(manager, envelope.queue_id)
    envelope.queue_id
  end

  defp result(id) do
    assert_receive {:telemetry, [:sovite, :smtp, :client, :delivery, :stop], _,
                    %{queue_id: ^id} = meta},
                   @timeout

    meta
  end

  defp reports(context),
    do: TLSReportEntries.list(context.repo, "example.net", DateTime.add(DateTime.utc_now(), 60))

  describe "MTA-STS" do
    test "enforce requires a certificate valid for a listed MX host", context do
      env = start(context, [tls: context.good_tls], policy: {:enforce, ["*.example.net"]})
      assert %{status: :delivered, tls: "TLS" <> _} = result(send_mail(context, env))

      assert [%{policy_type: :sts, mx_host: "mx.example.net", result_type: nil, policy: policy}] =
               reports(context)

      assert policy =~ "mx: *.example.net"
    end

    test "enforce defers on a bad certificate, or an MX host not in the policy", context do
      env = start(context, [tls: context.wrong_tls], policy: {:enforce, ["mx.example.net"]})
      assert %{status: :deferred, reply: reply} = result(send_mail(context, env))
      assert reply =~ "TLS (mta-sts) with host mx.example.net[127.0.0.1] failed"

      assert [%{result_type: :certificate_host_mismatch, receiving_ip: "127.0.0.1"}] =
               reports(context)

      env = start(context, [tls: context.good_tls], policy: {:enforce, ["mx2.example.net"]})
      assert %{status: :deferred, reply: reply} = result(send_mail(context, env))
      assert reply =~ "MX host mx.example.net is not allowed by the MTA-STS policy of example.net"
    end

    test "testing delivers anyway, and reports the problem", context do
      env = start(context, [tls: context.wrong_tls], policy: {:testing, ["mx.example.net"]})
      assert %{status: :delivered, tls: "TLS" <> _} = result(send_mail(context, env))
      assert [%{policy_type: :sts, result_type: :certificate_host_mismatch}] = reports(context)
    end

    test "TLS-Required: No ignores the policy", context do
      env = start(context, [tls: context.wrong_tls], policy: {:enforce, ["mx.example.net"]})
      id = send_mail(context, env, header: "TLS-Required: No\r\n")
      assert %{status: :delivered} = result(id)
    end

    test "DANE wins over MTA-STS", context do
      tlsa = fn port ->
        %{
          {"example.net", :mx} => {:secure, [{10, "mx.example.net"}]},
          {"mx.example.net", :a} => {:secure, [{127, 0, 0, 1}]},
          {"mx.example.net", :aaaa} => {:secure, []},
          {"_#{port}._tcp.mx.example.net", :tlsa} =>
            {:secure, [{3, 1, 1, spki_sha256(context.good.cert)}]}
        }
      end

      # The policy does not list the host, but its TLSA records match.
      env =
        start(context, [tls: context.good_tls],
          policy: {:enforce, ["mx2.example.net"]},
          dns: tlsa
        )

      assert %{status: :delivered} = result(send_mail(context, env))
      assert [%{policy_type: :tlsa, policy: "3 1 1 " <> _}] = reports(context)
    end

    test "reports failed TLSA lookups", context do
      dns = fn port ->
        %{
          {"example.net", :mx} => {:secure, [{10, "mx.example.net"}]},
          {"mx.example.net", :a} => {:secure, [{127, 0, 0, 1}]},
          {"mx.example.net", :aaaa} => {:secure, []},
          {"_#{port}._tcp.mx.example.net", :tlsa} => {:error, :servfail}
        }
      end

      env = start(context, [tls: context.good_tls], dns: dns)
      assert %{status: :deferred} = result(send_mail(context, env))
      assert [%{policy_type: :tlsa, result_type: :dnssec_invalid}] = reports(context)
    end

    test "reports sessions without a policy, and plaintext ones", context do
      env = start(context, [])
      assert %{status: :delivered, tls: nil} = result(send_mail(context, env))

      assert [%{policy_type: :no_policy_found, result_type: :starttls_not_supported}] =
               reports(context)
    end
  end

  describe "REQUIRETLS" do
    @extensions ["PIPELINING", "8BITMIME", "REQUIRETLS"]

    test "is sent to a verified server that supports it", context do
      env =
        start(context, [tls: context.good_tls, extensions: @extensions],
          policy: {:testing, ["mx.example.net"]}
        )

      assert %{status: :delivered} = result(send_mail(context, env, requiretls: true))
      assert_receive {:fake_mta, _, {:message, %{mail_args: args}}}, @timeout
      assert args =~ " REQUIRETLS"
    end

    test "fails without a policy, a supporting server, or a valid certificate", context do
      env = start(context, tls: context.good_tls, extensions: @extensions)
      assert %{status: :failed, reply: reply} = result(send_mail(context, env, requiretls: true))
      assert reply =~ "not covered by a DANE or MTA-STS policy"

      env = start(context, [tls: context.good_tls], policy: {:enforce, ["mx.example.net"]})
      assert %{status: :failed, reply: reply} = result(send_mail(context, env, requiretls: true))
      assert reply =~ "REQUIRETLS support required"

      env =
        start(context, [tls: context.wrong_tls, extensions: @extensions],
          policy: {:testing, ["mx.example.net"]}
        )

      assert %{status: :deferred, reply: reply} =
               result(send_mail(context, env, requiretls: true))

      assert reply =~ "TLS (mta-sts)"
    end
  end
end
