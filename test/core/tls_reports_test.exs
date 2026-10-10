defmodule Sovite.Core.TLSReportsTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Repo.Tables.TLSReportEntries
  alias Sovite.Core.TLSReports
  alias Sovite.DKIM.SigningKey
  alias Sovite.Queue.Spool
  alias Sovite.Test.{Database, FakeDNS, TelemetryForwarder}
  alias Sovite.TLS.MTASTS

  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    queue = Path.join(dir, "queue")
    :ok = Spool.init(queue)
    repo = Database.start!(dir)

    TelemetryForwarder.attach([
      [:sovite, :tls_rpt, :report, :sent],
      [:sovite, :tls_rpt, :report, :skipped],
      [:sovite, :tls_rpt, :report, :post_failed]
    ])

    {:ok, key} =
      :ed25519 |> SigningKey.generate(nil) |> SigningKey.from_pem("example.org", "s1")

    opts = %{
      repo: repo,
      directory: queue,
      hostname: "mx.example.org",
      org_name: "Example Org",
      from: "postmaster@example.org",
      contact_info: "postmaster@example.org",
      queue_manager: nil,
      post: [timeout: 2_000],
      mail_auth: %{signing_keys: %{"example.org" => [key]}, sign_opts: []},
      resolver:
        FakeDNS.resolver(%{
          {"_smtp._tls.example.net", :txt} => [
            "v=TLSRPTv1; rua=mailto:tlsrpt@example.net,https://127.0.0.1:1/tlsrpt"
          ]
        })
    }

    %{repo: repo, opts: opts, queue: queue}
  end

  defp add(repo, domain, attrs) do
    {:ok, _} =
      TLSReportEntries.add(
        repo,
        Map.merge(
          %{
            policy_domain: domain,
            policy_type: :sts,
            policy: MTASTS.policy_text(:enforce, ["*.example.net"], 86_400),
            mx_host: "mx1.example.net",
            receiving_ip: "192.0.2.25",
            sending_ip: "198.51.100.1"
          },
          attrs
        )
      )
  end

  defp attachment(path, loaded) do
    message =
      path
      |> Spool.stream_message(loaded.message_offset, loaded.message_size, loaded.prefix)
      |> Enum.join()

    [_, base64] =
      Regex.run(~r/Content-Transfer-Encoding: base64\r\n\r\n([A-Za-z0-9+\/=\r\n]+)/, message)

    base64 |> String.replace("\r\n", "") |> Base.decode64!()
  end

  defp wait_for_report(queue, timeout) do
    case Spool.list(queue, :incoming) do
      {:ok, [id]} ->
        id

      _ when timeout > 0 ->
        Process.sleep(20)
        wait_for_report(queue, timeout - 20)
    end
  end

  defp later, do: DateTime.add(DateTime.utc_now(), 60)

  test "sends one report per domain", context do
    add(context.repo, "example.net", %{})
    add(context.repo, "example.net", %{})

    add(context.repo, "example.net", %{
      result_type: :certificate_expired,
      failure_reason: "certificate expired",
      receiving_helo: "mx1"
    })

    add(context.repo, "example.net", %{
      policy_type: :tlsa,
      policy: "3 1 1 abcd",
      mx_host: "mx2.example.net"
    })

    # Domains without a TLS-RPT record get no report.
    add(context.repo, "other.example", %{policy_type: :no_policy_found, policy: nil})

    assert [id] = TLSReports.run(context.opts, later())

    assert_received {:telemetry, [:sovite, :tls_rpt, :report, :sent], %{sessions: 4},
                     %{domain: "example.net", to: ["tlsrpt@example.net"], urls: []}}

    # The https: destination refuses the connection.
    assert_received {:telemetry, [:sovite, :tls_rpt, :report, :post_failed], _,
                     %{domain: "example.net", url: "https://127.0.0.1:1/tlsrpt"}}

    assert_received {:telemetry, [:sovite, :tls_rpt, :report, :skipped], %{sessions: 1},
                     %{domain: "other.example", reason: "no TLS-RPT record"}}

    path = Spool.path(context.queue, :incoming, id)
    {:ok, loaded} = Spool.load(path)
    {:ok, report} = path |> attachment(loaded) |> :zlib.gunzip() |> JSON.decode()

    assert report["organization-name"] == "Example Org"
    [sts, tlsa] = report["policies"]

    assert sts["policy"]["policy-type"] == "sts"
    assert sts["policy"]["mx-host"] == ["*.example.net"]
    assert "mode: enforce" in sts["policy"]["policy-string"]

    assert sts["summary"] == %{
             "total-successful-session-count" => 2,
             "total-failure-session-count" => 1
           }

    assert [
             %{
               "result-type" => "certificate-expired",
               "receiving-mx-hostname" => "mx1.example.net",
               "receiving-mx-helo" => "mx1",
               "receiving-ip" => "192.0.2.25",
               "sending-mta-ip" => "198.51.100.1",
               "failed-session-count" => 1
             }
           ] = sts["failure-details"]

    assert tlsa["policy"] == %{
             "policy-type" => "tlsa",
             "policy-string" => ["3 1 1 abcd"],
             "policy-domain" => "example.net",
             "mx-host" => ["mx2.example.net"]
           }

    assert loaded.envelope.recipients == ["tlsrpt@example.net"]
    assert loaded.envelope.sender == "postmaster@example.org"
    assert loaded.prefix =~ "DKIM-Signature: "
    assert loaded.prefix =~ "d=example.org"

    {:ok, header} =
      Spool.read_headers(path, loaded.message_offset, loaded.message_size, prefix: loaded.prefix)

    assert header =~ "TLS-Report-Domain: example.net\r\n"

    assert TLSReportEntries.domains(context.repo, later()) == []
  end

  test "reports on a timer", context do
    add(context.repo, "example.net", %{})
    opts = context.opts |> Map.put(:interval, 10) |> Map.to_list()
    start_supervised!({TLSReports, opts})

    # Events are global: wait for this test's report, then its event.
    id = wait_for_report(context.queue, 3_000)
    assert_receive {:telemetry, [:sovite, :tls_rpt, :report, :sent], _, %{queue_id: ^id}}, 1_000
  end
end
