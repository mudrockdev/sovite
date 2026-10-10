defmodule Sovite.Core.DMARCReportsTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.DMARCReports
  alias Sovite.Core.Repo.Tables.DMARCReportEntries
  alias Sovite.Queue.Spool
  alias Sovite.Test.{Database, FakeDNS, TelemetryForwarder}

  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    queue = Path.join(dir, "queue")
    :ok = Spool.init(queue)
    repo = Database.start!(dir)

    TelemetryForwarder.attach([
      [:sovite, :dmarc, :report, :sent],
      [:sovite, :dmarc, :report, :skipped]
    ])

    opts = %{
      repo: repo,
      directory: queue,
      hostname: "mx.example.org",
      org_name: "Example Org",
      from: "postmaster@mx.example.org",
      queue_manager: nil,
      resolver:
        FakeDNS.resolver(%{
          {"example.com._report._dmarc.reports.example.net", :txt} => ["v=DMARC1"]
        })
    }

    %{repo: repo, opts: opts, queue: queue}
  end

  defp add(repo, rua, extra \\ %{}) do
    attrs =
      Map.merge(
        %{
          policy_domain: "example.com",
          rua: rua,
          adkim: :relaxed,
          aspf: :strict,
          p: :reject,
          sp: :quarantine,
          pct: 100,
          source_ip: "192.0.2.1",
          header_from: "example.com",
          envelope_from: "example.com",
          disposition: :none,
          dkim: :pass,
          spf: :fail,
          spf_domain: "example.com",
          spf_scope: :mfrom,
          spf_result: :softfail,
          signatures: [%{domain: "example.com", selector: "s1", result: :pass}]
        },
        extra
      )

    {:ok, _} = DMARCReportEntries.add(repo, attrs)
  end

  defp later, do: DateTime.add(DateTime.utc_now(), 60)

  test "sends to authorized destinations only, within their size limits", context do
    rua = "mailto:a@example.com!10m,mailto:b@reports.example.net,mailto:c@other.example,https://x"
    add(context.repo, rua)

    add(context.repo, rua, %{
      source_ip: "2001:db8::1",
      override: :local_policy,
      disposition: :none
    })

    assert [id] = DMARCReports.run(context.opts, later())
    {:ok, envelope, _} = Spool.read(Spool.path(context.queue, :incoming, id))
    assert envelope.recipients == ["a@example.com", "b@reports.example.net"]

    assert_received {:telemetry, [:sovite, :dmarc, :report, :sent], %{messages: 2},
                     %{domain: "example.com", to: ["a@example.com", "b@reports.example.net"]}}

    # One byte is too little for any report.
    add(context.repo, "mailto:a@example.com!1")
    assert DMARCReports.run(context.opts, later()) == []

    assert_received {:telemetry, [:sovite, :dmarc, :report, :skipped], %{messages: 1},
                     %{reason: "report too large for its destinations"}}

    add(context.repo, "mailto:x@other.example,mailto:not-an-address")
    assert DMARCReports.run(context.opts, later()) == []

    assert_received {:telemetry, [:sovite, :dmarc, :report, :skipped], _,
                     %{reason: "no authorized destination"}}

    assert DMARCReportEntries.domains(context.repo, later()) == []
  end

  test "reports on a timer", context do
    add(context.repo, "mailto:a@example.com")
    opts = Map.to_list(Map.put(context.opts, :interval, 10))
    start_supervised!({DMARCReports, opts})

    assert_receive {:telemetry, [:sovite, :dmarc, :report, :sent], _, %{queue_id: id}}, 2_000
    assert {:ok, [^id]} = Spool.list(context.queue, :incoming)
  end

  test "builds the report mail" do
    opts = %{from: "postmaster@mx.example.org", hostname: "mx.example.org", org_name: "Org"}
    gzip = :zlib.gzip(String.duplicate("<xml/>", 100))

    message =
      opts
      |> DMARCReports.message("example.com", "id1", ["a@example.com"], "r.xml.gz", gzip)
      |> IO.iodata_to_binary()

    assert message =~ "To: <a@example.com>\r\n"
    assert message =~ "Subject: Report Domain: example.com Submitter: Org Report-ID: <id1>\r\n"
    assert message =~ ~s(Content-Disposition: attachment; filename="r.xml.gz"\r\n)
    assert message |> String.split("\r\n") |> Enum.all?(&(byte_size(&1) <= 998))
  end
end
