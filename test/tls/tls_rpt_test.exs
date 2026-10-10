defmodule Sovite.TLS.TLSRPTTest do
  use ExUnit.Case, async: true

  alias Sovite.Test.{FakeDNS, FakeHTTP}
  alias Sovite.TLS.TLSRPT

  doctest TLSRPT

  describe "parse_record/1" do
    test "returns the mailto: and https: destinations in order" do
      record = "v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://reports.example.com/v1"

      assert TLSRPT.parse_record([record]) ==
               {:ok, ["mailto:tlsrpt@example.com", "https://reports.example.com/v1"]}
    end

    test "allows whitespace around delimiters and a trailing semicolon" do
      record = "v=TLSRPTv1 ;\trua=mailto:a@example.com ,  https://r.example.com/ ; "

      assert TLSRPT.parse_record([record]) ==
               {:ok, ["mailto:a@example.com", "https://r.example.com/"]}
    end

    test "ignores other TXT records and unknown fields" do
      txts = [
        "v=spf1 -all",
        "v=TLSRPTv10; rua=mailto:wrong@example.com",
        "v=TLSRPTv1; ext=1; rua=mailto:a@example.com; other=x"
      ]

      assert TLSRPT.parse_record(txts) == {:ok, ["mailto:a@example.com"]}
    end

    test "ignores unsupported schemes" do
      assert TLSRPT.parse_record(["v=TLSRPTv1; rua=ftp://x.example,mailto:a@example.com"]) ==
               {:ok, ["mailto:a@example.com"]}

      # URI schemes are case-insensitive (RFC 3986 §3.1).
      assert TLSRPT.parse_record(["v=TLSRPTv1; rua=HTTPS://r.example.com/,MAILTO:a@example.com"]) ==
               {:ok, ["HTTPS://r.example.com/", "MAILTO:a@example.com"]}

      assert TLSRPT.parse_record(["v=TLSRPTv1; rua=http://r.example.com/"]) ==
               {:error, :invalid_record}
    end

    test "fails without exactly one record" do
      assert TLSRPT.parse_record([]) == {:error, :no_record}
      assert TLSRPT.parse_record(["v=spf1 -all"]) == {:error, :no_record}
      # The version is case-sensitive and must come first.
      assert TLSRPT.parse_record(["v=tlsrptv1; rua=mailto:a@example.com"]) == {:error, :no_record}

      assert TLSRPT.parse_record([" v=TLSRPTv1; rua=mailto:a@example.com"]) ==
               {:error, :no_record}

      assert TLSRPT.parse_record([
               "v=TLSRPTv1; rua=mailto:a@example.com",
               "v=TLSRPTv1; rua=mailto:b@example.com"
             ]) == {:error, :multiple_records}
    end

    test "fails without a usable rua" do
      assert TLSRPT.parse_record(["v=TLSRPTv1"]) == {:error, :invalid_record}
      assert TLSRPT.parse_record(["v=TLSRPTv1; ext=1"]) == {:error, :invalid_record}

      assert TLSRPT.parse_record(["v=TLSRPTv1; RUA=mailto:a@example.com"]) ==
               {:error, :invalid_record}

      assert TLSRPT.parse_record(["v=TLSRPTv1; rua="]) == {:error, :invalid_record}

      assert TLSRPT.parse_record(["v=TLSRPTv1; rua=mailto:,https:///x"]) ==
               {:error, :invalid_record}
    end
  end

  describe "discover/2" do
    test "looks up _smtp._tls.<domain>" do
      resolver =
        FakeDNS.resolver(%{
          {"_smtp._tls.example.com", :txt} => ["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"],
          {"_smtp._tls.down.example", :txt} => {:error, :servfail},
          {"_smtp._tls.empty.example", :txt} => ["something else"],
          {"_smtp._tls.nodata.example", :a} => [{192, 0, 2, 1}]
        })

      assert TLSRPT.discover(resolver, "example.com.") == {:ok, ["mailto:tlsrpt@example.com"]}
      assert TLSRPT.discover(resolver, "missing.example") == {:error, :no_record}
      assert TLSRPT.discover(resolver, "nodata.example") == {:error, :no_record}
      assert TLSRPT.discover(resolver, "empty.example") == {:error, :no_record}
      assert TLSRPT.discover(resolver, "down.example") == {:error, {:dns, :servfail}}
    end
  end

  describe "result and policy types" do
    test "have their RFC 8460 names" do
      names = Enum.map(TLSRPT.result_types(), &TLSRPT.result_type_name/1)

      assert names == [
               "starttls-not-supported",
               "certificate-host-mismatch",
               "certificate-expired",
               "certificate-not-trusted",
               "validation-failure",
               "tlsa-invalid",
               "dnssec-invalid",
               "dane-required",
               "sts-policy-fetch-error",
               "sts-policy-invalid",
               "sts-webpki-invalid"
             ]

      assert Enum.map([:tlsa, :sts, :no_policy_found], &TLSRPT.policy_type_name/1) ==
               ["tlsa", "sts", "no-policy-found"]
    end
  end

  defp sample_report do
    %{
      organization_name: "Example Mail",
      contact_info: "tlsrpt@mx.example.net",
      report_id: "r1",
      begin: ~U[2026-10-09 00:00:00Z],
      end:
        DateTime.from_naive!(~N[2026-10-10 02:00:00.123], "Etc/UTC") |> DateTime.add(-2, :hour),
      policies: [
        %{
          type: :sts,
          string: ["version: STSv1", "mode: enforce", "mx: *.example.com", "max_age: 86400"],
          domain: "example.com",
          mx_host: ["*.example.com"],
          successful: 10,
          failed: 3,
          failures: [
            %{
              result_type: :certificate_expired,
              sending_mta_ip: {192, 0, 2, 1},
              receiving_mx_hostname: "mx1.example.com",
              receiving_mx_helo: nil,
              receiving_ip: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 25},
              count: 2,
              additional_information: nil,
              failure_reason_code: "X509_V_ERR_CERT_HAS_EXPIRED"
            },
            %{result_type: :starttls_not_supported, count: 1}
          ]
        },
        %{
          type: :no_policy_found,
          string: [],
          domain: "example.com",
          mx_host: [],
          successful: 4,
          failed: 0,
          failures: []
        }
      ]
    }
  end

  describe "report/1" do
    test "builds the RFC 8460 JSON document" do
      json = TLSRPT.report(sample_report())
      assert {:ok, report} = JSON.decode(json)

      assert report["organization-name"] == "Example Mail"
      assert report["contact-info"] == "tlsrpt@mx.example.net"
      assert report["report-id"] == "r1"

      assert report["date-range"] == %{
               "start-datetime" => "2026-10-09T00:00:00Z",
               "end-datetime" => "2026-10-10T00:00:00Z"
             }

      assert [sts, none] = report["policies"]

      assert sts["policy"] == %{
               "policy-type" => "sts",
               "policy-string" => [
                 "version: STSv1",
                 "mode: enforce",
                 "mx: *.example.com",
                 "max_age: 86400"
               ],
               "policy-domain" => "example.com",
               "mx-host" => ["*.example.com"]
             }

      assert sts["summary"] == %{
               "total-successful-session-count" => 10,
               "total-failure-session-count" => 3
             }

      assert sts["failure-details"] == [
               %{
                 "result-type" => "certificate-expired",
                 "sending-mta-ip" => "192.0.2.1",
                 "receiving-mx-hostname" => "mx1.example.com",
                 "receiving-ip" => "2001:db8::19",
                 "failed-session-count" => 2,
                 "failure-reason-code" => "X509_V_ERR_CERT_HAS_EXPIRED"
               },
               %{"result-type" => "starttls-not-supported", "failed-session-count" => 1}
             ]

      # Empty lists are left out.
      assert none == %{
               "policy" => %{"policy-type" => "no-policy-found", "policy-domain" => "example.com"},
               "summary" => %{
                 "total-successful-session-count" => 4,
                 "total-failure-session-count" => 0
               }
             }
    end

    test "keeps the RFC's member order and is stable" do
      json = TLSRPT.report(sample_report())
      assert json == TLSRPT.report(sample_report())

      assert String.starts_with?(
               json,
               ~s({"organization-name":"Example Mail","date-range":{"start-datetime":)
             )

      positions =
        Enum.map(~w(organization-name date-range contact-info report-id policies), fn name ->
          {pos, _} = :binary.match(json, ~s("#{name}"))
          pos
        end)

      assert positions == Enum.sort(positions)
    end

    test "leaves out a missing contact and converts times to UTC" do
      {:ok, begin} = DateTime.from_unix(1_700_000_000)

      # 01:13:20 at UTC+1.
      later = %DateTime{
        year: 2023,
        month: 11,
        day: 15,
        hour: 1,
        minute: 13,
        second: 20,
        microsecond: {0, 0},
        utc_offset: 3600,
        std_offset: 0,
        time_zone: "Etc/GMT-1",
        zone_abbr: "+01"
      }

      report =
        %{sample_report() | begin: begin, end: later, policies: []} |> Map.delete(:contact_info)

      {:ok, decoded} = JSON.decode(TLSRPT.report(report))

      refute Map.has_key?(decoded, "contact-info")
      assert decoded["policies"] == []

      assert decoded["date-range"] == %{
               "start-datetime" => "2023-11-14T22:13:20Z",
               "end-datetime" => "2023-11-15T00:13:20Z"
             }
    end

    test "escapes strings" do
      report = %{sample_report() | organization_name: ~s(A "quoted" \\ name\n)}
      {:ok, decoded} = JSON.decode(TLSRPT.report(report))
      assert decoded["organization-name"] == ~s(A "quoted" \\ name\n)
    end
  end

  describe "filename/5" do
    test "joins the parts with ! and Unix timestamps" do
      {:ok, from} = DateTime.from_unix(1_700_000_000)
      {:ok, to} = DateTime.from_unix(1_700_086_400)

      assert TLSRPT.filename("mx.example.net", "example.com", from, to, "abc123") ==
               "mx.example.net!example.com!1700000000!1700086400!abc123.json.gz"

      assert TLSRPT.filename("mx.example.net", "example.com", from, to, nil) ==
               "mx.example.net!example.com!1700000000!1700086400.json.gz"

      assert TLSRPT.filename("mx.example.net", "example.com", from, to, "") ==
               "mx.example.net!example.com!1700000000!1700086400.json.gz"
    end
  end

  defp message(overrides \\ %{}) do
    gzip = :zlib.gzip(TLSRPT.report(sample_report()) <> String.duplicate("x", 500))

    opts =
      Map.merge(
        %{
          from: "tlsrpt@mx.example.net",
          to: ["a@example.com", "b@example.com"],
          domain: "example.com",
          submitter: "mx.example.net",
          report_id: "r1",
          filename: "mx.example.net!example.com!1700000000!1700086400!r1.json.gz",
          gzip: gzip,
          hostname: "mx.example.net",
          date: ~U[2026-10-10 00:00:00Z]
        },
        overrides
      )

    {IO.iodata_to_binary(TLSRPT.message(opts)), gzip}
  end

  defp unfold(header), do: String.replace(header, ~r/\r\n[ \t]+/, " ")

  describe "message/1" do
    test "has the RFC 8460 §5.3 header fields" do
      {mail, _gzip} = message()
      [header, _body] = String.split(mail, "\r\n\r\n", parts: 2)
      header = unfold(header <> "\r\n")

      assert header =~ ~r/^From: <tlsrpt@mx\.example\.net>\r$/m
      assert header =~ ~r/^To: <a@example\.com>, <b@example\.com>\r$/m
      assert header =~ ~r/^Date: Sat, 10 Oct 2026 00:00:00 \+0000\r$/m
      assert header =~ ~r/^Message-ID: <[^>]+@mx\.example\.net>\r$/m

      assert header =~
               ~r/^Subject: Report Domain: example\.com Submitter: mx\.example\.net Report-ID: <r1>\r$/m

      assert header =~ ~r/^TLS-Report-Domain: example\.com\r$/m
      assert header =~ ~r/^TLS-Report-Submitter: mx\.example\.net\r$/m
      assert header =~ ~r/^MIME-Version: 1\.0\r$/m

      assert [_, _boundary] =
               Regex.run(
                 ~r/^Content-Type: multipart\/report; report-type="tlsrpt"; boundary="([^"]+)"\r$/m,
                 header
               )
    end

    test "uses CRLF and short lines" do
      {mail, _gzip} = message(%{to: Enum.map(1..20, &"user#{&1}@example.com")})

      refute mail =~ ~r/[^\r]\n/
      refute mail =~ ~r/\r[^\n]/
      lines = String.split(mail, "\r\n")
      assert Enum.all?(lines, &(byte_size(&1) <= 998))
      assert Enum.all?(lines, &(byte_size(&1) <= 78))
    end

    test "attaches the gzipped report" do
      {mail, gzip} = message(%{boundary: "BOUNDARY"})

      assert [_preamble, text, attachment, "--\r\n"] = String.split(mail, "\r\n--BOUNDARY")
      assert text =~ "Content-Type: text/plain; charset=us-ascii\r\n"

      [part_header, data] = String.split(attachment, "\r\n\r\n", parts: 2)
      part_header = unfold(part_header)
      assert part_header =~ "\r\nContent-Type: application/tlsrpt+gzip\r\n"

      assert part_header =~
               ~s(\r\nContent-Disposition: attachment; filename="mx.example.net!example.com!1700000000!1700086400!r1.json.gz")

      assert part_header =~ "\r\nContent-Transfer-Encoding: base64"

      base64_lines = String.split(data, "\r\n")
      assert Enum.all?(base64_lines, &(byte_size(&1) <= 76))
      assert base64_lines |> Enum.drop(-1) |> Enum.all?(&(byte_size(&1) == 76))

      assert {:ok, ^gzip} = base64_lines |> Enum.join() |> Base.decode64()

      assert {:ok, %{"report-id" => "r1"}} =
               gzip |> :zlib.gunzip() |> String.trim_trailing("x") |> JSON.decode()
    end

    test "cannot be broken by line breaks in values" do
      {mail, _gzip} =
        message(%{report_id: "r1\r\nBcc: evil@example.org", filename: ~s(a"b.json.gz)})

      refute mail =~ "\r\nBcc:"
      assert mail =~ ~s(filename="a\\"b.json.gz")
    end
  end

  describe "post/3" do
    defp start_receiver(status) do
      test = self()

      {:ok, http} =
        FakeHTTP.start_link(fn request ->
          send(test, {:request, request})
          {status, [], ""}
        end)

      FakeHTTP.url(http, "/tlsrpt")
    end

    test "posts the gzipped report" do
      url = start_receiver(201)
      gzip = :zlib.gzip(~s({"report-id":"r1"}))

      assert TLSRPT.post(url, gzip, allow_http: true, timeout: 5_000) == :ok

      assert_received {:request,
                       %{method: "POST", path: "/tlsrpt", headers: headers, body: ^gzip}}

      assert {"content-type", "application/tlsrpt+gzip"} =
               List.keyfind(headers, "content-type", 0)
    end

    test "fails on other statuses" do
      url = start_receiver(500)
      assert TLSRPT.post(url, "gz", allow_http: true) == {:error, {:http_status, 500}}

      url = start_receiver(302)
      assert TLSRPT.post(url, "gz", allow_http: true) == {:error, {:http_status, 302}}
    end

    test "fails on transport errors" do
      {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
      {:ok, port} = :inet.port(socket)
      :gen_tcp.close(socket)

      assert {:error, _reason} =
               TLSRPT.post("http://127.0.0.1:#{port}/", "gz", allow_http: true, timeout: 2_000)
    end

    test "uses TLS for https: URLs" do
      # A server that closes every connection before the handshake.
      {:ok, listen} = :gen_tcp.listen(0, ip: {127, 0, 0, 1}, active: false)
      {:ok, port} = :inet.port(listen)

      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listen)
        :gen_tcp.close(socket)
      end)

      assert {:error, _reason} =
               TLSRPT.post("https://127.0.0.1:#{port}/", "gz", cacerts: [], timeout: 2_000)
    end

    test "accepts only https: URLs" do
      url = start_receiver(200)

      assert TLSRPT.post(url, "gz") == {:error, :invalid_url}
      assert TLSRPT.post("mailto:a@example.com", "gz") == {:error, :invalid_url}
      assert TLSRPT.post("https:///path", "gz") == {:error, :invalid_url}
      assert TLSRPT.post("not a url", "gz", allow_http: true) == {:error, :invalid_url}
      refute_received {:request, _}
    end
  end
end
