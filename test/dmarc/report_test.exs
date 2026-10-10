defmodule Sovite.DMARC.ReportTest do
  use ExUnit.Case, async: true

  alias Sovite.DMARC.Report

  @start ~U[2026-10-09 00:00:00Z]
  @finish ~U[2026-10-10 00:00:00Z]

  defp report(overrides \\ %{}) do
    Map.merge(
      %{
        org_name: "Receiver & Co",
        email: "dmarc@receiver.example",
        extra_contact_info: nil,
        report_id: "r-1",
        begin: @start,
        end: @finish,
        policy: %{
          domain: "example.com",
          adkim: :relaxed,
          aspf: :strict,
          p: :reject,
          sp: :quarantine,
          pct: 100
        },
        records: [
          %{
            source_ip: {192, 0, 2, 1},
            count: 3,
            disposition: :none,
            dkim: :pass,
            spf: :fail,
            reasons: [],
            header_from: "example.com",
            envelope_from: nil,
            envelope_to: nil,
            dkim_auth: [%{domain: "example.com", selector: "s1", result: :pass}],
            spf_auth: [%{domain: "esp.example", scope: :mfrom, result: :softfail}]
          }
        ]
      },
      overrides
    )
  end

  test "builds an aggregate report" do
    assert Report.aggregate(report()) == """
           <?xml version="1.0" encoding="UTF-8"?>
           <feedback>
             <version>1.0</version>
             <report_metadata>
               <org_name>Receiver &amp; Co</org_name>
               <email>dmarc@receiver.example</email>
               <report_id>r-1</report_id>
               <date_range>
                 <begin>1791504000</begin>
                 <end>1791590400</end>
               </date_range>
             </report_metadata>
             <policy_published>
               <domain>example.com</domain>
               <adkim>r</adkim>
               <aspf>s</aspf>
               <p>reject</p>
               <sp>quarantine</sp>
               <pct>100</pct>
             </policy_published>
             <record>
               <row>
                 <source_ip>192.0.2.1</source_ip>
                 <count>3</count>
                 <policy_evaluated>
                   <disposition>none</disposition>
                   <dkim>pass</dkim>
                   <spf>fail</spf>
                 </policy_evaluated>
               </row>
               <identifiers>
                 <header_from>example.com</header_from>
               </identifiers>
               <auth_results>
                 <dkim>
                   <domain>example.com</domain>
                   <selector>s1</selector>
                   <result>pass</result>
                 </dkim>
                 <spf>
                   <domain>esp.example</domain>
                   <scope>mfrom</scope>
                   <result>softfail</result>
                 </spf>
               </auth_results>
             </record>
           </feedback>
           """
  end

  test "includes optional elements when given" do
    record = %{
      source_ip: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1},
      count: 1,
      disposition: :quarantine,
      dkim: :fail,
      spf: :fail,
      reasons: [%{type: "sampled_out", comment: nil}, %{type: "local_policy", comment: "list"}],
      header_from: "example.com",
      envelope_from: "bounce.example.com",
      envelope_to: "receiver.example",
      dkim_auth: [%{domain: "example.com", selector: nil, result: :fail}],
      spf_auth: [%{domain: "helo.example.com", scope: :helo, result: :none}]
    }

    xml =
      Report.aggregate(
        report(%{
          extra_contact_info: "https://receiver.example/dmarc",
          policy: %{
            domain: "example.com",
            adkim: :strict,
            aspf: :relaxed,
            p: :none,
            sp: :none,
            np: :reject,
            pct: 50
          },
          records: [record, record]
        })
      )

    assert xml =~ "<extra_contact_info>https://receiver.example/dmarc</extra_contact_info>"
    assert xml =~ "<sp>none</sp>\n    <np>reject</np>\n    <pct>50</pct>"
    assert xml =~ "<source_ip>2001:db8::1</source_ip>"

    assert xml =~
             "<reason>\n          <type>sampled_out</type>\n        </reason>\n" <>
               "        <reason>\n          <type>local_policy</type>\n" <>
               "          <comment>list</comment>\n        </reason>"

    assert xml =~
             "<envelope_to>receiver.example</envelope_to>\n" <>
               "      <envelope_from>bounce.example.com</envelope_from>\n" <>
               "      <header_from>example.com</header_from>"

    assert xml =~ "<dkim>\n        <domain>example.com</domain>\n        <result>fail</result>"
    assert xml =~ "<scope>helo</scope>"
    assert length(String.split(xml, "<record>")) == 3
  end

  test "escapes text and drops characters XML cannot carry" do
    xml =
      Report.aggregate(
        report(%{org_name: ~s(<a href="x">'O'&Co</a>), report_id: "id\x00\x1b-2", records: []})
      )

    assert xml =~
             "<org_name>&lt;a href=&quot;x&quot;&gt;&apos;O&apos;&amp;Co&lt;/a&gt;</org_name>"

    assert xml =~ "<report_id>id-2</report_id>"
    refute xml =~ "<record>"
  end

  test "writes empty elements without children" do
    record = %{hd(report().records) | dkim_auth: [], spf_auth: []}
    assert Report.aggregate(report(%{records: [record]})) =~ "<auth_results/>"
  end

  test "names report files" do
    assert Report.filename("mx.receiver.example", "example.com", @start, @finish, "r-1") ==
             "mx.receiver.example!example.com!1791504000!1791590400!r-1.xml.gz"

    assert Report.filename("mx.receiver.example", "example.com", @start, @finish, "") ==
             "mx.receiver.example!example.com!1791504000!1791590400.xml.gz"
  end
end
