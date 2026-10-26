defmodule Sovite.AnalyzerTest do
  use ExUnit.Case, async: true

  alias Sovite.Analyzer

  @message String.replace(
             """
             From: "PayPal" <service@paypa1.example>
             Subject: =?utf-8?Q?Your_account_is_l=C3=B6cked?=
             Content-Type: multipart/mixed; boundary=b

             --b
             Content-Type: multipart/alternative; boundary=a

             --a
             Content-Type: text/plain

             Log in at hxxps://paypal-secure.example[.]com/verify or mail support@paypa1.example.
             --a
             Content-Type: text/html

             <p>Log in at <a href="https://paypal-secure.example.com/verify">https://www.paypal.com/</a></p>
             <div style="display:none">lorem ipsum ham words</div>
             --a--
             --b
             Content-Type: application/pdf
             Content-Disposition: attachment; filename="invoice.pdf"
             Content-Transfer-Encoding: base64

             #{Base.encode64(<<"MZ", 0::size(464), 64::32-little, "PE", 0, 0>>)}
             --b
             Content-Type: application/zip
             Content-Disposition: attachment; filename=archive.zip
             Content-Transfer-Encoding: base64

             #{Base.encode64(<<"PK", 3, 4, 0::size(208), "readme.txt">>)}
             --b--
             """,
             "\n",
             "\r\n"
           )

  test "takes a message apart for a filter" do
    analysis = Analyzer.analyze(@message)

    assert analysis.subject == "Your account is löcked"
    assert analysis.anomalies == []

    assert [%{source: :plain}, %{source: :html, hidden_text: "lorem ipsum ham words"} = html] =
             analysis.texts

    assert html.text == "Log in at https://www.paypal.com/"

    # The link goes elsewhere than its text says.
    assert [
             %{source: :html, link_text: "https://www.paypal.com/", url: link},
             %{source: :text, url: written},
             %{source: :text, url: shown}
           ] = analysis.urls

    assert link.host == "paypal-secure.example.com"
    assert written.url == "https://paypal-secure.example.com/verify"
    assert :obfuscated in written.flags
    assert shown.host == "www.paypal.com"

    assert analysis.addresses == ["support@paypa1.example"]

    assert [pdf, zip] = analysis.attachments
    assert %{filename: "invoice.pdf", declared: "application/pdf", disguised: true} = pdf
    assert pdf.detected.extension == "exe"
    assert %{filename: "archive.zip", disguised: false, detected: %{extension: "zip"}} = zip
  end

  test "lists HTML anomalies too" do
    message = "Content-Type: text/html\r\n\r\n" <> String.duplicate("<b>x</b>", 20)
    assert [{:html, :tag_limit}] = Analyzer.analyze(message, html: [max_tags: 5]).anomalies
  end
end
