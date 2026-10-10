defmodule Sovite.DSNTest do
  use ExUnit.Case, async: true

  alias Sovite.DSN

  @report %{
    kind: :failure,
    reporting_mta: "mx.example.org",
    from: "MAILER-DAEMON@mx.example.org",
    to: "alice@example.org",
    recipients: [
      %{
        recipient: "bob@example.net",
        status: "5.1.1",
        remote_mta: "mx.example.net",
        diagnostic: "550 5.1.1 User unknown",
        last_attempt: ~U[2026-10-04 12:05:00Z]
      },
      %{
        recipient: "carol@nowhere.example",
        status: "5.1.2",
        reason: "Host or domain name not found"
      }
    ],
    headers: "From: alice@example.org\r\nSubject: hello\r\n",
    queue_id: "8CboABCDEFGHIJ",
    arrival_date: ~U[2026-10-04 12:00:00Z],
    date: ~U[2026-10-04 12:06:00Z],
    message_id: "<dsn.1@mx.example.org>",
    boundary: "BOUNDARY"
  }

  defp parts(message) do
    [headers, body] = String.split(message, "\r\n\r\n", parts: 2)
    parts = body |> String.split("\r\n--BOUNDARY") |> tl()
    {headers, parts}
  end

  test "builds a multipart/report failure notification" do
    {message, :"7bit"} = DSN.build(@report)
    {headers, parts} = parts(message)

    assert headers ==
             """
             From: Mail Delivery System <MAILER-DAEMON@mx.example.org>\r
             To: <alice@example.org>\r
             Subject: Undelivered Mail Returned to Sender\r
             Date: Sun, 4 Oct 2026 12:06:00 +0000\r
             Message-ID: <dsn.1@mx.example.org>\r
             Auto-Submitted: auto-replied\r
             MIME-Version: 1.0\r
             Content-Type: multipart/report; report-type=delivery-status;\r
             \tboundary="BOUNDARY"\
             """

    assert [text, status, original, "--\r\n"] = parts

    assert text =~ "Content-Type: text/plain; charset=us-ascii\r\n"
    assert text =~ "This is the mail system at host mx.example.org."
    assert text =~ "<bob@example.net>: host mx.example.net said: 550 5.1.1 User unknown\r\n"
    assert text =~ "<carol@nowhere.example>: Host or domain name not found\r\n"

    assert status ==
             """
             \r
             Content-Type: message/delivery-status\r
             Content-Description: Delivery report\r
             \r
             Reporting-MTA: dns; mx.example.org\r
             X-Sovite-Queue-ID: 8CboABCDEFGHIJ\r
             Arrival-Date: Sun, 4 Oct 2026 12:00:00 +0000\r
             \r
             Final-Recipient: rfc822; bob@example.net\r
             Action: failed\r
             Status: 5.1.1\r
             Remote-MTA: dns; mx.example.net\r
             Diagnostic-Code: smtp; 550 5.1.1 User unknown\r
             Last-Attempt-Date: Sun, 4 Oct 2026 12:05:00 +0000\r
             \r
             Final-Recipient: rfc822; carol@nowhere.example\r
             Action: failed\r
             Status: 5.1.2\r
             """

    assert original ==
             "\r\nContent-Type: text/rfc822-headers\r\n" <>
               "Content-Description: Undelivered Message Headers\r\n\r\n" <>
               "From: alice@example.org\r\nSubject: hello\r\n"

    assert String.ends_with?(message, "\r\n--BOUNDARY--\r\n")
  end

  test "builds a delay warning" do
    report = %{@report | kind: :delay} |> Map.put(:will_retry_until, ~U[2026-10-09 12:00:00Z])
    {message, _} = DSN.build(report)

    assert message =~ "Subject: Delayed Mail (still being retried)\r\n"
    assert message =~ "Delivery will be retried until\r\nFri, 9 Oct 2026 12:00:00 +0000."
    assert message =~ "Action: delayed\r\n"
    assert message =~ "Will-Retry-Until: Fri, 9 Oct 2026 12:00:00 +0000\r\n"
    assert message =~ "Content-Description: Delayed Message Headers\r\n"
    refute message =~ "Action: failed"
  end

  test "neutralizes hostile text from remote servers" do
    hostile = %{
      recipient: "bob@example.net",
      status: "5.0.0",
      remote_mta: "mx.example.net",
      diagnostic: "550 bad\r\nX-Injected: yes\r\n--BOUNDARYé" <> String.duplicate("x", 2000)
    }

    {message, _} = DSN.build(%{@report | recipients: [hostile]})

    refute message =~ "\r\nX-Injected"
    refute message =~ "\r\n--BOUNDARYé"
    assert message =~ "Diagnostic-Code: smtp; 550 bad??X-Injected: yes??--BOUNDARY??xxx"
    assert message |> String.split("\r\n") |> Enum.all?(&(byte_size(&1) < 998))
  end

  test "marks original headers with 8-bit bytes" do
    {message, :"8bitmime"} = DSN.build(%{@report | headers: "Subject: café\r\n"})
    assert message =~ "Content-Transfer-Encoding: 8bit\r\n\r\nSubject: café\r\n"
  end

  test "builds an internationalized notification (RFC 6533)" do
    report = %{
      @report
      | to: "jürgen@example.org",
        recipients: [
          %{recipient: "用户@example.net", status: "5.6.7", diagnostic: "553 5.6.7 Ünicode\u0007"}
        ],
        headers: "From: jürgen@example.org\r\nSubject: Grüße\r\n"
    }

    assert DSN.global?(report)
    {message, :"8bitmime"} = DSN.build(report)
    {headers, [text, status, original | _]} = parts(message)

    assert headers =~ "To: <jürgen@example.org>\r\n"
    assert headers =~ "report-type=global-delivery-status;"
    assert text =~ "Content-Type: text/plain; charset=utf-8\r\n"
    assert text =~ "<用户@example.net>: 553 5.6.7 Ünicode?\r\n"
    assert status =~ "Content-Type: message/global-delivery-status\r\n"
    assert status =~ "Final-Recipient: utf-8; 用户@example.net\r\n"
    assert status =~ "Diagnostic-Code: smtp; 553 5.6.7 Ünicode?\r\n"
    assert original =~ "Content-Type: message/global-headers\r\n"
    assert original =~ "Content-Transfer-Encoding: 8bit\r\n"
    assert original =~ "Subject: Grüße\r\n"
  end

  test "a notification is internationalized for UTF-8 headers only with SMTPUTF8" do
    report = %{@report | headers: "Subject: Grüße\r\n"}
    refute DSN.global?(report)
    {message, :"8bitmime"} = DSN.build(report)
    assert message =~ "Content-Type: text/rfc822-headers\r\n"
    assert message =~ "Final-Recipient: rfc822; bob@example.net\r\n"

    report = Map.put(report, :smtputf8, true)
    assert DSN.global?(report)
    assert report |> DSN.build() |> elem(0) =~ "Content-Type: message/global-headers\r\n"

    refute DSN.global?(Map.put(@report, :smtputf8, true))
  end

  test "cuts long internationalized text" do
    long = String.duplicate("ü", 1000)

    report = %{
      @report
      | to: "jürgen@example.org",
        recipients: [%{recipient: "b@example.net", status: "5.0.0", reason: long}]
    }

    {message, _} = DSN.build(report)
    [line] = Regex.run(~r/<b@example.net>: [^\r]*/u, message)
    assert byte_size(line) < 950
    assert String.ends_with?(line, "...")
    assert String.valid?(line)
  end

  test "works without original headers and optional fields" do
    report = %{
      kind: :failure,
      reporting_mta: "mx.example.org",
      from: "MAILER-DAEMON@mx.example.org",
      to: "alice@example.org",
      recipients: [%{recipient: "bob@example.net", status: "5.4.4"}]
    }

    {message, :"7bit"} = DSN.build(report)
    assert message =~ "<bob@example.net>: delivery status 5.4.4\r\n"
    assert message =~ ~r/Message-ID: <[a-z0-9.]+@mx.example.org>\r\n/
    assert message =~ ~r/boundary="=_sovite_[a-z2-7]+"/
  end
end
