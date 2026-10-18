defmodule Sovite.SMTP.CommandTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Sovite.SMTP.Command, only: [parse: 1]

  doctest Sovite.SMTP.Command
  doctest Sovite.SMTP.XText

  test "parses simple commands case-insensitively" do
    assert parse("EHLO client.example") == {:ok, {:ehlo, "client.example"}}
    assert parse("helo [192.0.2.1]") == {:ok, {:helo, "[192.0.2.1]"}}
    assert parse("data") == {:ok, :data}
    assert parse("RSET") == {:ok, :rset}
    assert parse("Quit") == {:ok, :quit}
    assert parse("NOOP") == {:ok, {:noop, ""}}
    assert parse("NOOP anything") == {:ok, {:noop, "anything"}}
    assert parse("HELP mail") == {:ok, {:help, "mail"}}
    assert parse("VRFY alice") == {:ok, {:vrfy, "alice"}}
  end

  test "rejects arguments where none are allowed, and missing ones" do
    assert parse("DATA now") == {:error, :data, :syntax}
    assert parse("QUIT x") == {:error, :quit, :syntax}
    assert parse("EHLO") == {:error, :ehlo, :syntax}
    assert parse("EHLO   ") == {:error, :ehlo, :syntax}
    assert parse("VRFY") == {:error, :vrfy, :syntax}
  end

  test "parses MAIL and RCPT paths and parameters" do
    assert parse("MAIL FROM:<>") == {:ok, {:mail, "", []}}
    assert parse("mail from:<a@example.com>") == {:ok, {:mail, "a@example.com", []}}
    # Common clients put a space after the colon.
    assert parse("MAIL FROM: <a@example.com>") == {:ok, {:mail, "a@example.com", []}}

    assert parse("MAIL FROM:<a@example.com> size=100 BODY=8BITMIME AUTH=<>") ==
             {:ok,
              {:mail, "a@example.com", [{"SIZE", "100"}, {"BODY", "8BITMIME"}, {"AUTH", "<>"}]}}

    assert parse("MAIL FROM:<a@example.com>  SMTPUTF8") ==
             {:ok, {:mail, "a@example.com", [{"SMTPUTF8", nil}]}}

    assert parse(~s(RCPT TO:<"john doe"@example.com>)) ==
             {:ok, {:rcpt, ~s("john doe"@example.com), []}}

    assert parse(~s(RCPT TO:<"a>b"@example.com>)) == {:ok, {:rcpt, ~s("a>b"@example.com), []}}
    assert parse("RCPT TO:<user@[192.0.2.1]>") == {:ok, {:rcpt, "user@[192.0.2.1]", []}}
  end

  test "strips source routes" do
    assert parse("RCPT TO:<@a.example,@b.example:user@c.example>") ==
             {:ok, {:rcpt, "user@c.example", []}}

    assert parse("RCPT TO:<@bad_host:user@c.example>") == {:error, :rcpt, :invalid_recipient}
    assert parse("RCPT TO:<@a.example>") == {:error, :rcpt, :invalid_recipient}
  end

  test "accepts <Postmaster> without a domain only for RCPT" do
    assert parse("RCPT TO:<postmaster>") == {:ok, {:rcpt, "postmaster", []}}
    assert parse("MAIL FROM:<postmaster>") == {:error, :mail, :invalid_sender}
    assert parse("RCPT TO:<user>") == {:error, :rcpt, :invalid_recipient}
    assert parse("RCPT TO:<>") == {:error, :rcpt, :invalid_recipient}
  end

  test "rejects malformed paths and parameters" do
    assert parse("MAIL FROM:a@example.com") == {:error, :mail, :invalid_sender}
    assert parse("MAIL FROM:<a@example.com") == {:error, :mail, :invalid_sender}
    assert parse("MAIL TO:<a@example.com>") == {:error, :mail, :syntax}
    assert parse("MAIL") == {:error, :mail, :syntax}
    assert parse("RCPT TO:<a@@example.com>") == {:error, :rcpt, :invalid_recipient}
    assert parse("RCPT TO:<a@example.com>SIZE=1") == {:error, :rcpt, :invalid_parameter}
    assert parse("MAIL FROM:<a@example.com> =1") == {:error, :mail, :invalid_parameter}
    assert parse("MAIL FROM:<a@example.com> SIZE=") == {:error, :mail, :invalid_parameter}
    assert parse("MAIL FROM:<a@example.com> X=a=b") == {:error, :mail, :invalid_parameter}
  end

  test "classifies unknown, unsupported, and non-SMTP commands" do
    assert parse("FOO bar") == {:error, nil, :unrecognized}
    assert parse("") == {:error, nil, :unrecognized}
    assert parse("EXPN staff") == {:error, nil, :not_implemented}
    assert parse("TURN") == {:error, nil, :not_implemented}
    assert parse("GET / HTTP/1.1") == {:error, nil, :non_smtp}
    assert parse("POST /form HTTP/1.1") == {:error, nil, :non_smtp}
  end

  test "parses XCLIENT and XFORWARD attributes" do
    assert parse("XCLIENT ADDR=192.0.2.1 name=mail.example.com") ==
             {:ok, {:xclient, [{"ADDR", "192.0.2.1"}, {"NAME", "mail.example.com"}]}}

    assert parse("XFORWARD HELO=[UNAVAILABLE] IDENT=a+20b PROTO=[TEMPUNAVAIL]") ==
             {:ok, {:xforward, [{"HELO", nil}, {"IDENT", "a b"}, {"PROTO", nil}]}}

    assert parse("XCLIENT") == {:error, :xclient, :syntax}
    assert parse("XCLIENT ADDR") == {:error, :xclient, :syntax}
    assert parse("XFORWARD IDENT=a+2") == {:error, :xforward, :syntax}
    assert parse("XFORWARD 1A=b") == {:error, :xforward, :syntax}
    # Decoded values may not hold control characters or invalid UTF-8.
    assert parse("XFORWARD HELO=a+0D+0AX-Injected:+20yes") == {:error, :xforward, :syntax}
    assert parse("XCLIENT LOGIN=a+FF") == {:error, :xclient, :syntax}
    assert parse("XCLIENT LOGIN=j+C3+B6rg") == {:ok, {:xclient, [{"LOGIN", "jörg"}]}}
  end

  test "parses STARTTLS and AUTH" do
    assert parse("STARTTLS") == {:ok, :starttls}
    assert parse("starttls x") == {:error, :starttls, :syntax}
    assert parse("AUTH plain") == {:ok, {:auth, "PLAIN", nil}}
    assert parse("AUTH PLAIN AGFiAGM=") == {:ok, {:auth, "PLAIN", "AGFiAGM="}}
    assert parse("AUTH SCRAM-SHA-256 =") == {:ok, {:auth, "SCRAM-SHA-256", "="}}
    assert parse("AUTH") == {:error, :auth, :syntax}
    assert parse("AUTH PLAIN a b") == {:error, :auth, :syntax}
    assert parse("AUTH PL/AIN") == {:error, :auth, :syntax}
    assert parse("AUTH " <> String.duplicate("X", 21)) == {:error, :auth, :syntax}
  end

  test "rejects control and non-ASCII characters" do
    assert parse("EHLO a\rb") == {:error, :ehlo, :invalid_characters}
    assert parse("MAIL FROM:<a@example.com>\0") == {:error, :mail, :invalid_characters}
    assert parse("RCPT TO:<ü@example.com>\u0085") == {:error, :rcpt, :invalid_characters}
    assert parse("RCPT TO:<\xFF@example.com>") == {:error, :rcpt, :invalid_characters}
    assert parse("EHLO bücher.example") == {:error, :ehlo, :invalid_characters}
    assert parse("X\tY") == {:error, nil, :invalid_characters}
  end

  test "accepts internationalized addresses (RFC 6531)" do
    assert parse("MAIL FROM:<jürgen@bücher.example> SMTPUTF8") ==
             {:ok, {:mail, "jürgen@bücher.example", [{"SMTPUTF8", nil}]}}

    assert parse("RCPT TO:<用户@例子.广告>") == {:ok, {:rcpt, "用户@例子.广告", []}}
    assert parse(~s(RCPT TO:<"ü ü"@example.com>)) == {:ok, {:rcpt, ~s("ü ü"@example.com), []}}
    assert parse("RCPT TO:<a@☃.example>") == {:error, :rcpt, :invalid_recipient}
    # Parameter values may be UTF-8 too (ORCPT); each parameter checks its own.
    assert parse("RCPT TO:<b@example.com> ORCPT=utf-8;ü@example.com") ==
             {:ok, {:rcpt, "b@example.com", [{"ORCPT", "utf-8;ü@example.com"}]}}

    assert parse("MAIL FROM:<a@example.com> SIZE=\u0085") == {:error, :mail, :invalid_characters}
  end

  test "parses BDAT" do
    assert parse("BDAT 100") == {:ok, {:bdat, 100, false}}
    assert parse("bdat 0 last") == {:ok, {:bdat, 0, true}}
    assert parse("BDAT 100 LAST") == {:ok, {:bdat, 100, true}}
    assert parse("BDAT") == {:error, :bdat, :syntax}
    assert parse("BDAT -1") == {:error, :bdat, :syntax}
    assert parse("BDAT 10 FIRST") == {:error, :bdat, :syntax}
    assert parse("BDAT 10 LAST x") == {:error, :bdat, :syntax}
    assert parse("BDAT " <> String.duplicate("9", 16)) == {:error, :bdat, :syntax}
  end

  test "parses ETRN" do
    assert parse("ETRN Example.COM") == {:ok, {:etrn, {:domain, "example.com"}}}
    assert parse("ETRN @example.com") == {:ok, {:etrn, {:subdomains, "example.com"}}}
    assert parse("ETRN #queue1") == {:ok, {:etrn, {:queue, "queue1"}}}
    assert parse("ETRN") == {:error, :etrn, :syntax}
    assert parse("ETRN @") == {:error, :etrn, :syntax}
    assert parse("ETRN #") == {:error, :etrn, :syntax}
    assert parse("ETRN a..b") == {:error, :etrn, :syntax}
  end

  property "never raises" do
    check all(line <- binary(max_length: 300)) do
      result = parse(line)
      assert match?({:ok, _}, result) or match?({:error, _, _}, result)
    end
  end

  property "never raises on MAIL/RCPT-shaped input" do
    check all(
            verb <- member_of(["MAIL FROM:", "RCPT TO:"]),
            path <-
              string(Enum.concat([?<, ?>, ?", ?\\, ?@, ?:, ?,, ?\s], ?a..?c), max_length: 40)
          ) do
      result = parse(verb <> path)
      assert match?({:ok, _}, result) or match?({:error, _, _}, result)
    end
  end
end
