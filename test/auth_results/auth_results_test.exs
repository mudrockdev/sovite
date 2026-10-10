defmodule Sovite.AuthResultsTest do
  use ExUnit.Case, async: true

  alias Sovite.AuthResults
  alias Sovite.Message.Headers

  doctest AuthResults

  @results [
    %{method: "spf", result: "pass", properties: [{"smtp.mailfrom", "a@example.com"}]},
    %{
      method: "dkim",
      result: "pass",
      properties: [{"header.d", "example.com"}, {"header.s", "sel"}, {"header.b", "AbCdEf12"}]
    }
  ]

  describe "value/2 and field/2" do
    test "one result per folded line" do
      assert AuthResults.value("mx.example.org", @results) ==
               "mx.example.org;\r\n\tspf=pass smtp.mailfrom=a@example.com;\r\n" <>
                 "\tdkim=pass header.d=example.com header.s=sel header.b=AbCdEf12"
    end

    test "the whole field" do
      assert AuthResults.field("mx.example.org", @results) ==
               "Authentication-Results: " <>
                 AuthResults.value("mx.example.org", @results) <> "\r\n"

      assert AuthResults.field("mx.example.org", []) ==
               "Authentication-Results: mx.example.org; none\r\n"
    end

    test "reason and comment" do
      result = %{
        method: "dkim",
        result: "fail",
        reason: ~s(signature "b=" \\ bad),
        comment: "key (2048 bit) \\ rsa",
        properties: [{"header.d", "example.com"}]
      }

      assert AuthResults.value("mx", [result]) ==
               "mx;\r\n\tdkim=fail (key \\(2048 bit\\) \\\\ rsa) " <>
                 ~s(reason="signature \\"b=\\" \\\\ bad" header.d=example.com)
    end

    test "nil reason and comment are left out" do
      assert AuthResults.value("mx", [
               %{method: "dmarc", result: "none", reason: nil, comment: nil}
             ]) ==
               "mx;\r\n\tdmarc=none"
    end

    test "quotes property values that are neither tokens nor addresses" do
      value = fn v ->
        AuthResults.value("mx", [%{method: "x", result: "y", properties: [{"p.v", v}]}])
      end

      for bare <- ["example.com", "@example.com", "a.b+c@sub.example.com", "1.2.3.4", "abc+def"] do
        assert value.(bare) == "mx;\r\n\tx=y p.v=#{bare}"
      end

      assert value.("Ab/Cd=") == ~s(mx;\r\n\tx=y p.v="Ab/Cd=")
      assert value.("a b") == ~s(mx;\r\n\tx=y p.v="a b")
      assert value.("") == ~s(mx;\r\n\tx=y p.v="")
      assert value.("a@-bad.example") == ~s(mx;\r\n\tx=y p.v="a@-bad.example")
      assert value.("a..b@example.com") == ~s(mx;\r\n\tx=y p.v="a..b@example.com")
      assert value.(~s(say "hi"\\)) == ~s(mx;\r\n\tx=y p.v="say \\"hi\\"\\\\")
      assert value.("évé@example.com") == ~s(mx;\r\n\tx=y p.v="évé@example.com")
    end

    test "control characters cannot break the field" do
      result = %{
        method: "x",
        result: "y",
        reason: "a\r\nb",
        comment: "c\nd",
        properties: [{"p.v", "e\r\nf"}]
      }

      value = AuthResults.value("mx", [result])
      assert value == ~s{mx;\r\n\tx=y (c d) reason="a  b" p.v="e  f"}
    end

    test "quotes an authserv-id that is not a token" do
      assert AuthResults.value("mx example", []) == ~s("mx example"; none)
    end
  end

  describe "authserv_id/1" do
    test "a plain id" do
      assert AuthResults.authserv_id(" mx.example.org; spf=pass") == {:ok, "mx.example.org"}
      assert AuthResults.authserv_id("mx.example.org") == {:ok, "mx.example.org"}
      assert AuthResults.authserv_id(" mx.example.org\r\n") == {:ok, "mx.example.org"}
    end

    test "after comments, nested and folded" do
      assert AuthResults.authserv_id(" (a (nested \\) comment) here)\r\n\t mx.example.org; none") ==
               {:ok, "mx.example.org"}

      assert AuthResults.authserv_id("(x)mx.example.org(y); none") == {:ok, "mx.example.org"}
    end

    test "a quoted id" do
      assert AuthResults.authserv_id(~s( "mx \\"one\\""; none)) == {:ok, ~s(mx "one")}
    end

    test "followed by a version" do
      assert AuthResults.authserv_id(" mx.example.org 1; spf=pass") == {:ok, "mx.example.org"}
    end

    test "no id" do
      for value <- ["", "  ", " ; spf=pass", " (unterminated mx.example.org", ~s( "unterminated)] do
        assert AuthResults.authserv_id(value) == :error
      end
    end
  end

  describe "strip/2" do
    test "removes our own results only" do
      header =
        "Authentication-Results: MX.Example.ORG; spf=pass smtp.mailfrom=a@b.example\r\n" <>
          "Subject: hi\r\n" <>
          "Authentication-Results: other.example; dkim=pass\r\n" <>
          "authentication-results:\r\n (forged)\r\n mx.example.org; dkim=pass\r\n" <>
          "Authentication-Results: ;garbage\r\n" <>
          "X-Authentication-Results: mx.example.org; none\r\n"

      fields = Headers.parse(header)

      assert AuthResults.strip(fields, "mx.example.org")
             |> Headers.encode()
             |> IO.iodata_to_binary() ==
               "Subject: hi\r\n" <>
                 "Authentication-Results: other.example; dkim=pass\r\n" <>
                 "Authentication-Results: ;garbage\r\n" <>
                 "X-Authentication-Results: mx.example.org; none\r\n"
    end

    test "a quoted id matches too" do
      fields = Headers.parse(~s(Authentication-Results: "mx.example.org"; none\r\n))
      assert AuthResults.strip(fields, "mx.example.org") == []
    end
  end

  describe "parse/1" do
    test "round trip of value/2" do
      results = [
        %{
          method: "dkim",
          result: "fail",
          reason: ~s(bad "sig" \\ here),
          comment: "nested (comment)",
          properties: [{"header.d", "example.com"}, {"header.b", "Ab/Cd+e="}]
        }
        | @results
      ]

      expected =
        Enum.map(results, fn result ->
          result |> Map.delete(:comment) |> Map.put_new(:reason, nil)
        end)

      assert AuthResults.parse(AuthResults.value("mx.example.org", results)) ==
               {:ok, "mx.example.org", expected}

      assert AuthResults.parse(AuthResults.value("mx.example.org", [])) ==
               {:ok, "mx.example.org", []}
    end

    test "a Gmail-style field" do
      value =
        " mx.google.com;\r\n" <>
          "       dkim=pass header.i=@example.com header.s=s1 header.b=abc;\r\n" <>
          "       spf=pass (google.com: domain of a@b designates 1.2.3.4 as permitted sender) smtp.mailfrom=a@b;\r\n" <>
          "       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=example.com\r\n"

      assert AuthResults.parse(value) ==
               {:ok, "mx.google.com",
                [
                  %{
                    method: "dkim",
                    result: "pass",
                    reason: nil,
                    properties: [
                      {"header.i", "@example.com"},
                      {"header.s", "s1"},
                      {"header.b", "abc"}
                    ]
                  },
                  %{
                    method: "spf",
                    result: "pass",
                    reason: nil,
                    properties: [{"smtp.mailfrom", "a@b"}]
                  },
                  %{
                    method: "dmarc",
                    result: "pass",
                    reason: nil,
                    properties: [{"header.from", "example.com"}]
                  }
                ]}
    end

    test "a Microsoft-style field" do
      value =
        " spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=example.com; dkim=none (message not signed)" <>
          " header.d=none;dmarc=none action=none header.from=example.com;compauth=pass reason=100"

      assert AuthResults.parse("mx.example.org;" <> value) ==
               {:ok, "mx.example.org",
                [
                  %{
                    method: "spf",
                    result: "pass",
                    reason: nil,
                    properties: [{"smtp.mailfrom", "example.com"}]
                  },
                  %{
                    method: "dkim",
                    result: "none",
                    reason: nil,
                    properties: [{"header.d", "none"}]
                  },
                  %{
                    method: "dmarc",
                    result: "none",
                    reason: nil,
                    properties: [{"action", "none"}, {"header.from", "example.com"}]
                  },
                  %{method: "compauth", result: "pass", reason: "100", properties: []}
                ]}
    end

    test "versions, case, unquoted base64 and stray words" do
      value =
        ~s{ "mx one" 1 ; DKIM/1=PASS Header.D=example.com header.b=ab/c+d= extra; ; SPF = SoftFail} <>
          ~s{ (comment) Reason = "x y" smtp.mailfrom="a b"@example.com;}

      assert AuthResults.parse(value) ==
               {:ok, "mx one",
                [
                  %{
                    method: "dkim",
                    result: "pass",
                    reason: nil,
                    properties: [{"header.d", "example.com"}, {"header.b", "ab/c+d="}]
                  },
                  %{
                    method: "spf",
                    result: "softfail",
                    reason: "x y",
                    properties: [{"smtp.mailfrom", ~s("a b"@example.com)}]
                  }
                ]}
    end

    test "none" do
      assert AuthResults.parse("mx.example.org 1; (nothing) NONE") == {:ok, "mx.example.org", []}
      assert AuthResults.parse("mx.example.org") == {:ok, "mx.example.org", []}
    end

    test "unparsable values" do
      for value <- [
            "",
            "; spf=pass",
            "mx junk; spf=pass",
            "mx; spf",
            "mx; spf=",
            "mx; =pass",
            "mx; @@",
            ~s(mx; spf=pass smtp.mailfrom="unterminated),
            "mx; spf=pass =x"
          ] do
        assert AuthResults.parse(value) == :error, value
      end
    end
  end
end
