defmodule Sovite.Message.ParsingTest do
  use ExUnit.Case, async: true

  alias Sovite.Message.{Date, MessageID, Received}

  doctest MessageID

  test "dates in their obsolete forms" do
    assert Date.parse("Fri, 31 Dec 99 23:59:60 GMT") == {:ok, ~U[1999-12-31 23:59:59Z]}
    assert Date.parse("1 Jan 101 00:00 -0130") == {:ok, ~U[2001-01-01 01:30:00Z]}

    assert Date.parse("  3 feb 2026 08:05:01 (a (nested) comment) A") ==
             {:ok, ~U[2026-02-03 08:05:01Z]}

    assert Date.parse("3 Feb 2026 8 : 05") == {:ok, ~U[2026-02-03 08:05:00Z]}

    for bad <- [
          "30 Feb 2026 10:00 +0000",
          "1 Foo 2026 10:00",
          "1 Jan 2026 25:00",
          "1 Jan 2026 10:00 +0360",
          ""
        ],
        do: assert(Date.parse(bad) == :error, bad)
  end

  test "message IDs" do
    assert MessageID.parse(~s(<"a b"@[192.0.2.1]>)) == {:ok, ~s("a b"), "[192.0.2.1]"}
    assert MessageID.parse("<a@localhost>") == {:ok, "a", "localhost"}

    for bad <- ["<a@b", "<@b>", "<a@>", "<a b@c>", "<a@b> <c@d>", ""],
        do: assert(MessageID.parse(bad) == :error, bad)
  end

  test "received fields as MTAs write them" do
    assert Received.parse(
             "by mx.example.com (Postfix, from userid 1000)\r\n\tid 123; 4 Oct 2026 12:00 +0000"
           ) ==
             %{from: nil, ip: nil, by: "mx.example.com", date: ~U[2026-10-04 12:00:00Z]}

    assert %{from: "[ipv6:2001:db8::1]", ip: "2001:db8::1", by: nil, date: nil} =
             Received.parse("from [IPv6:2001:db8::1] (unknown [IPv6:2001:db8::1]); garbage")

    assert Received.parse("") == %{from: nil, ip: nil, by: nil, date: nil}
  end
end
