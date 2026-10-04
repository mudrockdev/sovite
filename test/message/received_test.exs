defmodule Sovite.Message.ReceivedTest do
  use ExUnit.Case, async: true

  alias Sovite.Message.Date, as: MessageDate
  alias Sovite.Message.Received

  doctest Sovite.Message.Received
  doctest Sovite.Message.Date

  @date ~U[2026-10-04 12:00:00Z]

  defp fields(overrides \\ %{}) do
    Map.merge(
      %{
        helo: "client.example.net",
        remote_ip: {192, 0, 2, 7},
        by: "mx.example.com",
        protocol: "ESMTP",
        id: "0Q7c3XbK2mA9fZ",
        date: @date
      },
      overrides
    )
  end

  # A local time in a fixed-offset zone, built by hand since only Etc/UTC
  # is available without a time zone database.
  defp datetime(naive, utc_offset, std_offset \\ 0) do
    fields = %{
      time_zone: "Test/Zone",
      zone_abbr: "TST",
      utc_offset: utc_offset,
      std_offset: std_offset
    }

    struct!(DateTime, Map.merge(Map.from_struct(naive), fields))
  end

  describe "build/1" do
    test "includes the for clause for a single recipient" do
      assert Received.build(fields(%{for: "user@example.com"})) ==
               "Received: from client.example.net ([192.0.2.7])\r\n" <>
                 "\tby mx.example.com with ESMTP id 0Q7c3XbK2mA9fZ\r\n" <>
                 "\tfor <user@example.com>; Sun, 4 Oct 2026 12:00:00 +0000\r\n"
    end

    test "omits the for clause when :for is nil or absent" do
      expected =
        "Received: from client.example.net ([192.0.2.7])\r\n" <>
          "\tby mx.example.com with ESMTP id 0Q7c3XbK2mA9fZ; Sun, 4 Oct 2026 12:00:00 +0000\r\n"

      assert Received.build(fields()) == expected
      assert Received.build(fields(%{for: nil})) == expected
    end

    test "formats IPv6 address literals" do
      header = Received.build(fields(%{remote_ip: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}}))
      assert header =~ ~r/\AReceived: from client\.example\.net \(\[IPv6:2001:db8::1\]\)\r\n/
    end

    test "omits the id clause when :id is nil or absent" do
      expected =
        "Received: from client.example.net ([192.0.2.7])\r\n" <>
          "\tby mx.example.com with ESMTP; Sun, 4 Oct 2026 12:00:00 +0000\r\n"

      assert Received.build(fields(%{id: nil})) == expected
      assert Received.build(Map.delete(fields(), :id)) == expected
    end

    test "uses the offset of the given date" do
      date = datetime(~N[2026-10-04 17:30:00], 5 * 3600 + 30 * 60)
      assert Received.build(fields(%{date: date})) =~ "; Sun, 4 Oct 2026 17:30:00 +0530\r\n"
    end

    test "defaults the date to now" do
      header = Received.build(Map.delete(fields(), :date))
      [_, date] = Regex.run(~r/; (.*)\r\n\z/, header)
      assert date =~ ~r/\A\w{3}, \d{1,2} \w{3} \d{4} \d{2}:\d{2}:\d{2} \+0000\z/
    end

    test "ends every line in CRLF and indents continuation lines with a tab" do
      for f <- [fields(), fields(%{for: "user@example.com"}), fields(%{id: nil})] do
        header = Received.build(f)
        assert String.ends_with?(header, "\r\n")
        lines = header |> String.trim_trailing("\r\n") |> String.split("\r\n")
        assert ["Received: " <> _ | continuations] = lines
        assert continuations != []
        assert Enum.all?(continuations, &String.starts_with?(&1, "\t"))
        refute header |> String.replace("\r\n", "") |> String.contains?(["\r", "\n"])
      end
    end
  end

  test "protocol/1 builds RFC 3848 transmission types" do
    assert Received.protocol([]) == "SMTP"
    assert Received.protocol(esmtp: false, tls: true, auth: true) == "SMTP"
    assert Received.protocol(esmtp: true) == "ESMTP"
    assert Received.protocol(esmtp: true, tls: true) == "ESMTPS"
    assert Received.protocol(esmtp: true, auth: true) == "ESMTPA"
    assert Received.protocol(esmtp: true, tls: true, auth: true) == "ESMTPSA"
    assert Received.protocol(lmtp: true) == "LMTP"
    assert Received.protocol(lmtp: true, esmtp: true, tls: true, auth: true) == "LMTPSA"
  end

  describe "Date.format/1" do
    test "formats UTC dates without zero-padding the day" do
      assert MessageDate.format(~U[2026-01-01 00:00:00Z]) == "Thu, 1 Jan 2026 00:00:00 +0000"
      assert MessageDate.format(~U[2024-02-29 23:59:59Z]) == "Thu, 29 Feb 2024 23:59:59 +0000"

      assert MessageDate.format(~U[2026-12-28 09:05:07.123456Z]) ==
               "Mon, 28 Dec 2026 09:05:07 +0000"
    end

    test "formats positive and negative offsets using the local date" do
      assert MessageDate.format(datetime(~N[2026-10-04 17:30:00], 5 * 3600 + 30 * 60)) ==
               "Sun, 4 Oct 2026 17:30:00 +0530"

      assert MessageDate.format(datetime(~N[2026-10-03 23:15:00], -8 * 3600)) ==
               "Sat, 3 Oct 2026 23:15:00 -0800"

      assert MessageDate.format(datetime(~N[2026-10-03 12:00:00], -30 * 60)) ==
               "Sat, 3 Oct 2026 12:00:00 -0030"
    end

    test "includes the daylight saving offset" do
      assert MessageDate.format(datetime(~N[2026-07-01 12:00:00], -8 * 3600, 3600)) ==
               "Wed, 1 Jul 2026 12:00:00 -0700"
    end
  end
end
