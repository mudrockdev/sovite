defmodule Sovite.SRSTest do
  use ExUnit.Case, async: true

  alias Sovite.SRS

  doctest SRS

  @now ~U[2026-10-10 12:00:00Z]
  @opts [secrets: ["s3cret"], now: @now]

  defp forward!(address, domain, opts \\ @opts) do
    {:ok, srs} = SRS.forward(address, domain, opts)
    srs
  end

  # The hash as libsrs2 computes it, for checking the format by hand.
  defp hash(secret, data) do
    :hmac
    |> :crypto.mac(:sha, secret, String.downcase(data))
    |> Base.encode64()
    |> binary_part(0, 4)
  end

  defp stamp(datetime) do
    day = datetime |> DateTime.to_unix() |> div(86_400) |> rem(1024)
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    <<:binary.at(chars, div(day, 32)), :binary.at(chars, rem(day, 32))>>
  end

  describe "forward/3" do
    test "SRS0 for a plain address" do
      tt = stamp(@now)
      hh = hash("s3cret", tt <> "example.com" <> "Alice")

      assert forward!("Alice@example.com", "fwd.example.net") ==
               "SRS0=#{hh}=#{tt}=example.com=Alice@fwd.example.net"
    end

    test "the day counter" do
      # 2026-10-10 is day 20736; 20736 mod 1024 = 256 = 8 * 32 + 0.
      assert forward!("a@example.com", "fwd.example.net") =~ ~r/\ASRS0=....=IA=/

      assert forward!("a@example.com", "fwd.example.net",
               secrets: ["s"],
               now: ~U[1970-01-01 00:00:00Z]
             ) =~
               ~r/\ASRS0=....=AA=/
    end

    test "SRS1 for an SRS0 address from another forwarder" do
      srs0 = forward!("alice@example.com", "hop1.example")
      "SRS0" <> rest = srs0 |> String.split("@") |> hd()

      srs1 = forward!(srs0, "hop2.example")
      hh = hash("s3cret", "hop1.example" <> rest)
      assert srs1 == "SRS1=#{hh}=hop1.example=#{rest}@hop2.example"
      assert srs1 =~ "=hop1.example==" <> String.slice(rest, 1..-1//1)
    end

    test "SRS1 keeps the first hop when forwarded again" do
      srs1 = "alice@example.com" |> forward!("hop1.example") |> forward!("hop2.example")
      [_tag, _hash, rest] = srs1 |> String.split("@") |> hd() |> String.split("=", parts: 3)
      [hop, user] = String.split(rest, "=", parts: 2)

      srs1_again = forward!(srs1, "hop3.example", secrets: ["other"], now: @now)
      assert srs1_again == "SRS1=#{hash("other", hop <> user)}=#{rest}@hop3.example"
      assert {:ok, srs0} = SRS.reverse(srs1_again, secrets: ["other"])
      assert srs0 =~ "@hop1.example"
    end

    test "an SRS0 address with another separator" do
      srs0 = "SRS0+HHHH=TT=example.com=alice@hop1.example"
      hh = hash("s3cret", "hop1.example+HHHH=TT=example.com=alice")

      assert forward!(srs0, "hop2.example") ==
               "SRS1=#{hh}=hop1.example=+HHHH=TT=example.com=alice@hop2.example"
    end

    test "a broken SRS1 address is wrapped like any other" do
      assert forward!("SRS1=nohost@hop1.example", "hop2.example") =~
               ~r/\ASRS0=.*=hop1\.example=SRS1=nohost@hop2\.example\z/
    end

    test "an address already at the SRS domain is left alone" do
      assert SRS.forward("bob@FWD.example.net", "fwd.example.NET", @opts) ==
               {:ok, "bob@FWD.example.net"}
    end

    test "invalid addresses" do
      for address <- ["", "alice", "@example.com", "alice@", "a@b@example.com"] do
        assert SRS.forward(address, "fwd.example.net", @opts) == {:error, :invalid_address}
      end
    end

    test "requires secrets" do
      assert_raise KeyError, fn -> SRS.forward("a@example.com", "fwd.example.net", []) end
    end
  end

  describe "reverse/2" do
    test "round trip of SRS0" do
      srs = forward!("Alice.Smith+tag=x@Example.COM", "fwd.example.net")
      assert SRS.reverse(srs, @opts) == {:ok, "Alice.Smith+tag=x@Example.COM"}
    end

    test "round trip of SRS1" do
      srs0 = forward!("alice@example.com", "hop1.example", secrets: ["one"], now: @now)
      srs1 = forward!(srs0, "hop2.example", secrets: ["two"], now: @now)

      assert SRS.reverse(srs1, secrets: ["two"], now: @now) == {:ok, srs0}
      assert SRS.reverse(srs0, secrets: ["one"], now: @now) == {:ok, "alice@example.com"}
      assert SRS.reverse(srs1, secrets: ["one"], now: @now) == {:error, :bad_hash}
    end

    test "survives case mangling" do
      srs = forward!("alice@example.com", "fwd.example.net")
      assert SRS.reverse(String.downcase(srs), @opts) == {:ok, "alice@example.com"}
      assert SRS.reverse(String.upcase(srs), @opts) == {:ok, "ALICE@EXAMPLE.COM"}

      srs1 = forward!(srs, "hop2.example")
      assert {:ok, srs0} = SRS.reverse(String.upcase(srs1), @opts)
      assert String.downcase(srs0) == String.downcase(srs)
    end

    test "secret rotation" do
      old = forward!("alice@example.com", "fwd.example.net", secrets: ["old"], now: @now)
      new = forward!("alice@example.com", "fwd.example.net", secrets: ["new", "old"], now: @now)
      assert old != new

      rotated = [secrets: ["new", "old"], now: @now]
      assert SRS.reverse(old, rotated) == {:ok, "alice@example.com"}
      assert SRS.reverse(new, rotated) == {:ok, "alice@example.com"}
      assert SRS.reverse(old, secrets: ["new"], now: @now) == {:error, :bad_hash}
    end

    test "bad hash" do
      srs = forward!("alice@example.com", "fwd.example.net")
      tampered = String.replace(srs, "=alice@", "=mallory@")
      assert SRS.reverse(tampered, @opts) == {:error, :bad_hash}

      "SRS0=" <> <<_hash::binary-size(4), rest::binary>> = srs
      assert SRS.reverse("SRS0=xyz" <> rest, @opts) == {:error, :bad_hash}
      assert SRS.reverse("SRS0=xyzzy" <> rest, @opts) == {:error, :bad_hash}
    end

    test "expired" do
      srs = forward!("alice@example.com", "fwd.example.net")
      later = fn days -> [secrets: ["s3cret"], now: DateTime.add(@now, days, :day)] end

      assert SRS.reverse(srs, later.(21)) == {:ok, "alice@example.com"}
      assert SRS.reverse(srs, later.(22)) == {:error, :expired}
      assert SRS.reverse(srs, [{:max_age, 30} | later.(22)]) == {:ok, "alice@example.com"}
      # A timestamp from the future is very old, as the counter wraps.
      assert SRS.reverse(srs, later.(-1)) == {:error, :expired}
    end

    test "wrap-around of the day counter" do
      # Day 20479 is 1023 mod 1024 ("77"); the next day is 0 ("AA").
      sent = ~U[2026-01-26 12:00:00Z]
      assert sent |> DateTime.to_unix() |> div(86_400) == 20_479

      srs = forward!("alice@example.com", "fwd.example.net", secrets: ["s3cret"], now: sent)
      assert srs =~ "=77=example.com="

      for days <- [1, 5, 21] do
        now = DateTime.add(sent, days, :day)
        assert SRS.reverse(srs, secrets: ["s3cret"], now: now) == {:ok, "alice@example.com"}
      end

      assert SRS.reverse(srs, secrets: ["s3cret"], now: DateTime.add(sent, 22, :day)) ==
               {:error, :expired}

      # 1024 days later the stamp looks fresh again; the hash cannot tell.
      assert SRS.reverse(srs, secrets: ["s3cret"], now: DateTime.add(sent, 1024, :day)) ==
               {:ok, "alice@example.com"}
    end

    test "the + and - separators" do
      "SRS0=" <> rest = forward!("alice@example.com", "fwd.example.net")

      for tag <- ["SRS0+", "SRS0-", "srs0=", "Srs0+"] do
        assert SRS.reverse(tag <> rest, @opts) == {:ok, "alice@example.com"}
      end

      srs1 = forward!("SRS0-" <> rest, "hop2.example")
      assert srs1 =~ "=fwd.example.net=-"
      "SRS1=" <> rest1 = srs1
      assert SRS.reverse("srs1+" <> rest1, @opts) == {:ok, "SRS0-" <> rest}
    end

    test "not an SRS address" do
      for address <- ["alice@example.com", "SRS2=a=b=c=d@x", "SRS0", "SRS0x=a@b", "alice", ""] do
        assert SRS.reverse(address, @opts) == {:error, :not_srs}
      end
    end

    test "malformed" do
      for address <- [
            "SRS0=HHHH=TT=example.com@fwd.example.net",
            "SRS0=HHHH=TT==alice@fwd.example.net",
            "SRS0==TT=example.com=alice@fwd.example.net",
            "SRS0=HHHH=T=example.com=alice@fwd.example.net",
            "SRS0=HHHH=T1=example.com=alice@fwd.example.net",
            "SRS0=HHHH=TTT=example.com=alice@fwd.example.net",
            "SRS0=HHHH=TT=example.com=alice",
            "SRS0=HHHH=TT=example.com=alice@",
            "SRS1=HHHH=hop1@fwd.example.net",
            "SRS1=HHHH==x@fwd.example.net",
            "SRS1==hop1==x@fwd.example.net"
          ] do
        assert SRS.reverse(address, @opts) == {:error, :malformed}, address
      end
    end
  end

  test "srs?/1" do
    assert SRS.srs?("SRS0=HHHH=TT=example.com=alice@fwd.example.net")
    assert SRS.srs?("srs1-x@fwd.example.net")
    assert SRS.srs?("SRS0+x")
    refute SRS.srs?("SRS0@fwd.example.net")
    refute SRS.srs?("SRS3=x@fwd.example.net")
    refute SRS.srs?("")
  end
end
