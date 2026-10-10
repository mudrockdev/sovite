defmodule Sovite.Abuse.GreylistTest do
  use ExUnit.Case, async: true

  alias Sovite.Abuse.Greylist

  doctest Greylist

  @t0 ~U[2026-01-01 00:00:00Z]
  @day 86_400

  defp at(seconds), do: DateTime.add(@t0, seconds)

  describe "triplet/3" do
    test "reduces the client address to its network" do
      assert {"192.0.2.0/24", _, _} = Greylist.triplet({192, 0, 2, 200}, "", "a@b")

      assert {"2001:db8:1:2::/64", _, _} =
               Greylist.triplet({0x2001, 0xDB8, 1, 2, 3, 4, 5, 6}, "", "a@b")

      assert {"192.0.2.0/24", _, _} =
               Greylist.triplet({0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x02C8}, "", "a@b")
    end

    test "loosens the sender" do
      sender = fn address -> elem(Greylist.triplet({192, 0, 2, 1}, address, "a@b"), 1) end

      assert sender.("") == ""
      assert sender.("Alice@Example.COM") == "alice@example.com"
      assert sender.("prvs=1234abcdef=alice@example.com") == "alice@example.com"
      assert sender.("PRVS=1234ABCDEF=Alice@example.com") == "alice@example.com"
      assert sender.("msprvs1=19aBc0dEf=alice@example.com") == "alice@example.com"
      assert sender.("btv1==1234abcdef==alice@example.com") == "alice@example.com"
      assert sender.("bounce-123-456@list.example") == "bounce-#-#@list.example"
      assert sender.("prvs=1234abcdef=bounce-42@mx1.list.example") == "bounce-#@mx1.list.example"
      assert sender.("\"a@1\"@example.com") == "\"a@#\"@example.com"
      assert sender.("user42") == "user#"
    end

    test "lower-cases the recipient" do
      assert {_, _, "bob+tag1@example.com"} =
               Greylist.triplet({192, 0, 2, 1}, "", "Bob+Tag1@Example.com")
    end
  end

  test "key/1 is a stable SHA-256 of the triplet" do
    key = Greylist.key({"192.0.2.0/24", "a@b", "c@d"})
    assert key =~ ~r/\A[0-9a-f]{64}\z/
    assert key == Greylist.key({"192.0.2.0/24", "a@b", "c@d"})
    refute key == Greylist.key({"192.0.2.0/24", "a@b", "c@e"})
    refute Greylist.key({"n", "a", "bc"}) == Greylist.key({"n", "ab", "c"})
  end

  describe "check/3" do
    test "defers a new triplet, then passes it after the delay" do
      assert {{:defer, 300}, entry} = Greylist.check(nil, ~U[2026-01-01 00:00:00.123456Z])

      assert entry == %{
               first_seen: @t0,
               last_seen: @t0,
               passed_at: nil,
               expires_at: at(2 * @day)
             }

      assert {{:defer, 240}, entry} = Greylist.check(entry, at(60))
      assert entry == %{entry | first_seen: @t0, last_seen: at(60), expires_at: at(2 * @day)}

      assert {{:defer, 1}, _} = Greylist.check(entry, at(299))

      assert {:pass, entry} = Greylist.check(entry, at(300))

      assert entry == %{
               first_seen: @t0,
               last_seen: at(300),
               passed_at: at(300),
               expires_at: at(300 + 35 * @day)
             }

      assert {:pass, entry} = Greylist.check(entry, at(@day))
      assert entry == %{entry | passed_at: at(300), last_seen: at(@day)}
      assert entry.expires_at == at(36 * @day)
    end

    test "passes at the end of the retry window, and starts over after it" do
      {_, entry} = Greylist.check(nil, @t0)
      assert {:pass, _} = Greylist.check(entry, at(2 * @day))

      assert {{:defer, 300}, entry} = Greylist.check(entry, at(2 * @day + 1))
      assert entry.first_seen == at(2 * @day + 1)
      assert entry.expires_at == at(4 * @day + 1)
    end

    test "forgets a passed triplet unused for too long" do
      {_, entry} = Greylist.check(nil, @t0)
      {:pass, entry} = Greylist.check(entry, at(300))
      assert {:pass, _} = Greylist.check(entry, at(300 + 35 * @day))

      assert {{:defer, 300}, entry} = Greylist.check(entry, at(301 + 35 * @day))
      assert %{first_seen: first_seen, last_seen: first_seen, passed_at: nil} = entry
      assert first_seen == at(301 + 35 * @day)
    end

    test "takes options in milliseconds" do
      opts = [delay: 1500, retry_window: 10_000, max_age: 20_000]
      assert {{:defer, 2}, entry} = Greylist.check(nil, @t0, opts)
      assert entry.expires_at == at(10)
      assert {{:defer, 1}, _} = Greylist.check(entry, at(1), opts)
      assert {:pass, entry} = Greylist.check(entry, at(2), opts)
      assert entry.expires_at == at(22)
      assert {{:defer, 2}, _} = Greylist.check(entry, at(23), opts)
    end
  end
end
