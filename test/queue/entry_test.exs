defmodule Sovite.Queue.EntryTest do
  use ExUnit.Case, async: true

  alias Sovite.Queue.{Backoff, Entry, Envelope, Record}

  doctest Backoff

  @at ~U[2026-10-04 12:00:00Z]

  defp envelope(recipients \\ ["a@example.net", "b@example.net", "c@example.net"]),
    do: %Envelope{queue_id: "Q", sender: "s@example.org", recipients: recipients}

  defp details(status, reply \\ "reply"),
    do: %{status: status, reply: reply, remote: "mx.example.net[192.0.2.25]", smtp: true, at: @at}

  test "a new entry has every recipient pending" do
    entry = Entry.new(envelope())
    assert Entry.pending(entry) == ["a@example.net", "b@example.net", "c@example.net"]
    assert entry.attempts == 0
    refute Entry.done?(entry)
  end

  test "replays recipient outcomes, retries, notifications, and warnings" do
    entry =
      Entry.new(envelope(), [
        {:recipient, "a@example.net", :delivered, details("2.0.0")},
        {:recipient, "b@example.net", :failed, details("5.1.1")},
        {:recipient, "c@example.net", :deferred, details("4.2.2")},
        {:retry, 1, @at},
        :warned
      ])

    assert Entry.pending(entry) == ["c@example.net"]
    assert Entry.with_status(entry, :delivered) == ["a@example.net"]
    assert [{"b@example.net", %{status: "5.1.1"}}] = Entry.unnotified_failures(entry)
    assert entry.attempts == 1
    assert entry.next_attempt == @at
    assert entry.warned

    entry = Entry.apply_record(entry, {:notified, ["b@example.net"]})
    assert Entry.unnotified_failures(entry) == []
  end

  test "final outcomes never change" do
    entry =
      Entry.new(envelope(), [
        {:recipient, "a@example.net", :delivered, details("2.0.0")},
        {:recipient, "a@example.net", :deferred, details("4.0.0")},
        {:recipient, "a@example.net", :failed, details("5.0.0")}
      ])

    assert %{status: :delivered, details: %{status: "2.0.0"}} = entry.recipients["a@example.net"]
  end

  test "ignores records for unknown recipients" do
    entry =
      Entry.new(envelope(["a@example.net"]), [
        {:recipient, "x@example.net", :failed, details("5.0.0")},
        {:notified, ["x@example.net"]}
      ])

    assert Map.keys(entry.recipients) == ["a@example.net"]
  end

  test "records round-trip through their map form" do
    for record <- [
          {:recipient, "a@example.net", :deferred, details("4.4.1")},
          {:recipient, "a@example.net", :failed, %{details("5.1.2") | remote: nil, smtp: false}},
          {:notified, ["a@example.net", "b@example.net"]},
          {:retry, 3, @at},
          :warned
        ] do
      map = record |> Record.to_map() |> JSON.encode!() |> JSON.decode!()
      assert Record.from_map(map) == {:ok, record}
    end
  end

  test "rejects malformed records without creating atoms" do
    for bad <- [
          %{"type" => "nonsense"},
          %{"type" => "recipient", "recipient" => "a@b", "code" => "5.0.0", "status" => "lost"},
          %{"type" => "notified", "recipients" => [1]},
          %{"type" => "retry", "attempts" => 0, "next" => "2026-10-04T12:00:00Z"},
          %{"type" => "retry", "attempts" => 1, "next" => "soon"},
          "not a map"
        ] do
      assert Record.from_map(bad) == :error
    end
  end

  describe "Backoff.delay/2" do
    test "doubles up to the maximum" do
      delays = for n <- 1..8, do: Backoff.delay(n, min: 1000, max: 30_000, jitter: 0)
      assert delays == [1000, 2000, 4000, 8000, 16_000, 30_000, 30_000, 30_000]
      assert Backoff.delay(10_000, min: 1000, max: 30_000, jitter: 0) == 30_000
    end

    test "adds a bounded jitter" do
      delays = for _ <- 1..200, do: Backoff.delay(1, min: 1000, max: 30_000)
      assert Enum.all?(delays, &(&1 in 900..1100))
      assert delays |> Enum.uniq() |> length() > 1
    end
  end
end
