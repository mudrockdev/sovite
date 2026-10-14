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
          {:recipient, "a@example.net", :delivered, Map.put(details("2.0.0"), :action, :relayed)},
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
          %{
            "type" => "recipient",
            "recipient" => "a@b",
            "code" => "2.0.0",
            "status" => "delivered",
            "at" => "2026-10-04T12:00:00Z",
            "smtp" => true,
            "action" => "teleported"
          },
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

  describe "DSN" do
    defp dsn_entry(records \\ []) do
      envelope = %Envelope{
        queue_id: "Q",
        sender: "a@example.org",
        recipients: ["b@example.net", "c@example.net", "d@example.net"],
        dsn: %{
          "b@example.net" => %{notify: [:success, :delay], orcpt: nil},
          "c@example.net" => %{notify: :never, orcpt: nil}
        },
        expanded: ["list@example.org"]
      }

      Entry.new(envelope, records)
    end

    defp delivered(address, action) do
      details = %{
        status: "2.0.0",
        reply: "ok",
        remote: nil,
        smtp: false,
        at: ~U[2026-10-04 12:00:00Z]
      }

      {:recipient, address, :delivered,
       if(action, do: Map.put(details, :action, action), else: details)}
    end

    test "NOTIFY decides which notifications are due" do
      entry = dsn_entry()
      assert Entry.notify?(entry, "b@example.net", :success)
      assert Entry.notify?(entry, "b@example.net", :delay)
      refute Entry.notify?(entry, "b@example.net", :failure)
      refute Entry.notify?(entry, "c@example.net", :failure)
      refute Entry.notify?(entry, "c@example.net", :delay)
      assert Entry.notify?(entry, "d@example.net", :failure)
      assert Entry.notify?(entry, "d@example.net", :delay)
      refute Entry.notify?(entry, "d@example.net", :success)
    end

    test "successes and expansions to report, until notified" do
      entry =
        dsn_entry([delivered("b@example.net", :relayed), delivered("d@example.net", :delivered)])

      assert [{"b@example.net", %{action: :relayed}}] = Entry.unnotified_successes(entry)
      assert Entry.unnotified_expansions(entry) == ["list@example.org"]

      entry = Entry.apply_record(entry, {:notified, ["b@example.net", "list@example.org"]})
      assert Entry.unnotified_successes(entry) == []
      assert Entry.unnotified_expansions(entry) == []

      # A server that reports itself: no action.
      assert dsn_entry([delivered("b@example.net", nil)]) |> Entry.unnotified_successes() == []
    end

    test "the envelope keeps the DSN parameters" do
      envelope = %{
        dsn_entry().envelope
        | ret: :full,
          envid: "E1",
          body_type: :binarymime,
          notification: :success,
          dsn: %{"b@example.net" => %{notify: [:success], orcpt: {"utf-8", "bü@example.net"}}},
          priority: -4,
          hold: {:until, ~U[2026-10-20 12:00:00Z]},
          deliver_by: %{deadline: ~U[2026-10-21 12:00:00Z], mode: :notify, trace: true},
          rrvs: %{"b@example.net" => {~U[2014-04-03 23:01:00Z], :continue}}
      }

      assert envelope
             |> Envelope.to_map()
             |> JSON.encode!()
             |> JSON.decode!()
             |> Envelope.from_map() ==
               {:ok, envelope}
    end
  end
end
