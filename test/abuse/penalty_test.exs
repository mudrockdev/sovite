defmodule Sovite.Abuse.PenaltyTest do
  use ExUnit.Case, async: true

  alias Sovite.Abuse.Penalty
  alias Sovite.Test.TelemetryForwarder

  defp start(opts) do
    name = :"penalty_#{System.unique_integer([:positive])}"
    start_supervised!({Penalty, [name: name] ++ opts})
    name
  end

  test "bans a key after too many failures within the window" do
    TelemetryForwarder.attach([[:sovite, :abuse, :penalty, :banned]])
    name = start(max_failures: 3, window: 60_000, ban_time: 60_000)

    refute Penalty.banned?(name, :ip)
    assert Penalty.failure(name, :ip) == :ok
    assert Penalty.failure(name, :ip) == :ok
    assert Penalty.failure(name, :ip) == :banned
    assert Penalty.banned?(name, :ip)
    refute Penalty.banned?(name, :other)
    assert_received {:telemetry, _, %{failures: 3}, %{penalty: ^name, key: :ip, ban_time: 60_000}}

    assert Penalty.failure(name, :ip) == :banned
    refute_received {:telemetry, _, _, %{penalty: ^name}}

    assert Penalty.reset(name, :ip) == :ok
    refute Penalty.banned?(name, :ip)
  end

  test "failures older than the window are forgotten, and bans expire" do
    name = start(max_failures: 2, window: 50, ban_time: 50)
    assert Penalty.failure(name, :ip) == :ok
    Process.sleep(60)
    assert Penalty.failure(name, :ip) == :ok
    assert Penalty.failure(name, :ip) == :banned
    Process.sleep(60)
    refute Penalty.banned?(name, :ip)
  end

  test "purges old entries" do
    name = start(max_failures: 5, window: 10, ban_time: 10, cleanup_interval: 20)
    Penalty.failure(name, :ip)
    Process.sleep(80)
    assert :ets.tab2list(name) == []
  end
end
