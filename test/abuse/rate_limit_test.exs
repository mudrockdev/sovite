defmodule Sovite.Abuse.RateLimitTest do
  use ExUnit.Case, async: true

  alias Sovite.Abuse.RateLimit
  alias Sovite.Test.TelemetryForwarder

  # The clock starts at the beginning of a bucket for every window used here.
  defp start(opts \\ []) do
    name = :"rate_limit_#{System.unique_integer([:positive])}"
    clock = :atomics.new(1, signed: false)
    :atomics.put(clock, 1, 1_000_000)

    pid =
      start_supervised!(
        {RateLimit, [name: name, clock: fn -> :atomics.get(clock, 1) end] ++ opts}
      )

    {name, pid, clock}
  end

  defp advance(clock, ms), do: :atomics.add(clock, 1, ms)

  test "limits each key and window separately" do
    {name, _pid, _clock} = start()

    assert RateLimit.hit(name, :ip, 2, 1000) == :ok
    assert RateLimit.hit(name, :ip, 2, 1000) == :ok
    assert RateLimit.hit(name, :ip, 2, 1000) == :limited
    assert RateLimit.hit(name, :other, 2, 1000) == :ok
    assert RateLimit.hit(name, :ip, 5, 10_000, 5) == :ok
    assert RateLimit.hit(name, :ip, 5, 10_000) == :limited

    assert RateLimit.count(name, :ip, 1000) == 2
    assert RateLimit.count(name, :other, 1000) == 1
    assert RateLimit.count(name, :ip, 10_000) == 5
    assert RateLimit.count(name, :ip, 100) == 0
  end

  test "refused hits are not counted" do
    {name, _pid, _clock} = start()

    assert RateLimit.hit(name, :ip, 3, 1000, 2) == :ok
    assert RateLimit.hit(name, :ip, 3, 1000, 2) == :limited
    assert RateLimit.count(name, :ip, 1000) == 2
    assert RateLimit.hit(name, :ip, 3, 1000) == :ok
    assert RateLimit.count(name, :ip, 1000) == 3
    assert RateLimit.hit(name, :ip, 3, 1000, 4) == :limited
  end

  test "the previous bucket slides out of the window" do
    {name, _pid, clock} = start()
    for _ <- 1..10, do: assert(RateLimit.hit(name, :ip, 10, 1000) == :ok)

    advance(clock, 1000)
    assert RateLimit.count(name, :ip, 1000) == 10
    assert RateLimit.hit(name, :ip, 10, 1000) == :limited

    advance(clock, 300)
    assert RateLimit.count(name, :ip, 1000) == 7
    assert RateLimit.hit(name, :ip, 10, 1000, 3) == :ok
    assert RateLimit.hit(name, :ip, 10, 1000) == :limited

    advance(clock, 600)
    assert RateLimit.count(name, :ip, 1000) == 4

    # A new bucket: only the 3 hits of the one before remain.
    advance(clock, 100)
    assert RateLimit.count(name, :ip, 1000) == 3
    advance(clock, 1000)
    assert RateLimit.count(name, :ip, 1000) == 0
  end

  test "add counts without a limit, and reset forgets every window" do
    {name, _pid, _clock} = start()

    assert RateLimit.add(name, :ip, 1000) == 1
    assert RateLimit.add(name, :ip, 1000, 4) == 5
    assert RateLimit.add(name, :ip, 60_000, 2) == 2
    assert RateLimit.add(name, :other, 1000) == 1
    assert RateLimit.hit(name, :ip, 5, 1000) == :limited

    assert RateLimit.reset(name, :ip) == :ok
    assert RateLimit.count(name, :ip, 1000) == 0
    assert RateLimit.count(name, :ip, 60_000) == 0
    assert RateLimit.count(name, :other, 1000) == 1
  end

  test "reports the first refused hit of each bucket" do
    TelemetryForwarder.attach([[:sovite, :abuse, :rate_limit, :exceeded]])
    {name, _pid, clock} = start()

    assert RateLimit.hit(name, :ip, 1, 1000) == :ok
    assert RateLimit.hit(name, :ip, 1, 1000) == :limited
    assert_received {:telemetry, _, %{limit: 1, window: 1000}, %{rate_limit: ^name, key: :ip}}

    assert RateLimit.hit(name, :ip, 1, 1000) == :limited
    refute_received {:telemetry, _, _, %{rate_limit: ^name}}

    assert RateLimit.hit(name, :ip, 1, 10_000) == :ok
    assert RateLimit.hit(name, :ip, 1, 10_000) == :limited
    assert_received {:telemetry, _, %{limit: 1, window: 10_000}, %{rate_limit: ^name, key: :ip}}

    advance(clock, 1000)
    assert RateLimit.hit(name, :ip, 1, 1000) == :limited
    assert_received {:telemetry, _, %{window: 1000}, %{rate_limit: ^name, key: :ip}}
  end

  test "purges buckets older than the previous one" do
    {name, pid, clock} = start()
    RateLimit.add(name, :ip, 1000)
    RateLimit.add(name, :ip, 10_000)

    advance(clock, 1000)
    send(pid, :cleanup)
    :sys.get_state(pid)
    assert RateLimit.count(name, :ip, 1000) == 1

    advance(clock, 1000)
    send(pid, :cleanup)
    :sys.get_state(pid)
    assert [{{:ip, 10_000, _}, 1, 0}] = :ets.match_object(name, {{:_, :_, :_}, :_, :_})
  end

  test "uses the system clock by default" do
    name = :"rate_limit_#{System.unique_integer([:positive])}"
    start_supervised!({RateLimit, name: name})
    assert RateLimit.hit(name, :ip, 1, 60_000) == :ok
    assert RateLimit.add(name, :ip, 60_000) in 1..2
  end
end
