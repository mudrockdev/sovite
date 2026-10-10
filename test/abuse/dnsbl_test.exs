defmodule Sovite.Abuse.DNSBLTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Sovite.Abuse.DNSBL
  alias Sovite.Test.{FakeDNS, TelemetryForwarder}

  doctest DNSBL

  @ip {192, 0, 2, 99}
  @ip6 {0x2001, 0xDB8, 1, 2, 3, 4, 0x567, 0x89AB}

  # Answers from FakeDNS, after `:sleep` milliseconds for the names in
  # `:slow`. With `:notify`, tells that process about each lookup.
  defmodule TestDNS do
    @behaviour Sovite.DNS.Resolver

    @impl true
    def lookup(name, type, opts) do
      if pid = opts[:notify], do: send(pid, {:lookup, self(), name})
      if name in Keyword.get(opts, :slow, []), do: Process.sleep(Keyword.get(opts, :sleep, 0))
      if name in Keyword.get(opts, :crash, []), do: raise("resolver crashed")
      Sovite.DNS.lookup(FakeDNS.resolver(opts[:records]), name, type)
    end
  end

  defp resolver(records, opts), do: {TestDNS, [records: records] ++ opts}

  defp list(zone, weight, codes \\ []) do
    %{zone: zone, weight: weight, codes: Enum.map(codes, &code!/1)}
  end

  defp code!(code) do
    {:ok, pattern} = DNSBL.parse_code(code)
    pattern
  end

  describe "parse_code/1" do
    test "parses numbers, lists, and ranges" do
      pattern = code!("127.0.0.2")
      assert DNSBL.match?([{127, 0, 0, 2}], [pattern])
      refute DNSBL.match?([{127, 0, 0, 3}], [pattern])

      pattern = code!("127.0.0.[2..11]")
      assert DNSBL.match?([{127, 0, 0, 2}], [pattern])
      assert DNSBL.match?([{127, 0, 0, 11}], [pattern])
      refute DNSBL.match?([{127, 0, 0, 12}], [pattern])

      pattern = code!("127.0.[0..255].[1;3]")
      assert DNSBL.match?([{127, 0, 200, 1}], [pattern])
      assert DNSBL.match?([{127, 0, 0, 3}], [pattern])
      refute DNSBL.match?([{127, 0, 0, 2}], [pattern])

      pattern = code!("127.0.1.[2..99;102]")
      assert DNSBL.match?([{127, 0, 1, 50}], [pattern])
      assert DNSBL.match?([{127, 0, 1, 102}], [pattern])
      refute DNSBL.match?([{127, 0, 1, 100}], [pattern])
      refute DNSBL.match?([{127, 0, 2, 50}], [pattern])

      pattern = code!("[0..255].[0..255].[0..255].[0..255]")
      assert DNSBL.match?([{0, 0, 0, 0}, {255, 255, 255, 255}], [pattern])

      assert DNSBL.parse_code("127.0.0.[7]") == DNSBL.parse_code("127.0.0.7")
      assert DNSBL.parse_code("127.0.0.[7..7]") == DNSBL.parse_code("127.0.0.7")
    end

    test "rejects anything else with a readable message" do
      for code <- [
            "",
            "127.0.0",
            "127.0.0.2.",
            "127.0.0.2.1",
            " 127.0.0.2",
            "a.b.c.d",
            "127.0.0.-1",
            "127.0.0.+1",
            "1270.0.0.1",
            "127.0.0.[1",
            "127.0.0.1]",
            "127.0.0.[[1]]",
            "127.0.0.[]",
            "127.0.0.[1;;2]",
            "127.0.0.[1;]",
            "127.0.0.[1...2]",
            "127.0.0.[1..2..3]",
            "127.0.0.[..2]",
            "127.0.0.[ 1]",
            "127.0.0.[0x1]"
          ] do
        assert {:error, message} = DNSBL.parse_code(code), "accepted #{inspect(code)}"
        assert message =~ "invalid reply code #{inspect(code)}"
      end

      assert DNSBL.parse_code("127.0.0.256") ==
               {:error, ~s(invalid reply code "127.0.0.256": 256 is not between 0 and 255)}

      assert DNSBL.parse_code("127.0.0.[1..300]") ==
               {:error, ~s(invalid reply code "127.0.0.[1..300]": 300 is not between 0 and 255)}

      assert DNSBL.parse_code("127.0.0.[5..2]") ==
               {:error, ~s(invalid reply code "127.0.0.[5..2]": empty range 5..2)}

      assert DNSBL.parse_code("127.0.0.[1..2..3]") ==
               {:error, ~s(invalid reply code "127.0.0.[1..2..3]": invalid range "1..2..3")}

      assert {:error, "invalid reply code \"1.2.3\": expected four" <> _} =
               DNSBL.parse_code("1.2.3")
    end
  end

  describe "query names" do
    test "reverses IPv4 and IPv6 addresses (RFC 5782 §2.1, §2.4)" do
      assert DNSBL.query_name(@ip, "bl.example") == "99.2.0.192.bl.example"

      assert DNSBL.query_name(@ip6, "bl.example") ==
               "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.bl.example"
    end

    test "normalizes the zone and IPv4-mapped addresses" do
      assert DNSBL.query_name(@ip, "BL.Example.") == "99.2.0.192.bl.example"

      assert DNSBL.query_name({0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0263}, "bl.example") ==
               "99.2.0.192.bl.example"
    end

    test "builds domain queries (RFC 5782 §2.3)" do
      assert DNSBL.domain_query_name("Example.COM.", "RHSBL.example.") ==
               {:ok, "example.com.rhsbl.example"}

      assert DNSBL.domain_query_name("", "rhsbl.example") == :error
      assert DNSBL.domain_query_name(".", "rhsbl.example") == :error
      assert DNSBL.domain_query_name("[192.0.2.1]", "rhsbl.example") == :error
      assert DNSBL.domain_query_name("[IPv6:2001:db8::1]", "rhsbl.example") == :error

      # 239 + 1 + 13 = 253 bytes fit, one more does not.
      domain = String.duplicate("a", 63) <> "." <> String.duplicate("b", 175)
      assert {:ok, name} = DNSBL.domain_query_name(domain, "rhsbl.example")
      assert byte_size(name) == 253
      assert DNSBL.domain_query_name("c" <> domain, "rhsbl.example") == :error
    end
  end

  describe "lookup/2" do
    test "keeps only 127.0.0.0/8 answers" do
      resolver =
        FakeDNS.resolver(%{
          {"listed.example", :a} => [{127, 0, 0, 2}, {192, 0, 2, 1}, {127, 0, 0, 4}],
          {"public.example", :a} => [{10, 0, 0, 1}],
          {"nodata.example", :txt} => ["listed"]
        })

      assert DNSBL.lookup(resolver, "listed.example") == {:ok, [{127, 0, 0, 2}, {127, 0, 0, 4}]}
      assert DNSBL.lookup(resolver, "public.example") == {:ok, []}
      assert DNSBL.lookup(resolver, "nodata.example") == {:ok, []}
      assert DNSBL.lookup(resolver, "missing.example") == {:ok, []}
    end

    test "returns list operator errors and DNS errors" do
      resolver =
        FakeDNS.resolver(%{
          {"refused.example", :a} => [{127, 0, 0, 2}, {127, 255, 255, 254}],
          {"down.example", :a} => {:error, :servfail}
        })

      assert DNSBL.lookup(resolver, "refused.example") ==
               {:error, {:list_error, {127, 255, 255, 254}}}

      assert DNSBL.lookup(resolver, "down.example") == {:error, :servfail}
    end
  end

  describe "match?/2" do
    test "without patterns, any address matches" do
      assert DNSBL.match?([{127, 0, 0, 9}], [])
      refute DNSBL.match?([], [])
      refute DNSBL.match?([], [code!("127.0.0.2")])
    end

    test "matches any address against any pattern" do
      codes = [code!("127.0.0.2"), code!("127.0.0.[10..11]")]
      assert DNSBL.match?([{127, 0, 0, 4}, {127, 0, 0, 11}], codes)
      refute DNSBL.match?([{127, 0, 0, 4}, {127, 0, 0, 12}], codes)
    end
  end

  describe "score/4" do
    test "adds the weights of the lists that list the address" do
      TelemetryForwarder.attach([[:sovite, :abuse, :dnsbl, :listed]])

      resolver =
        FakeDNS.resolver(%{
          {"99.2.0.192.score-bl.example", :a} => [{127, 0, 0, 2}],
          {"99.2.0.192.score-bl2.example", :a} => [{127, 0, 0, 3}],
          {"99.2.0.192.score-wl.example", :a} => [{127, 0, 9, 1}]
        })

      lists = [
        list("score-bl.example", 3),
        list("score-bl2.example", 2),
        list("score-wl.example", -4, ["127.0.[0..255].[1..3]"]),
        list("score-clean.example", 5)
      ]

      assert DNSBL.score(resolver, {:ip, @ip}, lists) == %{
               score: 1,
               hits: [
                 %{zone: "score-bl.example", weight: 3, codes: [{127, 0, 0, 2}]},
                 %{zone: "score-bl2.example", weight: 2, codes: [{127, 0, 0, 3}]},
                 %{zone: "score-wl.example", weight: -4, codes: [{127, 0, 9, 1}]}
               ],
               errors: []
             }

      assert_received {:telemetry, [:sovite, :abuse, :dnsbl, :listed], %{weight: 3},
                       %{zone: "score-bl.example", query: @ip, codes: [{127, 0, 0, 2}]}}

      assert_received {:telemetry, _, %{weight: -4}, %{zone: "score-wl.example", query: @ip}}
      refute_received {:telemetry, _, _, %{zone: "score-clean.example"}}
    end

    test "scores IPv6 addresses" do
      name = DNSBL.query_name(@ip6, "v6.example")
      resolver = FakeDNS.resolver(%{{name, :a} => [{127, 0, 0, 2}]})

      assert %{score: 7, hits: [%{zone: "v6.example"}]} =
               DNSBL.score(resolver, {:ip, @ip6}, [list("v6.example", 7)])
    end

    test "counts only the lists whose codes match" do
      resolver =
        resolver(%{{"99.2.0.192.codes.example", :a} => [{127, 0, 0, 2}, {127, 0, 0, 4}]},
          notify: self()
        )

      lists = [
        list("codes.example", 3, ["127.0.0.2"]),
        list("codes.example", 1, ["127.0.0.[10..11]"]),
        list("Codes.Example.", 2, ["127.0.0.[3..4]", "127.0.0.2"])
      ]

      assert DNSBL.score(resolver, {:ip, @ip}, lists) == %{
               score: 5,
               hits: [
                 %{zone: "codes.example", weight: 3, codes: [{127, 0, 0, 2}]},
                 %{zone: "Codes.Example.", weight: 2, codes: [{127, 0, 0, 2}, {127, 0, 0, 4}]}
               ],
               errors: []
             }

      # The lists share one query.
      assert_received {:lookup, _, "99.2.0.192.codes.example"}
      refute_received {:lookup, _, _}
    end

    test "scores domains" do
      resolver = FakeDNS.resolver(%{{"example.com.rhsbl.example", :a} => [{127, 0, 1, 2}]})
      lists = [list("rhsbl.example", 4), list("other.example", 1)]

      assert DNSBL.score(resolver, {:domain, "Example.COM"}, lists) == %{
               score: 4,
               hits: [%{zone: "rhsbl.example", weight: 4, codes: [{127, 0, 1, 2}]}],
               errors: []
             }
    end

    test "skips domains that cannot be queried" do
      resolver = resolver(%{}, notify: self())
      lists = [list("rhsbl.example", 4)]

      for domain <- ["", "[192.0.2.1]", String.duplicate("a.", 125) <> "example"] do
        assert DNSBL.score(resolver, {:domain, domain}, lists) ==
                 %{score: 0, hits: [], errors: []}
      end

      assert DNSBL.score(resolver, {:ip, @ip}, []) == %{score: 0, hits: [], errors: []}
      refute_received {:lookup, _, _}
    end

    test "errors and timeouts add nothing" do
      TelemetryForwarder.attach([
        [:sovite, :abuse, :dnsbl, :listed],
        [:sovite, :abuse, :dnsbl, :error]
      ])

      resolver =
        resolver(
          %{
            {"99.2.0.192.err-ok.example", :a} => [{127, 0, 0, 2}],
            {"99.2.0.192.err-down.example", :a} => {:error, :servfail},
            {"99.2.0.192.err-refused.example", :a} => [{127, 255, 255, 254}],
            {"99.2.0.192.err-slow.example", :a} => [{127, 0, 0, 2}]
          },
          slow: ["99.2.0.192.err-slow.example"],
          sleep: 5_000
        )

      lists = [
        list("err-ok.example", 1),
        list("err-down.example", 2),
        list("err-down.example", 2, ["127.0.0.2"]),
        list("err-refused.example", 4),
        list("err-slow.example", 8)
      ]

      started = System.monotonic_time(:millisecond)

      assert DNSBL.score(resolver, {:ip, @ip}, lists, timeout: 200) == %{
               score: 1,
               hits: [%{zone: "err-ok.example", weight: 1, codes: [{127, 0, 0, 2}]}],
               errors: ["err-down.example", "err-refused.example", "err-slow.example"]
             }

      assert System.monotonic_time(:millisecond) - started < 2_000

      assert_received {:telemetry, [:sovite, :abuse, :dnsbl, :error], %{},
                       %{zone: "err-down.example", query: @ip, reason: :servfail}}

      assert_received {:telemetry, _, %{},
                       %{zone: "err-refused.example", reason: {:list_error, {127, 255, 255, 254}}}}

      assert_received {:telemetry, _, %{}, %{zone: "err-slow.example", reason: :timeout}}
      refute_received {:telemetry, _, _, %{zone: "err-down.example"}}

      refute_received {:telemetry, [:sovite, :abuse, :dnsbl, :listed], _,
                       %{zone: "err-slow.example"}}
    end

    test "leaves no messages for a process that traps exits" do
      Process.flag(:trap_exit, true)
      name = "99.2.0.192.trap.example"
      resolver = resolver(%{{name, :a} => [{127, 0, 0, 2}]}, slow: [name], sleep: 5_000)

      assert DNSBL.score(resolver, {:ip, @ip}, [list("trap.example", 1)], timeout: 50) ==
               %{score: 0, hits: [], errors: ["trap.example"]}

      Process.sleep(50)
      refute_received _
    end
  end

  describe "async_score/4 and await/2" do
    test "returns the result, sending nothing before it is asked" do
      Process.flag(:trap_exit, true)
      resolver = FakeDNS.resolver(%{{"99.2.0.192.async.example", :a} => [{127, 0, 0, 2}]})
      handle = DNSBL.async_score(resolver, {:ip, @ip}, [list("async.example", 2)])

      Process.sleep(50)
      refute_received _

      assert DNSBL.await(handle, 1_000) ==
               {:ok,
                %{
                  score: 2,
                  hits: [%{zone: "async.example", weight: 2, codes: [{127, 0, 0, 2}]}],
                  errors: []
                }}

      Process.sleep(50)
      refute_received _
      refute Process.alive?(handle.pid)
    end

    test "waits for a result that is not ready yet" do
      name = "99.2.0.192.async-wait.example"
      resolver = resolver(%{{name, :a} => [{127, 0, 0, 2}]}, slow: [name], sleep: 100)
      handle = DNSBL.async_score(resolver, {:ip, @ip}, [list("async-wait.example", 2)])

      assert {:ok, %{score: 2}} = DNSBL.await(handle, 2_000)
      Process.sleep(50)
      refute_received _
    end

    test "kills the scoring on timeout and leaves no messages" do
      Process.flag(:trap_exit, true)
      name = "99.2.0.192.async-slow.example"
      resolver = resolver(%{{name, :a} => [{127, 0, 0, 2}]}, slow: [name], sleep: 5_000)
      handle = DNSBL.async_score(resolver, {:ip, @ip}, [list("async-slow.example", 2)])

      assert DNSBL.await(handle, 50) == {:error, :timeout}
      refute Process.alive?(handle.pid)
      Process.sleep(100)
      refute_received _
    end

    test "returns a timeout when the background process is gone" do
      name = "99.2.0.192.async-crash.example"
      resolver = resolver(%{{name, :a} => [{127, 0, 0, 2}]}, crash: [name])

      capture_log(fn ->
        handle = DNSBL.async_score(resolver, {:ip, @ip}, [list("async-crash.example", 2)])
        ref = Process.monitor(handle.pid)
        assert_receive {:DOWN, ^ref, :process, _, _}, 1_000

        assert DNSBL.await(handle, 1_000) == {:error, :timeout}
      end)

      Process.sleep(50)
      refute_received _
    end

    test "stops when the caller exits" do
      name = "99.2.0.192.async-orphan.example"
      test = self()

      resolver =
        resolver(%{{name, :a} => [{127, 0, 0, 2}]}, slow: [name], sleep: 5_000, notify: test)

      caller =
        spawn(fn ->
          send(
            test,
            {:handle, DNSBL.async_score(resolver, {:ip, @ip}, [list("async-orphan.example", 1)])}
          )

          receive do: (:exit -> :ok)
        end)

      assert_receive {:handle, handle}
      assert_receive {:lookup, lookup, ^name}
      server = Process.monitor(handle.pid)
      task = Process.monitor(lookup)

      send(caller, :exit)
      assert_receive {:DOWN, ^server, :process, _, _}, 1_000
      assert_receive {:DOWN, ^task, :process, _, _}, 1_000
    end

    test "stops on its own if nobody asks" do
      resolver = FakeDNS.resolver(%{})

      handle =
        DNSBL.async_score(resolver, {:ip, @ip}, [list("async-idle.example", 1)], timeout: 0)

      server = Process.monitor(handle.pid)

      refute_receive {:DOWN, ^server, :process, _, _}, 4_000
      assert_receive {:DOWN, ^server, :process, _, _}, 3_000
    end
  end
end
