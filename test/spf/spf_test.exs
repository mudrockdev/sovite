defmodule Sovite.SPFTest do
  use ExUnit.Case, async: true

  alias Sovite.SPF
  alias Sovite.SPF.Result
  alias Sovite.Test.{FakeDNS, TelemetryForwarder}

  @ip {192, 0, 2, 3}
  @ip6 {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0xCB01}
  @mapped {0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0203}

  defmodule SlowDNS do
    @behaviour Sovite.DNS.Resolver

    @impl true
    def lookup(_name, _type, opts) do
      Process.sleep(Keyword.fetch!(opts, :sleep))
      {:ok, ["v=spf1 +all"]}
    end
  end

  # Checks example.com with the given records, plus `spf` as its SPF record.
  defp check(spf, records \\ %{}, ip \\ @ip, opts \\ []) do
    records = Map.put(records, {"example.com", :txt}, [spf])
    SPF.check_host(FakeDNS.resolver(records), ip, "example.com", "alice@example.com", opts)
  end

  defp result(spf, records \\ %{}, ip \\ @ip, opts \\ []),
    do: check(spf, records, ip, opts).result

  describe "record selection" do
    test "no record is none" do
      resolver = FakeDNS.resolver(%{{"nodata.example", :a} => [@ip]})

      assert SPF.check_host(resolver, @ip, "missing.example", "a@missing.example") ==
               %Result{result: :none, domain: "missing.example", reason: "no SPF record"}

      assert SPF.check_host(resolver, @ip, "nodata.example", "a@nodata.example").result == :none

      resolver =
        FakeDNS.resolver(%{
          {"example.com", :txt} => ["google-site-verification=x", "v=spf10 -all"]
        })

      assert SPF.check_host(resolver, @ip, "example.com", "a@example.com").result == :none
    end

    test "the version is case-insensitive and other TXT records are ignored" do
      resolver = FakeDNS.resolver(%{{"example.com", :txt} => ["something else", "V=SPF1 -all"]})

      assert SPF.check_host(resolver, @ip, "example.com", "a@example.com") ==
               %Result{result: :fail, domain: "example.com", mechanism: "-all"}
    end

    test "more than one record is permerror" do
      resolver = FakeDNS.resolver(%{{"example.com", :txt} => ["v=spf1 -all", "v=spf1 +all"]})

      assert SPF.check_host(resolver, @ip, "example.com", "a@example.com") ==
               %Result{result: :permerror, domain: "example.com", reason: "multiple SPF records"}
    end

    test "a DNS error is temperror" do
      resolver = FakeDNS.resolver(%{{"example.com", :txt} => {:error, :servfail}})

      assert SPF.check_host(resolver, @ip, "example.com", "a@example.com") ==
               %Result{
                 result: :temperror,
                 domain: "example.com",
                 reason: "DNS error for example.com: servfail"
               }
    end

    test "a malformed domain is none, without lookups" do
      long_label = String.duplicate("a", 64) <> ".example.com"
      long_name = String.duplicate("abcdefghi.", 25) <> "example.com"

      for domain <- ["localhost", "a..example.com", ".example.com", long_label, long_name, ""] do
        resolver = FakeDNS.resolver(%{{domain, :txt} => {:error, :servfail}})
        result = SPF.check_host(resolver, @ip, domain, "a@example.com")
        assert {domain, result.result} == {domain, :none}
        assert result.reason =~ "invalid domain"
      end

      domain = String.duplicate("a", 63) <> ".example.com"
      resolver = FakeDNS.resolver(%{{domain, :txt} => ["v=spf1 -all"]})
      assert SPF.check_host(resolver, @ip, domain, "a@" <> domain).result == :fail
      assert SPF.check_host(resolver, @ip, domain <> ".", "a@" <> domain).result == :fail
    end

    test "a syntax error anywhere is permerror" do
      assert check("v=spf1 +all foo") == %Result{
               result: :permerror,
               domain: "example.com",
               reason: ~s(unknown mechanism "foo")
             }

      assert result("v=spf1 +all ip4:192.0.2.1/33") == :permerror
      assert result("v=spf1 a:%{c}.example.com -all") == :permerror
      assert result("v=spf1 exists:%{d0}.example.com -all") == :permerror
      assert result("v=spf1 exists:%{d.example.com -all") == :permerror
      assert result("v=spf1 -all redirect=a.example redirect=b.example") == :permerror
    end

    test "unknown modifiers are ignored" do
      assert result("v=spf1 foo=bar moo.cow-1=%{d} -all") == :fail
    end
  end

  describe "qualifiers" do
    test "decide the result of a match" do
      for {spf, expected} <- [
            {"v=spf1 all", :pass},
            {"v=spf1 +all", :pass},
            {"v=spf1 -all", :fail},
            {"v=spf1 ~all", :softfail},
            {"v=spf1 ?all", :neutral}
          ] do
        assert {spf, result(spf)} == {spf, expected}
      end
    end

    test "no match is neutral" do
      assert check("v=spf1 ip4:198.51.100.0/24") == %Result{
               result: :neutral,
               domain: "example.com"
             }

      assert check("v=spf1") == %Result{result: :neutral, domain: "example.com"}
    end

    test "the first match wins" do
      assert check("v=spf1 -ip4:192.0.2.3 +all") ==
               %Result{result: :fail, domain: "example.com", mechanism: "-ip4:192.0.2.3"}
    end
  end

  describe "ip4 and ip6" do
    test "ip4" do
      assert check("v=spf1 ip4:192.0.2.0/24 -all").mechanism == "ip4:192.0.2.0/24"
      assert result("v=spf1 ip4:192.0.2.3 -all") == :pass
      assert result("v=spf1 ip4:192.0.2.4 -all") == :fail
      assert result("v=spf1 ip4:192.0.2.128/25 -all") == :fail
      assert result("v=spf1 ip4:0.0.0.0/0 -all") == :pass
      # Host bits past the prefix are ignored.
      assert result("v=spf1 ip4:192.0.2.200/24 -all") == :pass
    end

    test "ip4 matches IPv4-mapped IPv6 clients but no other IPv6 ones" do
      assert result("v=spf1 ip4:192.0.2.0/24 -all", %{}, @mapped) == :pass
      assert result("v=spf1 ip4:0.0.0.0/0 -all", %{}, @ip6) == :fail
    end

    test "ip6" do
      assert result("v=spf1 ip6:2001:db8::/32 -all", %{}, @ip6) == :pass
      assert result("v=spf1 ip6:2001:db8::cb01 -all", %{}, @ip6) == :pass
      assert result("v=spf1 ip6:2001:db8::cb00/127 -all", %{}, @ip6) == :pass
      assert result("v=spf1 ip6:2001:db8::cb00/128 -all", %{}, @ip6) == :fail
      assert result("v=spf1 ip6:2001:db9::/32 -all", %{}, @ip6) == :fail
      assert result("v=spf1 ip6:::/0 -all", %{}, @ip) == :fail
    end
  end

  describe "a" do
    test "looks up A records for IPv4 clients" do
      records = %{
        {"example.com", :a} => [{198, 51, 100, 1}, @ip],
        {"other.example", :a} => [{192, 0, 2, 200}],
        {"other.example", :aaaa} => [@ip6]
      }

      assert check("v=spf1 a -all", records).mechanism == "a"
      assert result("v=spf1 a:other.example -all", records) == :fail
      assert result("v=spf1 a:other.example/24 -all", records) == :pass
      assert result("v=spf1 a:other.example//0 -all", records) == :fail
      assert result("v=spf1 a:other.example -all", records, @mapped) == :fail
      assert result("v=spf1 a:other.example/24 -all", records, @mapped) == :pass
    end

    test "looks up AAAA records for IPv6 clients" do
      records = %{
        {"example.com", :a} => [@ip],
        {"example.com", :aaaa} => [{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}]
      }

      assert result("v=spf1 a -all", records, @ip6) == :fail
      assert result("v=spf1 a//64 -all", records, @ip6) == :pass
      assert result("v=spf1 a/0 -all", records, @ip6) == :fail
      assert result("v=spf1 a:example.com/32//64 -all", records, @ip6) == :pass
    end

    test "a name without addresses is no match" do
      assert result("v=spf1 a:missing.example -all") == :fail
      assert result("v=spf1 a -all") == :fail
    end

    test "a DNS error is temperror" do
      records = %{{"down.example", :a} => {:error, :timeout}}

      assert check("v=spf1 a:down.example -all", records) == %Result{
               result: :temperror,
               domain: "example.com",
               reason: "DNS error for down.example: timeout"
             }
    end

    test "a target with an empty label is no match" do
      assert result("v=spf1 a:%{l}.x.example.com -all") == :fail

      resolver =
        FakeDNS.resolver(%{
          {"example.com", :txt} => ["v=spf1 a:%{l}.x.example.com -all"],
          {"a..b.x.example.com", :a} => {:error, :servfail}
        })

      assert SPF.check_host(resolver, @ip, "example.com", "a..b@example.com").result == :fail
    end
  end

  describe "mx" do
    test "matches the addresses of the MX hosts" do
      records = %{
        {"example.com", :mx} => [{10, "mx1.example.com"}, {20, "mx2.example.com"}],
        {"mx1.example.com", :a} => [{198, 51, 100, 1}],
        {"mx2.example.com", :a} => [@ip],
        {"mx2.example.com", :aaaa} => [{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}]
      }

      assert check("v=spf1 mx -all", records).mechanism == "mx"
      assert result("v=spf1 mx:example.com -all", records) == :pass
      assert result("v=spf1 mx -all", records, @ip6) == :fail
      assert result("v=spf1 mx//64 -all", records, @ip6) == :pass
      assert result("v=spf1 mx:other.example/24 -all", records) == :fail
    end

    test "cidr lengths apply to the MX hosts' addresses" do
      records = %{
        {"example.com", :mx} => [{10, "mx.example.com"}],
        {"mx.example.com", :a} => [{192, 0, 2, 1}]
      }

      assert result("v=spf1 mx -all", records) == :fail
      assert result("v=spf1 mx/24 -all", records) == :pass
    end

    test "more than 10 MX records is permerror" do
      ten = for i <- 1..10, into: %{}, do: {{"mx#{i}.example.com", :a}, [{198, 51, 100, i}]}
      ten = Map.put(ten, {"example.com", :mx}, for(i <- 1..10, do: {i, "mx#{i}.example.com"}))
      assert result("v=spf1 mx -all", ten) == :fail

      eleven = Map.put(ten, {"example.com", :mx}, for(i <- 1..11, do: {i, "mx#{i}.example.com"}))

      assert check("v=spf1 mx -all", eleven) == %Result{
               result: :permerror,
               domain: "example.com",
               reason: "too many MX records for example.com"
             }
    end

    test "skips Null MX and hosts that do not resolve" do
      records = %{
        {"example.com", :mx} => [{0, "."}, {10, "gone.example.com"}, {20, "mx.example.com"}],
        {"mx.example.com", :a} => [@ip]
      }

      assert result("v=spf1 mx -all", records) == :pass
    end

    test "a host lookup error is temperror unless another host matches" do
      records = %{
        {"example.com", :mx} => [{10, "down.example.com"}, {20, "mx.example.com"}],
        {"down.example.com", :a} => {:error, :servfail},
        {"mx.example.com", :a} => [@ip]
      }

      assert result("v=spf1 mx -all", records) == :pass

      records = Map.put(records, {"mx.example.com", :a}, [{198, 51, 100, 1}])

      assert check("v=spf1 mx -all", records).reason ==
               "DNS error for down.example.com: servfail"
    end

    test "an MX lookup error is temperror" do
      assert result("v=spf1 mx -all", %{{"example.com", :mx} => {:error, :servfail}}) ==
               :temperror
    end

    test "MX host lookups do not count toward the limits" do
      records = for i <- 1..10, into: %{}, do: {{"mx#{i}.example.com", :a}, []}

      records =
        Map.put(records, {"example.com", :mx}, for(i <- 1..10, do: {i, "mx#{i}.example.com"}))

      assert result("v=spf1 mx mx mx mx mx -all", records, @ip, max_void_lookups: 0) == :fail
    end
  end

  describe "ptr" do
    @reverse "3.2.0.192.in-addr.arpa"

    test "matches a validated name in the target domain" do
      records = %{
        {@reverse, :ptr} => ["other.example", "mail.example.com"],
        {"other.example", :a} => [@ip],
        {"mail.example.com", :a} => [@ip]
      }

      assert check("v=spf1 ptr -all", records).mechanism == "ptr"
      assert result("v=spf1 ptr:example.com -all", records) == :pass
      assert result("v=spf1 ptr:mail.example.com -all", records) == :pass
      assert result("v=spf1 ptr:other.example -all", records) == :pass
      assert result("v=spf1 ptr:ail.example.com -all", records) == :fail
      assert result("v=spf1 ptr:example.net -all", records) == :fail
    end

    test "names must resolve back to the client" do
      records = %{
        {@reverse, :ptr} => ["mail.example.com"],
        {"mail.example.com", :a} => [{198, 51, 100, 1}]
      }

      assert result("v=spf1 ptr -all", records) == :fail
      assert result("v=spf1 ptr -all", Map.delete(records, {"mail.example.com", :a})) == :fail

      records = Map.put(records, {"mail.example.com", :a}, {:error, :servfail})
      assert result("v=spf1 ptr -all", records) == :fail
    end

    test "only the first 10 names are considered" do
      names = for i <- 1..10, do: "host#{i}.example.net"

      records = %{
        {@reverse, :ptr} => names ++ ["mail.example.com"],
        {"mail.example.com", :a} => [@ip]
      }

      assert result("v=spf1 ptr -all", records) == :fail

      assert result("v=spf1 ptr -all", %{
               records
               | {@reverse, :ptr} => ["mail.example.com" | names]
             }) ==
               :pass
    end

    test "a PTR lookup error is no match" do
      assert result("v=spf1 ptr -all", %{{@reverse, :ptr} => {:error, :servfail}}) == :fail
    end

    test "IPv6" do
      reverse = "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"

      records = %{
        {reverse, :ptr} => ["mail.example.com"],
        {"mail.example.com", :aaaa} => [@ip6]
      }

      assert result("v=spf1 ptr -all", records, @ip6) == :pass
    end
  end

  describe "exists" do
    test "matches any A record" do
      records = %{{"3.2.0.192.alice.allow.example.com", :a} => [{127, 0, 0, 2}]}

      assert check("v=spf1 exists:%{ir}.%{l}.allow.%{d} -all", records).mechanism ==
               "exists:%{ir}.%{l}.allow.%{d}"

      assert result("v=spf1 exists:nothing.example.com -all", records) == :fail
    end

    test "always looks up A records" do
      name = "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.allow.example.com"
      records = %{{name, :a} => [{127, 0, 0, 2}]}
      assert result("v=spf1 exists:%{ir}.allow.%{d} -all", records, @ip6) == :pass

      assert result("v=spf1 exists:%{ir}.allow.%{d} -all", %{{name, :aaaa} => [@ip6]}, @ip6) ==
               :fail
    end

    test "IPv4-mapped clients expand as IPv4" do
      records = %{{"3.2.0.192.in-addr.allow.example.com", :a} => [{127, 0, 0, 2}]}
      assert result("v=spf1 exists:%{ir}.%{v}.allow.%{d} -all", records, @mapped) == :pass
    end

    test "a DNS error is temperror" do
      records = %{{"x.example.com", :a} => {:error, :refused}}
      assert result("v=spf1 exists:x.example.com -all", records) == :temperror
    end
  end

  describe "include" do
    defp include(inner, extra \\ %{}) do
      records = Map.put(extra, {"inner.example", :txt}, inner)
      check("v=spf1 include:inner.example -all", records)
    end

    test "pass matches" do
      assert include(["v=spf1 +all"]) ==
               %Result{result: :pass, domain: "example.com", mechanism: "include:inner.example"}

      assert check("v=spf1 ~include:inner.example", %{{"inner.example", :txt} => ["v=spf1 +all"]}).result ==
               :softfail
    end

    test "fail, softfail, and neutral do not match" do
      for inner <- ["v=spf1 -all", "v=spf1 ~all", "v=spf1 ?all", "v=spf1"] do
        assert {inner, include([inner])} ==
                 {inner, %Result{result: :fail, domain: "example.com", mechanism: "-all"}}
      end
    end

    test "temperror is temperror" do
      assert include({:error, :servfail}) == %Result{
               result: :temperror,
               domain: "example.com",
               reason: "DNS error for inner.example: servfail"
             }

      assert include(["v=spf1 a:down.example -all"], %{{"down.example", :a} => {:error, :timeout}}).result ==
               :temperror
    end

    test "permerror and none are permerror" do
      assert include(["v=spf1 foo"]).result == :permerror
      assert include(["v=spf1 -all", "v=spf1 +all"]).result == :permerror

      assert check("v=spf1 include:inner.example -all") == %Result{
               result: :permerror,
               domain: "example.com",
               reason: "no SPF record at include target inner.example"
             }

      assert result("v=spf1 include:%{l}.x.example.com -all", %{}, @ip) == :permerror
    end

    test "the sender carries over and the domain changes" do
      records = %{
        {"inner.example", :txt} => ["v=spf1 exists:%{l}.%{d}.check.example.com -all"],
        {"alice.inner.example.check.example.com", :a} => [{127, 0, 0, 2}]
      }

      assert result("v=spf1 include:inner.example -all", records) == :pass
    end

    test "the included record's exp is not used" do
      records = %{
        {"inner.example", :txt} => ["v=spf1 -all exp=explain.example.com"],
        {"explain.example.com", :txt} => ["inner explanation"]
      }

      assert check("v=spf1 include:inner.example -all", records).explanation == nil
    end
  end

  describe "redirect" do
    test "is used when nothing matches" do
      records = %{{"_spf.example.net", :txt} => ["v=spf1 ip4:192.0.2.0/24 -all"]}

      assert check("v=spf1 ip4:198.51.100.1 redirect=_spf.example.net", records) ==
               %Result{result: :pass, domain: "example.com", mechanism: "ip4:192.0.2.0/24"}

      assert result("v=spf1 redirect=_spf.example.net", records, {198, 51, 100, 2}) == :fail
    end

    test "is ignored when a mechanism matches" do
      assert result("v=spf1 ~all redirect=_spf.example.net") == :softfail
      assert result("v=spf1 redirect=_spf.example.net ?all") == :neutral
    end

    test "the target's domain is used for macros" do
      records = %{
        {"_spf.example.net", :txt} => ["v=spf1 a -all"],
        {"_spf.example.net", :a} => [@ip]
      }

      assert result("v=spf1 redirect=_spf.example.net", records) == :pass
    end

    test "a target without a record is permerror" do
      assert check("v=spf1 redirect=_spf.example.net") == %Result{
               result: :permerror,
               domain: "example.com",
               reason: "no SPF record at redirect target _spf.example.net"
             }
    end

    test "the target's exp is used and the original's is not" do
      records = %{
        {"_spf.example.net", :txt} => ["v=spf1 -all exp=net.example.org"],
        {"com.example.org", :txt} => ["from com"],
        {"net.example.org", :txt} => ["from net"]
      }

      assert check("v=spf1 exp=com.example.org redirect=_spf.example.net", records).explanation ==
               "from net"

      records = Map.put(records, {"_spf.example.net", :txt}, ["v=spf1 -all"])

      assert check("v=spf1 exp=com.example.org redirect=_spf.example.net", records).explanation ==
               nil
    end
  end

  describe "DNS lookup limits" do
    defp includes(count) do
      for i <- 1..count, into: %{}, do: {{"i#{i}.example.net", :txt}, ["v=spf1 -all"]}
    end

    defp include_terms(count), do: Enum.map_join(1..count, " ", &"include:i#{&1}.example.net")

    test "10 lookups are fine, 11 are permerror" do
      assert result("v=spf1 #{include_terms(10)} -all", includes(10)) == :fail

      assert check("v=spf1 #{include_terms(11)} -all", includes(11)) == %Result{
               result: :permerror,
               domain: "example.com",
               reason: "too many DNS lookups"
             }
    end

    test "every DNS term counts" do
      records =
        Map.merge(includes(1), %{
          {"example.com", :a} => [{198, 51, 100, 1}],
          {"example.com", :mx} => [{10, "mx.example.com"}],
          {"mx.example.com", :a} => [{198, 51, 100, 1}],
          {"3.2.0.192.in-addr.arpa", :ptr} => ["host.example.net"],
          {"x.example.com", :a} => [{127, 0, 0, 2}],
          {"_spf.example.net", :txt} => ["v=spf1 -all"]
        })

      spf =
        "v=spf1 a mx ptr -exists:y.example.com include:i1.example.net a mx ptr ip4:198.51.100.0/24"

      assert result(spf <> " a redirect=_spf.example.net", records) == :fail
      assert result(spf <> " a a redirect=_spf.example.net", records) == :permerror

      assert result(spf <> " redirect=_spf.example.net", records, @ip, max_void_lookups: 0) ==
               :permerror
    end

    test "the limit spans nested records" do
      # example.com -> n1 -> n2 -> ... each include is one lookup.
      chain = fn depth ->
        for i <- 1..depth, into: %{} do
          next = if i == depth, do: "-all", else: "include:n#{i + 1}.example.net"
          {{"n#{i}.example.net", :txt}, ["v=spf1 #{next}"]}
        end
      end

      assert result("v=spf1 include:n1.example.net -all", chain.(10)) == :fail
      assert result("v=spf1 include:n1.example.net -all", chain.(11)) == :permerror
    end

    test ":max_lookups" do
      assert result("v=spf1 #{include_terms(3)} -all", includes(3), @ip, max_lookups: 2) ==
               :permerror

      assert result("v=spf1 #{include_terms(3)} -all", includes(3), @ip, max_lookups: 3) == :fail
    end

    test "more than 2 void lookups are permerror" do
      records = %{{"nodata.example.com", :txt} => ["x"]}

      assert result("v=spf1 a:gone1.example.com a:nodata.example.com -all", records) == :fail

      assert check(
               "v=spf1 a:gone1.example.com exists:gone2.example.com mx:nodata.example.com -all",
               records
             ) ==
               %Result{
                 result: :permerror,
                 domain: "example.com",
                 reason: "too many void DNS lookups"
               }

      assert result("v=spf1 a:gone.example.com -all", %{}, @ip, max_void_lookups: 0) == :permerror
      assert result("v=spf1 ptr -all", %{}, @ip, max_void_lookups: 0) == :permerror
    end
  end

  describe "macros" do
    test "p expands to a validated name, preferring the current domain" do
      records = %{
        {"3.2.0.192.in-addr.arpa", :ptr} => ["other.example.net", "mail.example.com"],
        {"other.example.net", :a} => [@ip],
        {"mail.example.com", :a} => [@ip],
        {"mail.example.com.allow.example.org", :a} => [{127, 0, 0, 2}]
      }

      assert result("v=spf1 exists:%{p}.allow.example.org -all", records) == :pass

      records = Map.delete(records, {"mail.example.com", :a})
      assert result("v=spf1 exists:%{p}.allow.example.org -all", records) == :fail

      records = Map.put(records, {"other.example.net.allow.example.org", :a}, [{127, 0, 0, 2}])
      assert result("v=spf1 exists:%{p}.allow.example.org -all", records) == :pass

      records = %{{"unknown.allow.example.org", :a} => [{127, 0, 0, 2}]}
      assert result("v=spf1 exists:%{p}.allow.example.org -all", records) == :pass
    end

    test "p counts as a lookup" do
      records = %{{"x.example.org", :a} => [{127, 0, 0, 2}]}
      assert result("v=spf1 exists:x.example.org -all", records, @ip, max_lookups: 1) == :pass

      assert result("v=spf1 exists:x%{p}.example.org -all", records, @ip, max_lookups: 1) ==
               :permerror
    end

    test "h is the HELO name" do
      records = %{{"mx.example.org.helo.example.com", :a} => [{127, 0, 0, 2}]}

      assert result("v=spf1 exists:%{h}.helo.%{d} -all", records, @ip, helo: "mx.example.org") ==
               :pass

      assert result("v=spf1 exists:%{h}.helo.%{d} -all", records) == :fail
    end
  end

  describe "explanations" do
    test "exp= explains a fail" do
      records = %{
        {"explain.example.com", :txt} => ["%{i} is not one of %{d}'s designated mail servers."]
      }

      assert check("v=spf1 -all exp=explain.%{d}", records) == %Result{
               result: :fail,
               domain: "example.com",
               mechanism: "-all",
               explanation: "192.0.2.3 is not one of example.com's designated mail servers."
             }
    end

    test "may use c, r, and t" do
      records = %{{"explain.example.com", :txt} => ["%{c} via %{r} at %{t}: see %{L}%_page"]}

      assert check("v=spf1 -all exp=explain.example.com", records, @ip6,
               receiver: "mx.example.org",
               now: 1_700_000_000
             ).explanation == "2001:db8::cb01 via mx.example.org at 1700000000: see alice page"
    end

    test "only a fail is explained" do
      records = %{{"explain.example.com", :txt} => ["no"]}
      assert check("v=spf1 ~all exp=explain.example.com", records).explanation == nil
      assert check("v=spf1 +all exp=explain.example.com", records).explanation == nil
    end

    test "problems leave the explanation out" do
      for answer <- [{:error, :servfail}, [], ["one", "two"], ["bad %{x} macro"], ["café"]] do
        records = %{{"explain.example.com", :txt} => answer}

        assert {answer, check("v=spf1 -all exp=explain.example.com", records)} ==
                 {answer, %Result{result: :fail, domain: "example.com", mechanism: "-all"}}
      end

      assert check("v=spf1 -all exp=explain.example.com").explanation == nil
      assert check("v=spf1 -all exp=%{l}.x.example.com").explanation == nil

      # The p macro is over the lookup limit.
      records = %{{"explain.example.com", :txt} => ["%{p}"]}

      assert check("v=spf1 -all exp=explain.example.com", records, @ip, max_lookups: 0).explanation ==
               nil

      records = %{
        {"explain.example.com", :txt} => ["%{p}"],
        {"3.2.0.192.in-addr.arpa", :ptr} => ["mail.example.com"],
        {"mail.example.com", :a} => [@ip]
      }

      assert check("v=spf1 -all exp=explain.example.com", records).explanation ==
               "mail.example.com"
    end
  end

  describe "timeout" do
    test "a check over its budget is temperror" do
      resolver = {SlowDNS, sleep: 200}

      assert SPF.check_host(resolver, @ip, "example.com", "a@example.com", timeout: 20) ==
               %Result{result: :temperror, domain: "example.com", reason: "timed out after 20 ms"}

      resolver = {SlowDNS, sleep: 0}

      assert SPF.check_host(resolver, @ip, "example.com", "a@example.com", timeout: 1000).result ==
               :pass
    end
  end

  describe "check_host/5" do
    test "a sender without a local part is postmaster" do
      records = %{
        {"example.com", :txt} => ["v=spf1 exists:%{l}.%{o}.check.example.org -all"],
        {"postmaster.example.com.check.example.org", :a} => [{127, 0, 0, 2}]
      }

      resolver = FakeDNS.resolver(records)
      assert SPF.check_host(resolver, @ip, "example.com", "example.com").result == :pass
      assert SPF.check_host(resolver, @ip, "example.com", "@example.com").result == :pass
      assert SPF.check_host(resolver, @ip, "example.com", "bob@example.com").result == :fail
    end

    test "rejects unknown options" do
      assert_raise ArgumentError, fn -> check("v=spf1 -all", %{}, @ip, bogus: 1) end
    end

    test "emits telemetry for the top-level check only" do
      TelemetryForwarder.attach([[:sovite, :spf, :check, :start], [:sovite, :spf, :check, :stop]])

      records = %{
        {"telemetry.example", :txt} => ["v=spf1 include:inner.telemetry.example -all"],
        {"inner.telemetry.example", :txt} => ["v=spf1 +all"]
      }

      SPF.check_host(FakeDNS.resolver(records), @ip, "telemetry.example", "a@telemetry.example")

      assert_receive {:telemetry, [:sovite, :spf, :check, :start], %{system_time: _},
                      %{domain: "telemetry.example", ip: @ip}}

      assert_receive {:telemetry, [:sovite, :spf, :check, :stop], %{duration: _},
                      %{domain: "telemetry.example", ip: @ip, result: :pass}}

      refute_received {:telemetry, _, _, %{domain: "inner.telemetry.example"}}
    end
  end

  describe "check_mail_from/5" do
    test "checks the sender's domain" do
      records = %{
        {"example.com", :txt} => ["v=spf1 exists:%{l}.%{h}.check.%{d} -all"],
        {"alice.mx.example.org.check.example.com", :a} => [{127, 0, 0, 2}]
      }

      result =
        SPF.check_mail_from(FakeDNS.resolver(records), @ip, "alice@example.com", "mx.example.org")

      assert %Result{result: :pass, domain: "example.com"} = result
    end

    test "the null sender checks postmaster at the HELO name" do
      records = %{
        {"mx.example.org", :txt} => ["v=spf1 exists:%{l}.%{o}.check.example.com -all"],
        {"postmaster.mx.example.org.check.example.com", :a} => [{127, 0, 0, 2}]
      }

      resolver = FakeDNS.resolver(records)

      assert %Result{result: :pass, domain: "mx.example.org"} =
               SPF.check_mail_from(resolver, @ip, "", "mx.example.org")

      assert %Result{result: :none} = SPF.check_mail_from(resolver, @ip, "", nil)
    end

    test "a sender without @ is postmaster at that domain" do
      records = %{
        {"example.com", :txt} => ["v=spf1 exists:%{l}.check.example.org -all"],
        {"postmaster.check.example.org", :a} => [{127, 0, 0, 2}]
      }

      assert %Result{result: :pass, domain: "example.com"} =
               SPF.check_mail_from(FakeDNS.resolver(records), @ip, "example.com", nil)
    end
  end

  describe "check_helo/4" do
    test "checks the HELO name with postmaster as the local part" do
      records = %{
        {"mx.example.org", :txt} => ["v=spf1 exists:%{l}.%{h}.check.example.com -all"],
        {"postmaster.mx.example.org.check.example.com", :a} => [{127, 0, 0, 2}]
      }

      assert %Result{result: :pass, domain: "mx.example.org"} =
               SPF.check_helo(FakeDNS.resolver(records), @ip, "mx.example.org")
    end

    test "an address literal or a name that is not a FQDN is none without lookups" do
      resolver = {SlowDNS, sleep: 60_000}

      for helo <- [
            "[192.0.2.3]",
            "[IPv6:2001:db8::1]",
            "localhost",
            "192.0.2.3",
            "-bad.example",
            nil
          ] do
        assert %Result{result: :none, domain: ^helo, reason: "HELO name is not a domain name"} =
                 SPF.check_helo(resolver, @ip, helo)
      end
    end
  end
end
