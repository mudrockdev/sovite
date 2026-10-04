defmodule Sovite.DNS.MXTest do
  use ExUnit.Case, async: true

  alias Sovite.DNS.MX
  alias Sovite.Test.FakeDNS

  @v4 {192, 0, 2, 25}
  @v6 {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x25}

  describe "hosts/3" do
    test "orders hosts by preference" do
      resolver =
        FakeDNS.resolver(%{
          {"example.com", :mx} => [
            {20, "mx2.example.com"},
            {10, "mx1.example.com"},
            {30, "mx3.example.com"}
          ]
        })

      assert MX.hosts(resolver, "example.com") ==
               {:ok, [{10, "mx1.example.com"}, {20, "mx2.example.com"}, {30, "mx3.example.com"}]}
    end

    test "shuffles hosts with equal preference" do
      records = for i <- 1..8, do: {10, "mx#{i}.example.com"}
      resolver = FakeDNS.resolver(%{{"example.com", :mx} => [{5, "best.example.com"} | records]})

      orders =
        for _ <- 1..50 do
          {:ok, [{5, "best.example.com"} | rest]} = MX.hosts(resolver, "example.com")
          assert Enum.sort(rest) == Enum.sort(records)
          rest
        end

      assert orders |> Enum.uniq() |> length() > 1
    end

    test "drops duplicate hosts" do
      resolver =
        FakeDNS.resolver(%{
          {"example.com", :mx} => [{10, "mx.example.com"}, {20, "MX.example.com"}]
        })

      assert MX.hosts(resolver, "example.com") == {:ok, [{10, "mx.example.com"}]}
    end

    test "uses the domain itself when it has no MX records (implicit MX)" do
      resolver = FakeDNS.resolver(%{{"example.com", :a} => [@v4]})
      assert MX.hosts(resolver, "example.com") == {:ok, [{0, "example.com"}]}

      resolver = FakeDNS.resolver(%{{"example.com", :aaaa} => [@v6]})
      assert MX.hosts(resolver, "example.com") == {:ok, [{0, "example.com"}]}

      resolver = FakeDNS.resolver(%{{"example.com", :txt} => ["v=spf1 -all"]})
      assert MX.hosts(resolver, "example.com") == {:error, :no_hosts}
    end

    test "recognizes a Null MX" do
      for null <- ["", "."] do
        resolver = FakeDNS.resolver(%{{"example.com", :mx} => [{0, null}]})
        assert MX.hosts(resolver, "example.com") == {:error, :null_mx}
      end

      resolver =
        FakeDNS.resolver(%{{"example.com", :mx} => [{0, ""}, {10, "mx.example.com"}]})

      assert MX.hosts(resolver, "example.com") == {:error, :null_mx}
    end

    test "separates permanent from temporary DNS errors" do
      resolver =
        FakeDNS.resolver(%{
          {"down.example", :mx} => {:error, :servfail},
          {"slow.example", :mx} => {:error, :timeout},
          {"addr.example", :a} => {:error, :timeout}
        })

      assert MX.hosts(resolver, "missing.example") == {:error, :nxdomain}
      assert MX.hosts(resolver, "down.example") == {:error, {:temporary, :servfail}}
      assert MX.hosts(resolver, "slow.example") == {:error, {:temporary, :timeout}}
      assert MX.hosts(resolver, "addr.example") == {:error, {:temporary, :timeout}}
    end

    test "excludes this server and worse MX hosts" do
      resolver =
        FakeDNS.resolver(%{
          {"example.com", :mx} => [
            {10, "primary.example.com"},
            {20, "Backup.Example.com"},
            {20, "other.example.com"},
            {30, "worse.example.com"}
          ]
        })

      assert MX.hosts(resolver, "example.com", exclude: ["backup.example.com"]) ==
               {:ok, [{10, "primary.example.com"}]}

      assert MX.hosts(resolver, "example.com", exclude: ["primary.example.com"]) ==
               {:error, :loops_back}

      assert {:ok, [_, _, _, _]} =
               MX.hosts(resolver, "example.com", exclude: ["elsewhere.example"])
    end
  end

  describe "resolve/3" do
    test "returns each host's addresses in the requested order" do
      resolver =
        FakeDNS.resolver(%{
          {"example.com", :mx} => [{10, "mx1.example.com"}, {20, "mx2.example.com"}],
          {"mx1.example.com", :a} => [@v4],
          {"mx1.example.com", :aaaa} => [@v6],
          {"mx2.example.com", :a} => [{192, 0, 2, 26}]
        })

      assert MX.resolve(resolver, "example.com") ==
               {:ok, [{"mx1.example.com", [@v6, @v4]}, {"mx2.example.com", [{192, 0, 2, 26}]}]}

      assert MX.resolve(resolver, "example.com", families: [:a, :aaaa]) ==
               {:ok, [{"mx1.example.com", [@v4, @v6]}, {"mx2.example.com", [{192, 0, 2, 26}]}]}

      assert MX.resolve(resolver, "example.com", families: [:aaaa]) ==
               {:ok, [{"mx1.example.com", [@v6]}]}
    end

    test "skips hosts without addresses" do
      resolver =
        FakeDNS.resolver(%{
          {"example.com", :mx} => [{10, "gone.example.com"}, {20, "mx.example.com"}],
          {"mx.example.com", :a} => [@v4]
        })

      assert MX.resolve(resolver, "example.com") == {:ok, [{"mx.example.com", [@v4]}]}
    end

    test "fails when no host has an address" do
      resolver = FakeDNS.resolver(%{{"example.com", :mx} => [{10, "gone.example.com"}]})
      assert MX.resolve(resolver, "example.com") == {:error, :no_addresses}

      resolver =
        FakeDNS.resolver(%{
          {"example.com", :mx} => [{10, "gone.example.com"}, {20, "down.example.com"}],
          {"down.example.com", :a} => {:error, :servfail},
          {"down.example.com", :aaaa} => {:error, :servfail}
        })

      assert MX.resolve(resolver, "example.com") == {:error, {:temporary, :servfail}}
    end

    test "passes MX errors through" do
      resolver = FakeDNS.resolver(%{{"example.com", :mx} => [{0, "."}]})
      assert MX.resolve(resolver, "example.com") == {:error, :null_mx}
    end
  end

  describe "addresses/3" do
    test "returns address literals without a lookup" do
      resolver = FakeDNS.resolver(%{})
      assert MX.addresses(resolver, "[192.0.2.1]") == {:ok, [{192, 0, 2, 1}]}

      assert MX.addresses(resolver, "[IPv6:2001:db8::1]") ==
               {:ok, [{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}]}
    end

    test "succeeds when one address family has records" do
      resolver =
        FakeDNS.resolver(%{
          {"mx.example.com", :a} => [@v4],
          {"mx.example.com", :aaaa} => {:error, :servfail}
        })

      assert MX.addresses(resolver, "mx.example.com") == {:ok, [@v4]}
      assert MX.addresses(resolver, "mx.example.com", [:aaaa]) == {:error, :servfail}
      assert MX.addresses(resolver, "other.example.com") == {:error, :nxdomain}
    end
  end
end
