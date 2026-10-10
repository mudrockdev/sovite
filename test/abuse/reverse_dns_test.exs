defmodule Sovite.Abuse.ReverseDNSTest do
  use ExUnit.Case, async: true

  alias Sovite.Abuse.ReverseDNS
  alias Sovite.Test.FakeDNS

  doctest ReverseDNS

  @ip {192, 0, 2, 1}
  @ptr "1.2.0.192.in-addr.arpa"
  @ip6 {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}
  @ptr6 "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
  @mapped {0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0201}

  defp check(records, ip \\ @ip, opts \\ []),
    do: ReverseDNS.check(FakeDNS.resolver(records), ip, opts)

  test "reverse_name/1" do
    assert ReverseDNS.reverse_name(@ip) == @ptr
    assert ReverseDNS.reverse_name(@ip6) == @ptr6
    assert ReverseDNS.reverse_name(@mapped) == @ptr
  end

  describe "check/3" do
    test "confirms a name whose addresses include the client" do
      assert check(%{
               {@ptr, :ptr} => ["Mail.Example.COM"],
               {"mail.example.com", :a} => [{192, 0, 2, 9}, @ip]
             }) == {:ok, "mail.example.com"}
    end

    test "returns the first name that confirms" do
      records = %{
        {@ptr, :ptr} => ["one.example", "two.example", "three.example"],
        {"one.example", :a} => [{192, 0, 2, 9}],
        {"two.example", :a} => [@ip],
        {"three.example", :a} => [@ip]
      }

      assert check(records) == {:ok, "two.example"}
    end

    test "looks up AAAA records for IPv6 clients" do
      assert check(%{{@ptr6, :ptr} => ["v6.example"], {"v6.example", :aaaa} => [@ip6]}, @ip6) ==
               {:ok, "v6.example"}

      assert check(%{{@ptr6, :ptr} => ["v6.example"], {"v6.example", :a} => [@ip]}, @ip6) ==
               {:unconfirmed, ["v6.example"]}
    end

    test "checks IPv4-mapped addresses as IPv4" do
      assert check(%{{@ptr, :ptr} => ["mail.example"], {"mail.example", :a} => [@ip]}, @mapped) ==
               {:ok, "mail.example"}
    end

    test "returns unconfirmed names" do
      records = %{
        {@ptr, :ptr} => ["one.example", "Two.Example.", "three.example"],
        {"one.example", :a} => [{192, 0, 2, 9}],
        {"two.example", :aaaa} => [@ip6]
      }

      assert check(records) == {:unconfirmed, ["one.example", "two.example", "three.example"]}
    end

    test "skips invalid names" do
      records = %{
        {@ptr, :ptr} => ["bad_name.example", "-bad.example", "", "mail.example"],
        {"bad_name.example", :a} => [@ip],
        {"mail.example", :a} => [@ip]
      }

      assert check(records) == {:ok, "mail.example"}
      assert check(%{{@ptr, :ptr} => ["bad_name.example"]}) == :none
    end

    test "checks at most :max_names names" do
      records = %{
        {@ptr, :ptr} => ["one.example", "two.example"],
        {"two.example", :a} => [@ip]
      }

      assert check(records, @ip, max_names: 1) == {:unconfirmed, ["one.example"]}
      assert check(records, @ip, max_names: 2) == {:ok, "two.example"}

      names = for i <- 1..11, do: "host#{i}.example"
      records = %{{@ptr, :ptr} => names, {"host11.example", :a} => [@ip]}
      assert check(records) == {:unconfirmed, Enum.take(names, 10)}
    end

    test "returns none without PTR records" do
      assert check(%{}) == :none
      assert check(%{{@ptr, :txt} => ["no PTR here"]}) == :none
    end

    test "returns a temporary error when a lookup fails" do
      assert check(%{{@ptr, :ptr} => {:error, :servfail}}) == {:error, :temporary}

      records = %{
        {@ptr, :ptr} => ["down.example", "other.example"],
        {"down.example", :a} => {:error, :timeout},
        {"other.example", :a} => [{192, 0, 2, 9}]
      }

      assert check(records) == {:error, :temporary}

      # A name that confirms still wins.
      records = Map.put(records, {"other.example", :a}, [@ip])
      assert check(records) == {:ok, "other.example"}
    end
  end
end
