defmodule Sovite.DNSTest do
  use ExUnit.Case, async: true

  alias Sovite.DNS
  alias Sovite.DNS.InetRes
  alias Sovite.Test.{FakeDNS, FakeNameserver}

  describe "InetRes.extract/2" do
    setup do
      answers = [
        rr(:cname, ~c"www.example.com.", ~c"example.com."),
        rr(:a, ~c"example.com.", {192, 0, 2, 1}),
        rr(:mx, ~c"example.com.", {10, ~c"mx1.example.com."}),
        rr(:mx, ~c"example.com.", {20, ~c"mx2.example.com"}),
        rr(:txt, ~c"example.com.", [~c"v=spf1 ", ~c"-all"])
      ]

      %{msg: :inet_dns.make_msg(anlist: answers)}
    end

    test "returns only records of the requested type", %{msg: msg} do
      assert InetRes.extract(msg, :a) == [{192, 0, 2, 1}]
      assert InetRes.extract(msg, :cname) == ["example.com"]
      assert InetRes.extract(msg, :aaaa) == []
    end

    test "converts MX exchanges to strings without the trailing dot", %{msg: msg} do
      assert InetRes.extract(msg, :mx) == [{10, "mx1.example.com"}, {20, "mx2.example.com"}]
    end

    test "joins TXT character strings", %{msg: msg} do
      assert InetRes.extract(msg, :txt) == ["v=spf1 -all"]
    end
  end

  describe "InetRes.lookup/3" do
    setup do
      {:ok, ns} =
        FakeNameserver.start_link(%{
          {"example.com", :mx} => [{10, ~c"mx.example.com"}],
          {"example.com", :txt} => [[~c"v=spf1 ", ~c"-all"]],
          {"mx.example.com", :a} => [{192, 0, 2, 25}],
          {"broken.example", :a} => :servfail,
          {"refused.example", :a} => :refused
        })

      %{resolver: {InetRes, nameservers: [FakeNameserver.address(ns)], timeout: 1_000, retry: 1}}
    end

    test "returns answers from the nameserver", %{resolver: resolver} do
      assert DNS.lookup(resolver, "example.com", :mx) == {:ok, [{10, "mx.example.com"}]}
      assert DNS.lookup(resolver, "example.com", :txt) == {:ok, ["v=spf1 -all"]}
      assert DNS.lookup(resolver, "MX.example.com", :a) == {:ok, [{192, 0, 2, 25}]}
    end

    test "distinguishes NODATA from NXDOMAIN", %{resolver: resolver} do
      assert DNS.lookup(resolver, "example.com", :aaaa) == {:ok, []}
      assert DNS.lookup(resolver, "missing.example", :a) == {:error, :nxdomain}
    end

    test "maps server failures to error atoms", %{resolver: resolver} do
      assert DNS.lookup(resolver, "broken.example", :a) == {:error, :servfail}
      assert DNS.lookup(resolver, "refused.example", :a) == {:error, :refused}
    end

    test "rejects names that cannot be sent as a query without querying" do
      assert InetRes.lookup("", :a, []) == {:error, :invalid_name}
      assert InetRes.lookup("bad name.example", :a, []) == {:error, :invalid_name}
      assert InetRes.lookup("bücher.example", :a, []) == {:error, :invalid_name}
      assert InetRes.lookup(String.duplicate("a", 254), :a, []) == {:error, :invalid_name}
    end
  end

  describe "InetRes.lookup_secure/3" do
    setup do
      tlsa = <<3, 1, 1>> <> :binary.copy(<<0xAB>>, 32)

      {:ok, ns} =
        FakeNameserver.start_link(%{
          {"_25._tcp.mx.signed.example", 52} => {:secure, [tlsa]},
          {"_25._tcp.mx.unsigned.example", 52} => [tlsa],
          {"_25._tcp.mx.junk.example", 52} => [<<3>>],
          {"signed.example", :mx} => {:secure, [{10, ~c"mx.signed.example"}]},
          {"broken.example", 52} => :servfail
        })

      %{resolver: {InetRes, nameservers: [FakeNameserver.address(ns)], timeout: 1_000, retry: 1}}
    end

    test "reports the AD bit", %{resolver: resolver} do
      record = {3, 1, 1, :binary.copy(<<0xAB>>, 32)}

      assert DNS.lookup_secure(resolver, "_25._tcp.mx.signed.example", :tlsa) ==
               {:ok, [record], true}

      assert DNS.lookup_secure(resolver, "_25._tcp.mx.unsigned.example", :tlsa) ==
               {:ok, [record], false}

      assert DNS.lookup_secure(resolver, "signed.example", :mx) ==
               {:ok, [{10, "mx.signed.example"}], true}

      assert DNS.lookup(resolver, "_25._tcp.mx.signed.example", :tlsa) == {:ok, [record]}
    end

    test "drops malformed TLSA data and maps errors", %{resolver: resolver} do
      assert DNS.lookup_secure(resolver, "_25._tcp.mx.junk.example", :tlsa) == {:ok, [], false}
      assert DNS.lookup_secure(resolver, "missing.example", :tlsa) == {:error, :nxdomain}
      assert DNS.lookup_secure(resolver, "broken.example", :tlsa) == {:error, :servfail}
      assert InetRes.lookup_secure("bad name", :tlsa, []) == {:error, :invalid_name}
    end

    test "times out against a silent server" do
      {:ok, socket} = :gen_udp.open(0, ip: {127, 0, 0, 1})
      {:ok, port} = :inet.port(socket)
      resolver = {InetRes, nameservers: [{{127, 0, 0, 1}, port}], timeout: 100, retry: 1}
      assert DNS.lookup_secure(resolver, "x.example", :tlsa) == {:error, :timeout}
    end

    defmodule PlainResolver do
      @moduledoc false
      @behaviour Sovite.DNS.Resolver
      @impl true
      def lookup(_name, :a, _opts), do: {:ok, [{192, 0, 2, 1}]}
    end

    test "resolvers without lookup_secure are never authenticated" do
      assert DNS.lookup_secure({PlainResolver, []}, "x.example", :a) ==
               {:ok, [{192, 0, 2, 1}], false}
    end
  end

  test "the default resolver is InetRes" do
    assert DNS.default_resolver() == {InetRes, []}
  end

  describe "FakeDNS" do
    setup do
      resolver =
        FakeDNS.resolver(%{
          {"Example.com.", :mx} => [{10, "mx.example.com"}],
          {"broken.example", :mx} => {:error, :servfail}
        })

      %{resolver: resolver}
    end

    test "answers from the table, case-insensitively", %{resolver: resolver} do
      assert DNS.lookup(resolver, "EXAMPLE.COM", :mx) == {:ok, [{10, "mx.example.com"}]}
    end

    test "distinguishes NODATA from NXDOMAIN", %{resolver: resolver} do
      assert DNS.lookup(resolver, "example.com", :a) == {:ok, []}
      assert DNS.lookup(resolver, "missing.example", :a) == {:error, :nxdomain}
    end

    test "returns configured errors", %{resolver: resolver} do
      assert DNS.lookup(resolver, "broken.example", :mx) == {:error, :servfail}
    end
  end

  defp rr(type, domain, data),
    do: :inet_dns.make_rr(domain: domain, type: type, class: :in, data: data)
end
