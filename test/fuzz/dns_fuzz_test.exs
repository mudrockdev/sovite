defmodule Sovite.DNSFuzzTest do
  # Fuzzing of what comes from DNS: answers as nameservers send them,
  # and the records that SPF, DMARC, DKIM, MTA-STS, and TLS-RPT read.
  # Anyone who can answer a query (or spoof an answer) controls these.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.{DKIM, DMARC, SPF}
  alias Sovite.DKIM.SigningKey
  alias Sovite.DNS.InetRes
  alias Sovite.Test.{FakeDNS, Fuzz}
  alias Sovite.TLS.{MTASTS, TLSRPT}

  @moduletag :fuzz
  # `mix fuzz` runs each property many times.
  @moduletag timeout: :infinity

  @types [:a, :aaaa, :mx, :txt, :ptr, :cname, :ns, :tlsa]

  describe "answers" do
    property "decode to records of the type asked for, with printable names" do
      seeds = [
        response(:a, [{192, 0, 2, 1}, {192, 0, 2, 2}]),
        response(:aaaa, [{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}]),
        response(:mx, [{10, ~c"mx1.example.com"}, {20, ~c"mx2.example.com"}, {0, ~c"."}]),
        response(:txt, [[~c"v=spf1 ip4:192.0.2.0/24 -all"], [~c"part one ", ~c"part two"]]),
        response(:ptr, [~c"host.example.com"]),
        response(:cname, [~c"alias.example.net"]),
        response(:ns, [~c"ns1.example.com", ~c"ns2.example.com"]),
        response(:tlsa, [<<3, 1, 1>> <> :crypto.hash(:sha256, "key")])
      ]

      check all(packet <- Fuzz.input(seeds, [<<0>>, <<0xC0, 12>>]), max_runs: Fuzz.runs()) do
        for type <- @types do
          case Fuzz.quick(fn -> InetRes.answer(packet, type) end) do
            {:ok, records, authenticated} ->
              assert is_boolean(authenticated)
              assert Enum.all?(records, &record?(type, &1)), inspect({type, records})

            {:error, reason} ->
              assert reason in [:servfail, :nxdomain, :refused, :other]
          end
        end
      end
    end
  end

  describe "records" do
    property "SPF evaluates to a result, and an explanation is printable" do
      records = [
        "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx/24 ptr -all",
        "v=spf1 include:_spf.example.net exists:%{ir}.%{v}.ex.example.com ~all exp=why.example.com",
        "v=spf1 redirect=_spf.example.net",
        "v=spf1 a:%{d2}.example.com/24//64 -all exp=why.%{d}"
      ]

      explanations = ["%{i} may not send for %{d}; see %{h} %{s} %{l} %{o} %{p}", "%-%_%%x"]

      check all(
              record <- Fuzz.input(records, [" ", ":", "/", "%{", "}", "=", "-", "~", "?"]),
              explanation <- Fuzz.input(explanations, ["%{", "}", "%"]),
              max_runs: Fuzz.runs()
            ) do
        resolver =
          FakeDNS.resolver(%{
            {"example.com", :txt} => [record],
            {"example.com", :a} => [{192, 0, 2, 1}],
            {"example.com", :mx} => [{10, "mx.example.com"}],
            {"mx.example.com", :a} => [{192, 0, 2, 25}],
            {"_spf.example.net", :txt} => [record],
            {"why.example.com", :txt} => [explanation],
            {"9.2.0.192.in-addr.arpa", :ptr} => ["mx.example.com"]
          })

        result =
          Fuzz.quick(fn ->
            SPF.check_host(resolver, {192, 0, 2, 9}, "example.com", "a@example.com",
              helo: "mx.example.com"
            )
          end)

        assert result.result in [:pass, :fail, :softfail, :neutral, :none, :temperror, :permerror]

        if result.explanation,
          do: assert(result.explanation =~ ~r/\A[\x20-\x7e]*\z/, inspect(result.explanation))
      end
    end

    property "DMARC policies parse and decide, or are ignored" do
      seeds = [
        "v=DMARC1; p=reject; sp=quarantine; pct=50; adkim=s; aspf=r; rua=mailto:a@example.com",
        "v=DMARC1; p=none; fo=1:d:s; rf=afrf; ri=3600; ruf=mailto:f@example.net!10m; np=reject",
        "v=DMARC1;p=quarantine;t=y;psd=n"
      ]

      check all(
              record <- Fuzz.input(seeds, [";", "=", " ", ":", "!", ","]),
              max_runs: Fuzz.runs()
            ) do
        assert {_, _} = Fuzz.quick(fn -> DMARC.Record.parse(record) end)

        resolver = FakeDNS.resolver(%{{"_dmarc.example.com", :txt} => [record]})

        result =
          Fuzz.quick(fn ->
            DMARC.check(resolver, "example.com",
              spf: {:pass, "example.com"},
              dkim: [{:pass, "other.example"}],
              random: fn -> 0.5 end
            )
          end)

        assert %DMARC.Result{} = result
      end
    end

    property "DKIM keys from DNS verify or fail, never crash" do
      {:ok, rsa} = SigningKey.from_pem(SigningKey.generate(:rsa, 1024), "example.com", "s")
      message = "From: a@example.com\r\nSubject: x\r\n\r\nbody\r\n"
      signed = Enum.join(DKIM.sign(message, [rsa])) <> message

      {:ok, ed} = SigningKey.from_pem(SigningKey.generate(:ed25519), "example.com", "s")

      seeds = [
        SigningKey.dns_record(rsa),
        SigningKey.dns_record(ed),
        "v=DKIM1; k=rsa; t=s:y; h=sha256; p="
      ]

      check all(record <- Fuzz.input(seeds, [";", "=", " ", ":"]), max_runs: Fuzz.runs()) do
        resolver = FakeDNS.resolver(%{{SigningKey.dns_name(rsa), :txt} => [record]})

        for result <- Fuzz.quick(fn -> DKIM.verify(signed, resolver) end) do
          assert result.result in [:pass, :fail, :neutral, :temperror, :permerror, :policy]
        end
      end
    end

    property "MTA-STS and TLS-RPT records and policies parse or are refused" do
      records = [
        "v=STSv1; id=20261018T000000;",
        "v=TLSRPTv1; rua=mailto:a@example.com,https://r.example/x"
      ]

      policies = [
        "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: *.example.net\nmax_age: 86400\n",
        "version: STSv1\r\nmode: testing\r\nmx: mx.example.com\r\nmax_age: 604800\r\n"
      ]

      check all(
              record <- Fuzz.input(records, [";", "=", " ", ","]),
              policy <- Fuzz.input(policies, ["\n", ":", "*", " "]),
              max_runs: Fuzz.runs()
            ) do
        assert {_, _} = Fuzz.quick(fn -> MTASTS.parse_record([record]) end)
        assert {_, _} = Fuzz.quick(fn -> TLSRPT.parse_record([record]) end)
        assert {_, _} = Fuzz.quick(fn -> MTASTS.parse_policy(policy) end)
      end
    end
  end

  defp response(type, answers) do
    :inet_dns.encode(
      :inet_dns.make_msg(
        header: :inet_dns.make_header(id: 1, qr: true, rd: true, ra: true, opcode: :query),
        qdlist: [:inet_dns.make_dns_query(domain: ~c"example.com", type: wire(type), class: :in)],
        anlist:
          for data <- answers do
            :inet_dns.make_rr(
              domain: ~c"example.com",
              type: wire(type),
              class: :in,
              ttl: 300,
              data: data
            )
          end
      )
    )
  end

  defp wire(:tlsa), do: 52
  defp wire(type), do: type

  defp record?(type, {_, _, _, _} = ip) when type == :a,
    do: Tuple.to_list(ip) |> Enum.all?(&(&1 in 0..255))

  defp record?(:aaaa, ip) when tuple_size(ip) == 8,
    do: Tuple.to_list(ip) |> Enum.all?(&(&1 in 0..0xFFFF))

  defp record?(:mx, {preference, name}),
    do: preference in 0..0xFFFF and (name == "" or name?(name))

  defp record?(:txt, text), do: is_binary(text)
  defp record?(type, name) when type in [:ptr, :cname, :ns], do: name?(name)

  defp record?(:tlsa, {usage, selector, matching, data}),
    do: is_binary(data) and Enum.all?([usage, selector, matching], &(&1 in 0..255))

  defp record?(_type, _record), do: false

  defp name?(name), do: is_binary(name) and name =~ ~r/\A[\x21-\x7e]+\z/
end
