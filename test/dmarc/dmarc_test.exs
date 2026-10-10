defmodule Sovite.DMARCTest do
  use ExUnit.Case, async: true

  alias Sovite.DMARC
  alias Sovite.DMARC.{Policy, Record, Result}
  alias Sovite.Message.Headers
  alias Sovite.Test.FakeDNS

  @v4 {192, 0, 2, 1}

  # A resolver that also reports each name it is asked for.
  defp tracing(records) do
    {module, opts} = FakeDNS.resolver(records)
    {__MODULE__.Tracer, [inner: module, pid: self()] ++ opts}
  end

  defmodule Tracer do
    @moduledoc false
    def lookup(name, type, opts) do
      send(opts[:pid], {:lookup, name, type})
      opts[:inner].lookup(name, type, opts)
    end
  end

  defp lookups do
    receive do
      {:lookup, name, type} -> [{name, type} | lookups()]
    after
      0 -> []
    end
  end

  describe "discover/2" do
    test "finds a record at the domain itself" do
      resolver =
        FakeDNS.resolver(%{
          {"_dmarc.example.com", :txt} => ["v=DMARC1; p=reject; rua=mailto:d@example.com"]
        })

      assert {:ok, %Policy{domain: "example.com", org_domain: "example.com", record: record}} =
               DMARC.discover(resolver, "Example.COM.")

      assert %Record{p: :reject, rua: [%{uri: "mailto:d@example.com"}]} = record
    end

    test "walks up to a parent, ignoring non-DMARC records" do
      resolver =
        tracing(%{
          {"_dmarc.mail.example.com", :txt} => ["v=spf1 -all", "hello"],
          {"_dmarc.example.com", :txt} => ["v=DMARC1; p=quarantine"]
        })

      assert {:ok, %Policy{domain: "example.com", org_domain: "example.com"}} =
               DMARC.discover(resolver, "a.mail.example.com")

      assert lookups() == [
               {"_dmarc.a.mail.example.com", :txt},
               {"_dmarc.mail.example.com", :txt},
               {"_dmarc.example.com", :txt}
             ]
    end

    test "treats a level with two DMARC records as having none" do
      resolver =
        FakeDNS.resolver(%{
          {"_dmarc.mail.example.com", :txt} => ["v=DMARC1; p=none", "v=DMARC1; p=reject"],
          {"_dmarc.example.com", :txt} => ["v=DMARC1; p=quarantine"]
        })

      assert {:ok, %Policy{domain: "example.com", record: %Record{p: :quarantine}}} =
               DMARC.discover(resolver, "mail.example.com")
    end

    test "skips a record that does not parse" do
      resolver =
        FakeDNS.resolver(%{
          {"_dmarc.mail.example.com", :txt} => ["v=DMARC1; p=bogus"],
          {"_dmarc.example.com", :txt} => ["v=DMARC1; p=quarantine"]
        })

      assert {:ok, %Policy{domain: "example.com"}} = DMARC.discover(resolver, "mail.example.com")
    end

    test "jumps to the last 7 labels for long names, and never queries the TLD" do
      resolver = tracing(%{})

      assert DMARC.discover(resolver, "a.b.c.d.e.f.g.h.i.example.com") ==
               {:none, "a.b.c.d.e.f.g.h.i.example.com"}

      assert lookups() == [
               {"_dmarc.a.b.c.d.e.f.g.h.i.example.com", :txt},
               {"_dmarc.e.f.g.h.i.example.com", :txt},
               {"_dmarc.f.g.h.i.example.com", :txt},
               {"_dmarc.g.h.i.example.com", :txt},
               {"_dmarc.h.i.example.com", :txt},
               {"_dmarc.i.example.com", :txt},
               {"_dmarc.example.com", :txt}
             ]
    end

    test "walks one label at a time for 8 labels" do
      resolver = tracing(%{})
      DMARC.discover(resolver, "a.b.c.d.e.f.example.com")
      assert [_, {"_dmarc.b.c.d.e.f.example.com", :txt} | _] = lookups()
    end

    test "queries only the name itself for a single label" do
      resolver = tracing(%{})
      assert DMARC.discover(resolver, "localhost") == {:none, "localhost"}
      assert lookups() == [{"_dmarc.localhost", :txt}]
    end

    test "fails on DNS errors other than NXDOMAIN" do
      resolver =
        FakeDNS.resolver(%{
          {"_dmarc.mail.example.com", :txt} => {:error, :servfail},
          {"_dmarc.example.com", :txt} => ["v=DMARC1; p=quarantine"]
        })

      assert DMARC.discover(resolver, "mail.example.com") == {:error, :temperror}

      resolver = FakeDNS.resolver(%{{"_dmarc.example.com", :txt} => {:error, :timeout}})
      assert DMARC.discover(resolver, "mail.example.com") == {:error, :temperror}
    end

    test "returns the org domain without a policy" do
      resolver = FakeDNS.resolver(%{{"_dmarc.example.com", :txt} => []})
      assert DMARC.discover(resolver, "mail.example.com") == {:none, "mail.example.com"}
    end
  end

  describe "org_domain/2" do
    test "is the domain with the fewest labels that has a record" do
      resolver =
        FakeDNS.resolver(%{
          {"_dmarc.mail.example.com", :txt} => ["v=DMARC1; p=none"],
          {"_dmarc.example.com", :txt} => ["v=DMARC1; p=reject"]
        })

      assert DMARC.org_domain(resolver, "a.mail.example.com") == {:ok, "example.com"}
      assert DMARC.org_domain(resolver, "mail.example.com") == {:ok, "example.com"}
    end

    test "is the domain itself without records" do
      assert DMARC.org_domain(FakeDNS.resolver(%{}), "a.mail.example.com") ==
               {:ok, "a.mail.example.com"}
    end

    test "stops at a record with psd=n" do
      resolver =
        tracing(%{
          {"_dmarc.dept.example.com", :txt} => ["v=DMARC1; p=none; psd=n"],
          {"_dmarc.example.com", :txt} => ["v=DMARC1; p=reject"]
        })

      assert DMARC.org_domain(resolver, "a.dept.example.com") == {:ok, "dept.example.com"}
      refute {"_dmarc.example.com", :txt} in lookups()
    end

    test "is one label below a record with psd=y" do
      resolver =
        FakeDNS.resolver(%{
          {"_dmarc.example.co.uk", :txt} => ["v=DMARC1; p=none"],
          {"_dmarc.co.uk", :txt} => ["v=DMARC1; p=reject; psd=y"]
        })

      assert DMARC.org_domain(resolver, "a.mail.example.co.uk") == {:ok, "example.co.uk"}
      assert DMARC.org_domain(resolver, "other.co.uk") == {:ok, "other.co.uk"}
      assert DMARC.org_domain(resolver, "co.uk") == {:ok, "co.uk"}
    end

    test "is one label below a psd=y record reached by the long-name jump" do
      resolver =
        FakeDNS.resolver(%{{"_dmarc.d.e.f.g.h.i.example", :txt} => ["v=DMARC1; p=none; psd=y"]})

      assert DMARC.org_domain(resolver, "a.b.c.d.e.f.g.h.i.example") ==
               {:ok, "c.d.e.f.g.h.i.example"}
    end

    test "fails on DNS errors" do
      resolver = FakeDNS.resolver(%{{"_dmarc.example.com", :txt} => {:error, :servfail}})
      assert DMARC.org_domain(resolver, "mail.example.com") == {:error, :temperror}
    end
  end

  describe "aligned?/4" do
    setup do
      resolver =
        FakeDNS.resolver(%{
          {"_dmarc.example.com", :txt} => ["v=DMARC1; p=reject"],
          {"_dmarc.other.com", :txt} => ["v=DMARC1; p=reject"],
          {"_dmarc.broken.com", :txt} => {:error, :servfail}
        })

      %{resolver: resolver}
    end

    test "strict mode needs the same domain", %{resolver: resolver} do
      assert DMARC.aligned?(resolver, :strict, "Example.com.", "example.COM") == {:ok, true}
      assert DMARC.aligned?(resolver, :strict, "mail.example.com", "example.com") == {:ok, false}
    end

    test "relaxed mode needs the same org domain", %{resolver: resolver} do
      assert DMARC.aligned?(resolver, :relaxed, "mail.example.com", "example.com") == {:ok, true}
      assert DMARC.aligned?(resolver, :relaxed, "a.example.com", "b.example.com") == {:ok, true}
      assert DMARC.aligned?(resolver, :relaxed, "example.com", "other.com") == {:ok, false}
      assert DMARC.aligned?(resolver, :relaxed, "example.com", "example.org") == {:ok, false}
      assert DMARC.aligned?(resolver, :relaxed, "x.broken.com", "x.broken.com") == {:ok, true}

      assert DMARC.aligned?(resolver, :relaxed, "x.broken.com", "y.broken.com") ==
               {:error, :temperror}
    end
  end

  describe "check/3" do
    defp resolver(record, extra \\ %{}) do
      FakeDNS.resolver(Map.merge(%{{"_dmarc.example.com", :txt} => [record]}, extra))
    end

    test "passes with aligned SPF only" do
      resolver = resolver("v=DMARC1; p=reject")

      assert %Result{
               result: :pass,
               from_domain: "example.com",
               policy: %Policy{domain: "example.com"},
               disposition: :none,
               applied: nil,
               spf_aligned: true,
               dkim_aligned: false,
               dkim_domain: nil
             } =
               DMARC.check(resolver, "Example.com",
                 spf: {:pass, "bounce.example.com"},
                 dkim: [{:pass, "esp.example"}, {:fail, "example.com"}]
               )
    end

    test "passes with aligned DKIM only" do
      resolver = resolver("v=DMARC1; p=reject")

      assert %Result{
               result: :pass,
               spf_aligned: false,
               dkim_aligned: true,
               dkim_domain: "mail.example.com"
             } =
               DMARC.check(resolver, "example.com",
                 spf: {:pass, "esp.example"},
                 dkim: [
                   {:fail, "example.com"},
                   {:pass, "esp.example"},
                   {:pass, "Mail.Example.com"}
                 ]
               )
    end

    test "fails when SPF and DKIM pass for unaligned domains" do
      resolver = resolver("v=DMARC1; p=reject")

      assert %Result{
               result: :fail,
               disposition: :reject,
               applied: :p,
               sampled: true,
               spf_aligned: false,
               dkim_aligned: false
             } =
               DMARC.check(resolver, "example.com",
                 spf: {:pass, "esp.example"},
                 dkim: [{:pass, "esp.example"}]
               )

      assert %Result{result: :fail} = DMARC.check(resolver, "example.com", [])

      assert %Result{result: :fail} =
               DMARC.check(resolver, "example.com", spf: {:softfail, "example.com"})

      assert %Result{result: :fail} = DMARC.check(resolver, "example.com", spf: {:none, nil})
    end

    test "honors strict alignment" do
      resolver = resolver("v=DMARC1; p=reject; adkim=s; aspf=s")

      assert %Result{result: :fail} =
               DMARC.check(resolver, "example.com",
                 spf: {:pass, "bounce.example.com"},
                 dkim: [{:pass, "mail.example.com"}]
               )

      assert %Result{result: :pass, dkim_domain: "example.com"} =
               DMARC.check(resolver, "example.com", dkim: [{:pass, "example.com"}])
    end

    test "uses sp for an existing subdomain and np for a non-existent one" do
      resolver =
        resolver("v=DMARC1; p=reject; sp=quarantine; np=none", %{
          {"mail.example.com", :mx} => [{10, "mx.example.com"}]
        })

      assert %Result{result: :fail, disposition: :quarantine, applied: :sp} =
               DMARC.check(resolver, "mail.example.com", [])

      assert %Result{result: :fail, disposition: :none, applied: :np} =
               DMARC.check(resolver, "ghost.example.com", [])

      assert %Result{result: :fail, disposition: :reject, applied: :p} =
               DMARC.check(resolver, "example.com", [])
    end

    test "counts a subdomain with a DNS error as existing" do
      resolver =
        resolver("v=DMARC1; p=reject; sp=quarantine; np=none", %{
          {"mail.example.com", :a} => {:error, :servfail}
        })

      assert %Result{applied: :sp} = DMARC.check(resolver, "mail.example.com", [])
    end

    test "uses the subdomain policy found at a parent for alignment" do
      resolver =
        resolver("v=DMARC1; p=reject", %{{"mail.example.com", :a} => [@v4]})

      assert %Result{result: :pass, policy: %Policy{domain: "example.com"}} =
               DMARC.check(resolver, "mail.example.com", dkim: [{:pass, "example.com"}])
    end

    test "samples with pct" do
      resolver = resolver("v=DMARC1; p=reject; pct=30")

      assert %Result{disposition: :reject, sampled: true, reason: nil} =
               DMARC.check(resolver, "example.com", random: fn -> 0.29 end)

      assert %Result{disposition: :quarantine, sampled: false, reason: "sampled out (pct=30)"} =
               DMARC.check(resolver, "example.com", random: fn -> 0.3 end)

      resolver = resolver("v=DMARC1; p=quarantine; pct=0")

      assert %Result{disposition: :none, sampled: false} =
               DMARC.check(resolver, "example.com", random: fn -> 0.0 end)

      assert %Result{} = DMARC.check(resolver("v=DMARC1; p=reject; pct=50"), "example.com", [])
    end

    test "lowers the disposition in testing mode" do
      resolver = resolver("v=DMARC1; p=reject; t=y")

      assert %Result{result: :fail, disposition: :quarantine, sampled: false} =
               DMARC.check(resolver, "example.com", random: fn -> 0.0 end)

      resolver = resolver("v=DMARC1; p=none; t=y")
      assert %Result{result: :fail, disposition: :none} = DMARC.check(resolver, "example.com", [])
    end

    test "returns none without a policy" do
      assert %Result{result: :none, policy: nil, disposition: :none} =
               DMARC.check(FakeDNS.resolver(%{}), "example.com", spf: {:pass, "example.com"})
    end

    test "returns temperror on DNS errors" do
      resolver = FakeDNS.resolver(%{{"_dmarc.example.com", :txt} => {:error, :servfail}})

      assert %Result{result: :temperror, disposition: :none, policy: nil} =
               DMARC.check(resolver, "example.com", [])

      resolver =
        resolver("v=DMARC1; p=reject", %{{"_dmarc.broken.com", :txt} => {:error, :timeout}})

      assert %Result{result: :temperror, disposition: :none, policy: %Policy{}} =
               DMARC.check(resolver, "example.com", dkim: [{:pass, "x.broken.com"}])

      assert %Result{result: :temperror} =
               DMARC.check(resolver, "example.com", spf: {:pass, "x.broken.com"})
    end

    test "returns permerror for an invalid From domain" do
      assert %Result{result: :permerror, disposition: :none} =
               DMARC.check(FakeDNS.resolver(%{}), "not a domain", [])
    end

    test "caches org domains within one check" do
      resolver =
        tracing(%{
          {"_dmarc.example.com", :txt} => ["v=DMARC1; p=reject"],
          {"_dmarc.esp.com", :txt} => ["v=DMARC1; p=none"]
        })

      DMARC.check(resolver, "example.com",
        spf: {:pass, "bounce.esp.com"},
        dkim: [{:pass, "bounce.esp.com"}, {:pass, "esp.com"}]
      )

      assert Enum.frequencies(lookups()) == %{
               {"_dmarc.example.com", :txt} => 1,
               {"_dmarc.bounce.esp.com", :txt} => 1,
               {"_dmarc.esp.com", :txt} => 2
             }
    end
  end

  describe "from_domain/1" do
    defp from(header), do: header |> Headers.parse() |> DMARC.from_domain()

    test "reads the domain of the From: mailbox" do
      assert from("From: alice@Example.COM\r\n") == {:ok, "example.com"}
      assert from("Subject: hi\r\nfrom: Alice <alice@example.com>\r\n") == {:ok, "example.com"}

      assert from(~s|From: "Doe, Jane (CEO)" <jane@example.com> (comment)\r\n|) ==
               {:ok, "example.com"}

      assert from(~s|From: "a@evil.example" <a@example.com>\r\n|) == {:ok, "example.com"}
      assert from("From: Alice\r\n <alice@example.com>\r\n") == {:ok, "example.com"}
      assert from("From: Team: a@example.com, b@example.com;\r\n") == {:ok, "example.com"}
    end

    test "allows several mailboxes with the same domain" do
      assert from("From: a@example.com, B <b@EXAMPLE.com>\r\n") == {:ok, "example.com"}
    end

    test "rejects several domains or From: fields" do
      assert from("From: a@example.com, b@other.example\r\n") == {:error, :multiple}
      assert from("From: a@example.com\r\nFrom: a@example.com\r\n") == {:error, :multiple}
    end

    test "rejects a missing or unusable From:" do
      assert from("Subject: hi\r\n") == {:error, :missing}
      assert from("From: undisclosed\r\n") == {:error, :invalid}
      assert from("From: <alice@[192.0.2.1]>\r\n") == {:error, :invalid}
      assert from(~s|From: "unterminated <a@example.com>\r\n|) == {:error, :invalid}
      assert from("From: a@example.com, b@bad_domain\r\n") == {:error, :invalid}
    end
  end

  describe "report_authorized?/3" do
    test "allows destinations in the same org domain" do
      resolver = FakeDNS.resolver(%{{"_dmarc.example.com", :txt} => ["v=DMARC1; p=none"]})
      assert DMARC.report_authorized?(resolver, "mail.example.com", "example.com") == {:ok, true}
      assert DMARC.report_authorized?(resolver, "example.com", "example.com") == {:ok, true}
    end

    test "checks the external destination record" do
      resolver =
        FakeDNS.resolver(%{
          {"example.com._report._dmarc.reports.example", :txt} => ["v=DMARC1"],
          {"other.com._report._dmarc.reports.example", :txt} => ["not dmarc"],
          {"broken.com._report._dmarc.reports.example", :txt} => {:error, :servfail}
        })

      assert DMARC.report_authorized?(resolver, "Example.com", "reports.example.") == {:ok, true}
      assert DMARC.report_authorized?(resolver, "other.com", "reports.example") == {:ok, false}
      assert DMARC.report_authorized?(resolver, "nope.com", "reports.example") == {:ok, false}

      assert DMARC.report_authorized?(resolver, "broken.com", "reports.example") ==
               {:error, :temperror}
    end

    test "fails when the org domain lookup fails" do
      resolver = FakeDNS.resolver(%{{"_dmarc.reports.com", :txt} => {:error, :servfail}})

      assert DMARC.report_authorized?(resolver, "example.com", "reports.com") ==
               {:error, :temperror}
    end
  end
end
