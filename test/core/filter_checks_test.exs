defmodule Sovite.Core.FilterChecksTest do
  use ExUnit.Case, async: true

  alias Sovite.{Analyzer, ARC, DKIM, DMARC, Rules, SPF}
  alias Sovite.Core.Config
  alias Sovite.Core.Filter.{Checks, RuleFiles}
  alias Sovite.DKIM.SigningKey
  alias Sovite.Test.FakeDNS

  defp names(symbols), do: Enum.map(symbols, &elem(&1, 0))

  defp builtin! do
    {:ok, rules} = RuleFiles.load([], RuleFiles.flags())
    rules
  end

  test "check results as symbols" do
    checks = %{
      spf: %SPF.Result{result: :fail, domain: "example.com", mechanism: "-all"},
      dkim: [
        %DKIM.Result{result: :fail, domain: "a.example"},
        %DKIM.Result{result: :pass, domain: "b.example"},
        %DKIM.Result{result: :pass, domain: "b.example"},
        %DKIM.Result{result: :neutral, domain: nil}
      ],
      dmarc: %DMARC.Result{result: :fail, from_domain: "example.com", disposition: :quarantine},
      arc: %ARC.Result{cv: :pass, sealers: ["list.example"]},
      dnsbl: %{
        score: 1,
        hits: [
          %{zone: "zen.spamhaus.org", weight: 3, codes: [{127, 0, 0, 2}]},
          %{zone: "list.dnswl.org", weight: -2, codes: [{127, 0, 15, 0}]}
        ],
        errors: []
      },
      rhsbl: %{
        score: 2,
        hits: [%{zone: "dbl.spamhaus.org", weight: 2, codes: [{127, 0, 1, 2}]}],
        errors: []
      },
      reverse_dns: {:unconfirmed, ["a.example", "b.example", "c.example", "d.example"]},
      greylist: :passed,
      rate_limits: ["messages"],
      access: ["sender"]
    }

    assert Checks.symbols(checks) == [
             {"R_SPF_FAIL", ["example.com", "-all"], 0},
             {"R_DKIM_ALLOW", ["b.example"], 0},
             {"R_DKIM_REJECT", ["a.example"], 0},
             {"R_DKIM_PERMFAIL", [""], 0},
             {"DMARC_POLICY_QUARANTINE", ["example.com"], 0},
             {"ARC_ALLOW", ["list.example"], 0},
             {"RBL_ZEN_SPAMHAUS_ORG", ["127.0.0.2"], 3},
             {"RWL_LIST_DNSWL_ORG", ["127.0.15.0"], -2},
             {"RHSBL_DBL_SPAMHAUS_ORG", ["127.0.1.2"], 2},
             {"RDNS_UNCONFIRMED", ["a.example", "b.example", "c.example"], 0},
             {"GREYLIST_PASSED", [], 0},
             {"RATELIMITED", ["messages"], 0},
             {"ACCESS_OK", ["sender"], 0}
           ]

    assert names(Checks.symbols(%{dkim: [], arc: %ARC.Result{cv: :none}, reverse_dns: :none})) ==
             ~w(R_DKIM_NA ARC_NA RDNS_NONE)

    assert names(Checks.symbols(%{reverse_dns: {:error, :temporary}, dmarc: {:error, :missing}})) ==
             ~w(DMARC_NA RDNS_DNSFAIL)

    assert Checks.symbols(%{reverse_dns: {:ok, "mail.example"}, rate_limits: [], greylist: nil}) ==
             []

    for {result, name} <- [
          pass: "R_SPF_ALLOW",
          softfail: "R_SPF_SOFTFAIL",
          neutral: "R_SPF_NEUTRAL",
          none: "R_SPF_NA",
          temperror: "R_SPF_DNSFAIL",
          permerror: "R_SPF_PERMFAIL"
        ],
        do: assert([{^name, _, _}] = Checks.symbols(%{spf: %SPF.Result{result: result}}))

    for {result, disposition, name} <- [
          {:pass, :none, "DMARC_POLICY_ALLOW"},
          {:fail, :reject, "DMARC_POLICY_REJECT"},
          {:fail, :none, "DMARC_POLICY_SOFTFAIL"},
          {:none, :none, "DMARC_NA"},
          {:temperror, :none, "DMARC_DNSFAIL"},
          {:permerror, :none, "DMARC_BAD_POLICY"}
        ] do
      dmarc = %DMARC.Result{result: result, disposition: disposition, from_domain: "x.example"}
      assert [{^name, _, _}] = Checks.symbols(%{dmarc: dmarc})
    end
  end

  test "the built-in rules score them, and lists score their weight" do
    checks = %{
      spf: %SPF.Result{result: :fail, domain: "example.com"},
      dmarc: %DMARC.Result{result: :fail, from_domain: "example.com", disposition: :reject},
      dnsbl: %{score: 3, hits: [%{zone: "zen.spamhaus.org", weight: 3, codes: []}], errors: []}
    }

    result = Rules.scan(builtin!(), Analyzer.analyze(""), symbols: Checks.symbols(checks))

    assert [
             %{name: "R_SPF_FAIL", score: 1.0, group: "spf"},
             %{name: "DMARC_POLICY_REJECT", score: 2.0, group: "dmarc"},
             %{name: "RBL_ZEN_SPAMHAUS_ORG", score: 3.0, group: nil}
           ] = result.symbols

    assert result.score == 6.0
  end

  test "the built-in rules declare every symbol the checks give" do
    declared = MapSet.new(Rules.symbols(builtin!()), & &1.name)

    for name <-
          ~w(R_SPF_ALLOW R_SPF_FAIL R_SPF_SOFTFAIL R_SPF_NEUTRAL R_SPF_NA R_SPF_DNSFAIL
             R_SPF_PERMFAIL R_DKIM_ALLOW R_DKIM_REJECT R_DKIM_TEMPFAIL R_DKIM_PERMFAIL R_DKIM_NA
             DMARC_POLICY_ALLOW DMARC_POLICY_REJECT DMARC_POLICY_QUARANTINE DMARC_POLICY_SOFTFAIL
             DMARC_NA DMARC_DNSFAIL DMARC_BAD_POLICY ARC_ALLOW ARC_REJECT ARC_NA RDNS_NONE
             RDNS_UNCONFIRMED RDNS_DNSFAIL GREYLIST_PASSED RATELIMITED ACCESS_OK),
        do: assert(name in declared, name)
  end

  describe "run/3" do
    setup do
      {:ok, key} = SigningKey.from_pem(SigningKey.generate(:ed25519), "example.com", "s1")

      message =
        "From: Alice <alice@example.com>\r\nTo: bob@example.net\r\nSubject: hi\r\n\r\nHello\r\n"

      [signature] = DKIM.sign(message, [key])

      records = %{
        {"example.com", :txt} => ["v=spf1 ip4:192.0.2.1 -all"],
        {"_dmarc.example.com", :txt} => ["v=DMARC1; p=reject"],
        {SigningKey.dns_name(key), :txt} => [SigningKey.dns_record(key)],
        {"9.2.0.192.bl.example", :a} => [{127, 0, 0, 2}],
        {"example.com.dbl.example", :a} => [{127, 0, 1, 2}],
        {"1.2.0.192.in-addr.arpa", :ptr} => ["mail.example.com"],
        {"mail.example.com", :a} => [{192, 0, 2, 1}]
      }

      %{resolver: FakeDNS.resolver(records), message: signature <> message}
    end

    test "checks a message from elsewhere", %{resolver: resolver, message: message} do
      opts = [
        resolver: resolver,
        dnsbl: [%{zone: "bl.example", weight: 3, codes: []}],
        rhsbl: [%{zone: "dbl.example", weight: 2, codes: [], check: [:sender]}]
      ]

      envelope = %{ip: "192.0.2.9", helo: "client.example", from: "alice@example.com"}
      checks = Checks.run(message, envelope, opts)

      assert names(Checks.symbols(checks)) ==
               ~w(R_SPF_FAIL R_DKIM_ALLOW DMARC_POLICY_ALLOW ARC_NA RBL_BL_EXAMPLE
                  RHSBL_DBL_EXAMPLE RDNS_NONE)

      # From the address SPF allows, with a tampered body, and LF line endings.
      tampered = String.replace(message, "Hello", "Hullo") |> String.replace("\r\n", "\n")
      checks = Checks.run(tampered, %{ip: {192, 0, 2, 1}, from: "alice@example.com"}, opts)

      assert names(Checks.symbols(checks)) ==
               ~w(R_SPF_ALLOW R_DKIM_REJECT DMARC_POLICY_ALLOW ARC_NA RHSBL_DBL_EXAMPLE)
    end

    test "only what the options and the envelope allow", %{resolver: resolver, message: message} do
      opts = [resolver: resolver, spf: false, arc: false, dmarc: false, reverse_dns: false]
      assert Checks.run(message, %{ip: "192.0.2.9"}, opts) |> Map.keys() == [:dkim]
      assert Checks.run(message, %{ip: "not an ip"}, opts) |> Map.keys() == [:dkim]

      checks = Checks.run("no header", %{}, resolver: resolver)
      assert names(Checks.symbols(checks)) == ~w(R_DKIM_NA DMARC_NA ARC_NA)
    end

    test "checks that take too long are left out", %{message: message} do
      resolver = {__MODULE__.Slow, []}
      envelope = %{ip: "192.0.2.9", from: "a@example.com"}

      {time, checks} =
        :timer.tc(fn -> Checks.run(message, envelope, resolver: resolver, timeout: 50) end)

      assert checks == %{}
      assert time < 500_000
    end

    test "options from the config" do
      {:ok, config} = Config.parse("[spf]\nverify = false\n")
      opts = Checks.opts(config, :resolver)
      assert opts[:spf] == false
      assert opts[:dkim] == true
      assert opts[:resolver] == :resolver
    end
  end

  defmodule Slow do
    @moduledoc false
    def lookup(_name, _type, _opts) do
      Process.sleep(1000)
      {:error, :timeout}
    end

    def lookup_secure(_name, _type, _opts) do
      Process.sleep(1000)
      {:error, :timeout}
    end
  end
end
