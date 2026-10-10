defmodule Sovite.Core.Delivery.TLSPolicyTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Delivery.TLSPolicy
  alias Sovite.Test.FakeDNS
  alias Sovite.TLS.MTASTS.Policy

  @opts %{
    resolver: FakeDNS.resolver(%{{"_25._tcp.mx.example.net", :tlsa} => {:error, :servfail}}),
    tls: %{default: :dane, policy: %{}, cacerts: []}
  }

  defp ctx(fields) do
    Map.merge(
      %{
        level: :may,
        domain: "example.net",
        relay: false,
        sts: nil,
        sts_failure: nil,
        requiretls: false,
        tls_optional: false,
        dnssec: false
      },
      Map.new(fields)
    )
  end

  defp plan(fields, host \\ "mx.example.net", secure \\ false),
    do: TLSPolicy.plan(ctx(fields), host, 25, secure, @opts)

  test "address literals" do
    assert {:ok, :none, _} = plan([level: :none], "[192.0.2.1]")
    assert {:ok, {:required, "encrypt", _}, _} = plan([level: :encrypt], "[192.0.2.1]")
    assert {:ok, {:may, _}, _} = plan([level: :dane], "[192.0.2.1]")
    assert {:retry, {"4.7.5", _}, nil} = plan([level: :verify], "[192.0.2.1]")
    assert {:retry, {"5.7.30", _}, nil} = plan([requiretls: true], "[192.0.2.1]")
  end

  test "levels without a recipient policy" do
    assert {:ok, :none, %{type: :no_policy_found}} = plan(level: :none)
    assert {:ok, {:required, "encrypt", _}, _} = plan(level: :encrypt)
    assert {:ok, {:required, "verify", _}, _} = plan(level: :verify)
    assert {:ok, {:may, _}, _} = plan(level: :dane)
  end

  test "REQUIRETLS needs a verified next hop" do
    assert {:retry, {"5.7.30", "REQUIRETLS, but TLS is turned off" <> _}, nil} =
             plan(level: :none, requiretls: true)

    assert {:retry, {"5.7.30", _}, nil} = plan(level: :encrypt, requiretls: true)

    # A relay host is trusted by name: its certificate must be valid.
    assert {:ok, {:required, "verify", _}, _} = plan(relay: true, requiretls: true)
  end

  test "MTA-STS testing reports hosts the policy does not list" do
    policy = %Policy{mode: :testing, mx: ["mx2.example.net"], max_age: 60, text: "x"}

    assert {:ok, {:may, _}, %{type: :sts, failure: {:validation_failure, _}}} =
             plan(sts: policy)

    assert {:retry, {"4.7.5", _}, nil} = plan(sts: policy, requiretls: true)
  end

  test "a fetch failure is reported with every session" do
    failure = {:sts_policy_fetch_error, "policy fetch failed"}
    assert {:ok, {:may, _}, %{type: :sts, failure: ^failure}} = plan(sts_failure: failure)
  end

  test "a failed TLSA lookup skips the host and is reported" do
    assert {:retry, {"4.7.5", "TLSA lookup for mx.example.net failed: servfail"},
            %{type: :tlsa, failure: {:dnssec_invalid, _}} = report} =
             plan([level: :dane], "mx.example.net", true)

    # Recorded without a session: nothing to record without a repo.
    assert TLSPolicy.record(
             ctx([]),
             report,
             nil,
             {"mx.example.net", {192, 0, 2, 1}},
             {:retry, {"4.7.5", "x"}},
             Map.put(@opts, :client, [])
           ) == :ok
  end
end
