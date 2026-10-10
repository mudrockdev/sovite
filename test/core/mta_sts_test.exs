defmodule Sovite.Core.MTASTSTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.MTASTS
  alias Sovite.Core.Repo.Tables.MTASTSPolicies
  alias Sovite.Test.{Certs, Database, FakeDNS, TelemetryForwarder}
  alias Sovite.TLS.MTASTS.Policy

  @moduletag :tmp_dir

  setup_all do
    ca = Certs.ca()
    %{ca: ca, cert: Certs.issue(ca, names: ["mta-sts.example.net"])}
  end

  setup %{tmp_dir: dir} = context do
    TelemetryForwarder.attach([[:sovite, :mta_sts, :fetched], [:sovite, :mta_sts, :failed]])

    {:ok, policies} = Agent.start_link(fn -> %{"example.net" => policy(:enforce)} end)
    server_tls = Sovite.TLS.server_options(certs_keys: [Certs.certs_keys(context.cert)])

    listener =
      start_supervised!(
        {Sovite.Listener,
         port: 0,
         ip: {127, 0, 0, 1},
         handler: Sovite.TLS.MTASTS.Server,
         handler_opts: [
           tls: fn -> server_tls end,
           policy: fn domain -> Agent.get(policies, &Map.fetch(&1, domain)) end
         ]}
      )

    {:ok, {_ip, port}} = Sovite.Listener.sockname(listener)

    %{
      repo: Database.start!(dir),
      policies: policies,
      fetch: [connect_to: {{127, 0, 0, 1}, port}, cacerts: [context.ca.cert], timeout: 2_000]
    }
  end

  defp policy(mode, mx \\ ["mx.example.net"]),
    do: Sovite.TLS.MTASTS.policy_text(mode, mx, 86_400)

  defp config(context, txt) do
    records = if txt, do: %{{"_mta-sts.example.net", :txt} => txt}, else: %{}
    %{repo: context.repo, resolver: FakeDNS.resolver(records), fetch: context.fetch}
  end

  defp find(context, txt, now \\ DateTime.utc_now()),
    do: MTASTS.find(config(context, txt), "example.net", now)

  test "fetches a policy and caches it until its id changes", context do
    assert %{policy: %Policy{mode: :enforce, mx: ["mx.example.net"]}, failure: nil} =
             find(context, ["v=STSv1; id=1"])

    assert_received {:telemetry, [:sovite, :mta_sts, :fetched], _,
                     %{domain: "example.net", policy_id: "1", mode: :enforce}}

    assert %{policy_id: "1", mode: :enforce, max_age: 86_400} =
             MTASTSPolicies.get(context.repo, "example.net")

    # The same id: the cached policy, without a fetch.
    Agent.update(context.policies, &Map.put(&1, "example.net", policy(:testing)))
    assert %{policy: %Policy{mode: :enforce}} = find(context, ["v=STSv1; id=1"])
    refute_received {:telemetry, [:sovite, :mta_sts, :fetched], _, _}

    # A new id: fetched again.
    assert %{policy: %Policy{mode: :testing}} = find(context, ["v=STSv1; id=2"])
    assert MTASTSPolicies.get(context.repo, "example.net").policy_id == "2"

    # An expired policy is fetched again even with the same id.
    later = DateTime.add(DateTime.utc_now(), 2, :day)
    Agent.update(context.policies, &Map.put(&1, "example.net", policy(:enforce)))
    assert %{policy: %Policy{mode: :enforce}} = find(context, ["v=STSv1; id=2"], later)
  end

  test "keeps using a cached policy when the record or the fetch fails", context do
    assert %{policy: %Policy{mode: :enforce}} = find(context, ["v=STSv1; id=1"])
    Agent.update(context.policies, &Map.delete(&1, "example.net"))

    # The record is gone, its lookup fails, or the policy cannot be
    # fetched: an attacker might be behind any of these.
    assert %{policy: %Policy{mode: :enforce}} = find(context, nil)
    assert %{policy: %Policy{mode: :enforce}} = find(context, {:error, :servfail})
    assert %{policy: %Policy{mode: :enforce}} = find(context, ["v=STSv1; id=9"])
    refute_received {:telemetry, [:sovite, :mta_sts, :failed], _, _}
  end

  test "without a cached policy, reports why none was found", context do
    assert find(context, nil) == %{policy: nil, failure: nil}
    assert find(context, ["v=STSv1"]) == %{policy: nil, failure: nil}

    assert %{policy: nil, failure: {:sts_policy_fetch_error, "_mta-sts lookup failed: servfail"}} =
             find(context, {:error, :servfail})

    Agent.update(context.policies, &Map.delete(&1, "example.net"))

    assert %{policy: nil, failure: {:sts_policy_fetch_error, "policy fetch failed: " <> _}} =
             find(context, ["v=STSv1; id=1"])

    assert_received {:telemetry, [:sovite, :mta_sts, :failed], _, %{domain: "example.net"}}

    Agent.update(context.policies, &Map.put(&1, "example.net", "version: STSv1\r\n"))

    assert %{policy: nil, failure: {:sts_policy_invalid, _}} = find(context, ["v=STSv1; id=1"])

    # A certificate that is not valid for mta-sts.example.net.
    bad = %{context | fetch: Keyword.put(context.fetch, :cacerts, [Certs.ca().cert])}

    assert %{policy: nil, failure: {:sts_webpki_invalid, "policy host TLS failed: " <> _}} =
             find(bad, ["v=STSv1; id=1"])
  end

  test "treats mode none as no policy", context do
    Agent.update(context.policies, &Map.put(&1, "example.net", policy(:none, [])))
    assert find(context, ["v=STSv1; id=1"]) == %{policy: nil, failure: nil}
    assert MTASTSPolicies.get(context.repo, "example.net").mode == :none
  end

  test "the server shares and remembers lookups", context do
    resolver = FakeDNS.resolver(%{{"_mta-sts.example.net", :txt} => ["v=STSv1; id=1"]})

    server =
      start_supervised!(
        {MTASTS, repo: context.repo, resolver: resolver, fetch: context.fetch, name: nil}
      )

    results =
      1..5
      |> Enum.map(fn _ -> Task.async(fn -> MTASTS.policy(server, "Example.NET") end) end)
      |> Enum.map(&Task.await/1)

    assert [%{policy: %Policy{mode: :enforce}}] = Enum.uniq(results)
    assert_received {:telemetry, [:sovite, :mta_sts, :fetched], _, _}
    refute_received {:telemetry, [:sovite, :mta_sts, :fetched], _, _}

    # Remembered: no new lookup, even after the cached policy is gone.
    MTASTSPolicies.delete(context.repo, "example.net")
    assert %{policy: %Policy{}} = MTASTS.policy(server, "example.net")
    refute_received {:telemetry, [:sovite, :mta_sts, :fetched], _, _}

    assert %{policy: nil, failure: {:sts_policy_fetch_error, _}} =
             MTASTS.policy(spawn(fn -> :ok end), "example.net", 100)
  end
end
