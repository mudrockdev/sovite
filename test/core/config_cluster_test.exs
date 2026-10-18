defmodule Sovite.Core.ConfigClusterTest do
  # [cluster], [[tenant]], [[ip_pool]], and the shared configuration.
  use ExUnit.Case, async: true

  alias Sovite.Core.Config

  @moduletag :tmp_dir

  defp errors(toml) do
    {:error, errors} = Config.parse(toml)
    Enum.map(errors, &Exception.message/1)
  end

  test "defaults: no cluster, tenants, or pools" do
    {:ok, config} = Config.parse("")

    assert config.cluster == %{
             enabled: false,
             node_name: nil,
             address: nil,
             port: 4370,
             seeds: [],
             cert_file: nil,
             key_file: nil,
             ca_file: nil,
             join_interval: 10_000,
             sync_interval: 1_000,
             shared_config: nil,
             queue_replicas: 1,
             handover_after: 600_000,
             destination_affinity: false
           }

    assert config.tenant == []
    assert config.ip_pool == []
    assert config.delivery.ip_pool == nil
  end

  test "reads the cluster, tenants, and pools" do
    {:ok, config} =
      Config.parse("""
      [cluster]
      enabled = true
      node_name = "mx1@10.0.0.1"
      address = "10.0.0.1"
      seeds = ["mx2@10.0.0.2", "mx3@[2001:db8::3]:4371", "mx4@mx4.example.com:4370"]
      cert_file = "/etc/sovite/node.pem"
      key_file = "/etc/sovite/node.key"
      ca_file = "/etc/sovite/ca.pem"
      shared_config = "/var/lib/sovite/cluster.toml"
      queue_replicas = 2
      handover_after = "5m"
      destination_affinity = true

      [delivery]
      ip_pool = "shared"

      [[tenant]]
      name = "acme"
      domains = ["Acme.Example"]
      users = ["relay"]
      ip_pool = "acme"
      messages = "100/1h"
      recipients = "1000/1d"
      max_message_size = "10M"
      max_recipients = 50

      [[ip_pool]]
      name = "shared"

      [[ip_pool.address]]
      address = "192.0.2.10"

      [[ip_pool]]
      name = "acme"
      overflow = "shared"

      [[ip_pool.address]]
      address = "2001:db8::10"
      helo = "mta.acme.example"
      node = "mx2@10.0.0.2"
      warmup_start = 2026-10-01
      warmup = [50, 100]
      daily_limit = 1000
      """)

    assert config.cluster.seeds == [
             "mx2@10.0.0.2",
             "mx3@[2001:db8::3]:4371",
             "mx4@mx4.example.com:4370"
           ]

    assert config.cluster.address == {10, 0, 0, 1}
    assert config.cluster.handover_after == 300_000

    assert [tenant] = config.tenant

    assert tenant == %{
             name: "acme",
             domains: ["acme.example"],
             users: ["relay"],
             ip_pool: "acme",
             messages: {100, 3_600_000},
             recipients: {1000, 86_400_000},
             max_message_size: 10 * 1024 * 1024,
             max_recipients: 50
           }

    assert [%{name: "shared"}, %{name: "acme", overflow: "shared", address: [address]}] =
             config.ip_pool

    assert address == %{
             address: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x10},
             helo: "mta.acme.example",
             node: "mx2@10.0.0.2",
             warmup_start: ~D[2026-10-01],
             warmup: [50, 100],
             daily_limit: 1000
           }
  end

  test "rejects bad cluster settings" do
    assert errors("""
           [cluster]
           enabled = true
           address = "0.0.0.0"
           node_name = "bad name"
           seeds = ["mx2", "mx2@10.0.0.2:99999", "@h"]
           """) == [
             ~s(cluster.node_name: "bad name" is not a node name, such as "mx1@10.0.0.1"),
             ~s(cluster.seeds[0]: "mx2" is not a cluster peer, such as "mx2@10.0.0.2:4370"),
             ~s(cluster.seeds[1]: "mx2@10.0.0.2:99999" is not a cluster peer, such as "mx2@10.0.0.2:4370"),
             ~s(cluster.seeds[2]: "@h" is not a cluster peer, such as "mx2@10.0.0.2:4370")
           ]

    assert errors("""
           [cluster]
           enabled = true
           address = "0.0.0.0"
           """) == [
             "cluster.node_name: is required when the cluster is enabled",
             "cluster.cert_file: is required when the cluster is enabled",
             "cluster.key_file: is required when the cluster is enabled",
             "cluster.ca_file: is required when the cluster is enabled",
             "cluster.address: must be an address the other nodes can reach: they are told it"
           ]

    assert errors("[cluster]\nqueue_replicas = 3") == [
             "cluster.queue_replicas: expected an integer from 0 to 2, got 3"
           ]
  end

  test "rejects bad tenants and pools" do
    assert errors("""
           [delivery]
           ip_pool = "nope"

           [[tenant]]
           name = "a"
           domains = ["a.example", "shared.example"]
           users = ["u"]
           ip_pool = "missing"

           [[tenant]]
           name = "a"
           domains = ["SHARED.example"]
           users = ["U"]

           [[tenant]]
           name = "bad name"

           [[ip_pool]]
           name = "p"
           overflow = "q"

           [[ip_pool.address]]
           address = "192.0.2.1"
           node = "mx2@10.0.0.2"
           warmup = [10]

           [[ip_pool]]
           name = "q"
           overflow = "p"

           [[ip_pool]]
           name = "r"
           overflow = "r"

           [[ip_pool.address]]
           address = "192.0.2.2"
           warmup_start = "yesterday"
           """) == [
             ~s(tenant[2].name: "bad name" is not a valid name: use letters, digits, "_", and "-"),
             ~s(ip_pool[2].address[0].warmup_start: expected a date like "2026-10-01", got "yesterday")
           ]

    assert errors("""
           [delivery]
           ip_pool = "nope"

           [[tenant]]
           name = "a"
           domains = ["a.example", "shared.example"]
           users = ["u"]
           ip_pool = "missing"

           [[tenant]]
           name = "a"
           domains = ["SHARED.example"]
           users = ["U"]

           [[ip_pool]]
           name = "p"
           overflow = "q"

           [[ip_pool.address]]
           address = "192.0.2.1"
           node = "mx2@10.0.0.2"
           warmup = [10]

           [[ip_pool]]
           name = "q"
           overflow = "p"

           [[ip_pool]]
           name = "r"
           overflow = "r"

           [[ip_pool.address]]
           address = "192.0.2.2"
           """) == [
             ~s(tenant[1].name: "a" names another tenant already),
             ~s(tenant[0].ip_pool: no [[ip_pool]] is named "missing"),
             ~s(tenant[1].domains: "shared.example" is in tenant[0] already),
             ~s(tenant[1].users: "u" is in tenant[0] already),
             "ip_pool[0].address[0].node: needs the cluster to be enabled",
             "ip_pool[0].address[0].warmup_start: is required with warmup",
             "ip_pool[1].address: must not be empty",
             "ip_pool[2].overflow: must name another pool",
             ~s(ip_pool[0].overflow: leads back to "p"),
             ~s(ip_pool[1].overflow: leads back to "q"),
             ~s(delivery.ip_pool: no [[ip_pool]] is named "nope")
           ]
  end

  describe "the shared configuration" do
    setup %{tmp_dir: dir} do
      shared = Path.join(dir, "cluster.toml")
      local = Path.join(dir, "sovite.toml")

      File.write!(local, """
      [server]
      hostname = "mx1.example.com"

      [smtp]
      max_recipients = 10

      [cluster]
      shared_config = "#{shared}"
      """)

      %{shared: shared, local: local}
    end

    test "comes first, under the node's own file", %{shared: shared, local: local} do
      # Not there yet: the node's file alone.
      assert {:ok, config} = Config.load(local)
      assert config.smtp.max_recipients == 10

      File.write!(shared, """
      # sovite shared config: version 2, from mx2@h, 2026-10-18T00:00:00Z
      [server]
      hostname = "shared.example.com"

      [smtp]
      max_recipients = 20
      max_errors = 3

      [domains]
      relay = ["relay.example"]
      """)

      assert {:ok, config} = Config.load(local)
      assert config.server.hostname == "mx1.example.com"
      assert config.smtp.max_recipients == 10
      assert config.smtp.max_errors == 3
      assert config.domains.relay == ["relay.example"]
      assert config.raw["smtp"] == %{"max_recipients" => 10, "max_errors" => 3}

      assert {:ok, config} = Config.load_with_shared(local, "[smtp]\nmax_errors = 4")
      assert config.smtp.max_errors == 4
      assert config.domains.relay == []
    end

    test "cannot have a [cluster] table, or invalid TOML", %{shared: shared, local: local} do
      File.write!(shared, "[cluster]\nenabled = false")
      assert {:error, [error]} = Config.load(local)
      assert Exception.message(error) =~ "the shared config cannot have a [cluster] table"

      File.write!(shared, "[smtp")
      assert {:error, [error]} = Config.load(local)
      assert Exception.message(error) =~ "#{shared}: invalid TOML"

      assert {:error, [error]} = Config.load_with_shared(local, "[smtp]\nmax_errors = 0")
      assert Exception.message(error) =~ "smtp.max_errors"
    end
  end
end
