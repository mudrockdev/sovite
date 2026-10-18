defmodule Sovite.Core.Cluster.PlacementTest do
  # Placement without Partisan running: no other node is connected.
  use ExUnit.Case, async: true

  alias Sovite.Core.Cluster.Placement
  alias Sovite.Core.{Config, IPPools}
  alias Sovite.Queue.Envelope

  @moduletag :tmp_dir

  @smtp %{transport: :smtp, nexthop: {:mx, "example.net"}, source: %{}, auth: nil}
  @envelope %Envelope{queue_id: "Q", sender: "", recipients: ["a@example.net"]}

  test "options only for clusters" do
    {:ok, config} = Config.parse("")
    assert Placement.placement_opts(config) == nil
  end

  test "a node alone delivers everything itself" do
    opts = %{node: "a@127.0.0.1", affinity: true, ip_pools: nil}

    for nexthop <- [
          {:mx, "example.net"},
          {:host, %{host: "relay", port: 25}},
          {:literal, {192, 0, 2, 1}}
        ] do
      route = {:deliver, %{@smtp | nexthop: nexthop}}
      assert Placement.place(route, opts, @envelope) == route
    end

    # Not SMTP, already handed over, or no cluster.
    assert Placement.place({:deliver, %{transport: :local}}, opts, @envelope) ==
             {:deliver, %{transport: :local}}

    route = {:deliver, @smtp}
    assert Placement.place(route, opts, %{@envelope | forwarded_from: "b@127.0.0.1"}) == route
    assert Placement.place(route, nil, @envelope) == route
    assert Placement.place({:defer, "4.0.0", "x"}, opts, @envelope) == {:defer, "4.0.0", "x"}
  end

  test "mail of a pool on nodes that are not up waits", %{tmp_dir: _dir} do
    {:ok, config} =
      Config.parse("""
      [cluster]
      enabled = true
      node_name = "a@127.0.0.1"
      address = "127.0.0.1"
      cert_file = "/c"
      key_file = "/k"
      ca_file = "/ca"
      [[ip_pool]]
      name = "far"
      [[ip_pool.address]]
      address = "192.0.2.1"
      node = "b@127.0.0.1"
      [[ip_pool]]
      name = "near"
      [[ip_pool.address]]
      address = "192.0.2.2"
      """)

    name = :"placement_#{System.unique_integer([:positive])}"
    start_supervised!({IPPools, IPPools.opts(config, name, nil)})
    opts = %{Placement.placement_opts(config) | ip_pools: name}

    assert Placement.place({:deliver, Map.put(@smtp, :pool, "far")}, opts, @envelope) ==
             {:defer, "4.4.0", "no cluster node with an address of IP pool far is up"}

    route = {:deliver, Map.put(@smtp, :pool, "near")}
    assert Placement.place(route, opts, @envelope) == route
  end

  test "ranks nodes the same way everywhere" do
    nodes = ["a@h", "b@h", "c@h"]
    ranked = Placement.rank("example.net", nodes)
    assert Enum.sort(ranked) == nodes
    assert Placement.rank("example.net", Enum.reverse(nodes)) == ranked
    # Removing a node that is not first keeps the first.
    [first | rest] = ranked
    assert hd(Placement.rank("example.net", [first | Enum.drop(rest, 1)])) == first

    assert Placement.existing_node("never-made-into-an-atom-#{System.unique_integer()}") ==
             {:error, :unknown_node}
  end
end
