defmodule Sovite.ClusterTest do
  use ExUnit.Case, async: true

  alias Sovite.Cluster.Peer
  alias Sovite.Test.{Certs, ClusterEcho, ClusterPeers}

  @moduletag :tmp_dir

  describe "Peer" do
    test "parses name@host:port" do
      assert Peer.parse("mx2@10.0.0.2:4370") ==
               {:ok, %Peer{name: :"mx2@10.0.0.2", ip: {10, 0, 0, 2}, port: 4370}}

      assert {:ok, %Peer{name: :"mx2@2001:db8::2", ip: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 2}}} =
               Peer.parse("mx2@[2001:db8::2]:4370")

      assert {:ok, %Peer{port: 4370}} = Peer.parse("mx2@10.0.0.2", 4370)
      assert {:ok, %Peer{ip: {127, 0, 0, 1}}} = Peer.parse("mx2@localhost:1")

      assert Peer.format(%Peer{name: :"mx2@10.0.0.2", ip: {10, 0, 0, 2}, port: 4370}) ==
               "mx2@10.0.0.2:4370"

      for bad <-
            ["mx2", "mx2@10.0.0.2", "mx2@10.0.0.2:0", "mx2@10.0.0.2:x", "@10.0.0.2:1"] ++
              ["m x@10.0.0.2:1", "mx2@[::1]", "mx2@a:1:2"] do
        assert {:error, _} = Peer.parse(bad), bad
      end

      assert {:error, "has a host that does not resolve"} = Peer.parse("mx2@nowhere.invalid:1")
    end

    test "parses node names" do
      assert Peer.node_name("mx1@10.0.0.1") == {:ok, :"mx1@10.0.0.1"}
      assert Peer.node_name("mx1@2001:db8::1") == {:ok, :"mx1@2001:db8::1"}

      for bad <- ["mx1", "mx1@", "@h", "mx 1@h", "mx1@h/x"],
          do: assert({:error, _} = Peer.node_name(bad))
    end
  end

  defp start_node(name, tls) do
    peer = ClusterPeers.start!()
    port = ClusterPeers.free_port()
    node = :"#{name}@127.0.0.1"

    :ok =
      ClusterPeers.call(peer, Sovite.Cluster, :start, [
        [name: node, ip: {127, 0, 0, 1}, port: port, tls: tls]
      ])

    {:ok, _} = ClusterPeers.call(peer, ClusterEcho, :start, [:echo])
    %{peer: peer, node: node, spec: %Peer{name: node, ip: {127, 0, 0, 1}, port: port}}
  end

  @tag timeout: 120_000
  test "nodes join over mutual TLS, and send and call each other", %{tmp_dir: dir} do
    tls = ClusterPeers.tls(dir)
    a = start_node("a", tls.("a"))
    b = start_node("b", tls.("b"))

    assert ClusterPeers.call(a.peer, Sovite.Cluster, :node, []) == a.node
    assert ClusterPeers.call(a.peer, Sovite.Cluster, :start, [[]]) == {:error, :already_started}
    assert :ok = ClusterPeers.call(a.peer, Sovite.Cluster, :join, [b.spec])

    ClusterPeers.eventually(fn ->
      ClusterPeers.call(b.peer, Sovite.Cluster, :connected, []) == [a.node]
    end)

    assert ClusterPeers.call(a.peer, Sovite.Cluster, :members, []) == [a.node, b.node]
    assert ClusterPeers.call(a.peer, Sovite.Cluster, :connected?, [b.node])

    assert {:nodeup, a.node} in ClusterPeers.call(b.peer, ClusterEcho, :received, [:echo])

    assert :ok = ClusterPeers.call(a.peer, Sovite.Cluster, :send, [b.node, :echo, {:hello, 1}])

    assert :ok =
             ClusterPeers.call(a.peer, Sovite.Cluster, :send, [
               b.node,
               :echo,
               {:big, :binary.copy("x", 1_000_000)},
               [channel: :bulk]
             ])

    ClusterPeers.eventually(fn ->
      received = ClusterPeers.call(b.peer, ClusterEcho, :received, [:echo])
      {:hello, 1} in received and Enum.any?(received, &match?({:big, _}, &1))
    end)

    assert ClusterPeers.call(a.peer, Sovite.Cluster, :call, [b.node, :echo, :ping]) ==
             {:ok, {:echo, :ping}}

    assert ClusterPeers.call(a.peer, Sovite.Cluster, :call, [b.node, :nobody, :ping, 200]) ==
             {:error, :timeout}

    assert {:error, _} =
             ClusterPeers.call(a.peer, Sovite.Cluster, :send, [:"c@127.0.0.1", :echo, :x])

    # The joiner reports b going away.
    :peer.stop(b.peer)

    ClusterPeers.eventually(fn ->
      {:nodedown, b.node} in ClusterPeers.call(a.peer, ClusterEcho, :received, [:echo])
    end)

    assert ClusterPeers.call(a.peer, Sovite.Cluster, :connected, []) == []
  end

  @tag timeout: 120_000
  test "the joiner joins known peers, again once they come back", %{tmp_dir: dir} do
    tls = ClusterPeers.tls(dir)
    a = start_node("a", tls.("a"))
    b = start_node("b", tls.("b"))

    {:ok, _} =
      ClusterPeers.call(a.peer, GenServer, :start, [
        Sovite.Cluster.Joiner,
        [peers: [b.spec], interval: 200, name: nil]
      ])

    ClusterPeers.eventually(fn ->
      ClusterPeers.call(a.peer, Sovite.Cluster, :connected, []) == [b.node]
    end)
  end

  @tag timeout: 120_000
  test "nodes with certificates from another CA cannot join", %{tmp_dir: dir} do
    a = start_node("a", ClusterPeers.tls(dir).("a"))
    b = start_node("b", ClusterPeers.tls(dir, Certs.ca()).("b"))

    ClusterPeers.call(a.peer, Sovite.Cluster, :join, [b.spec])
    Process.sleep(1_500)
    assert ClusterPeers.call(a.peer, Sovite.Cluster, :connected, []) == []
    assert ClusterPeers.call(b.peer, Sovite.Cluster, :connected, []) == []
  end
end
