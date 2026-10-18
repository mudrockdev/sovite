defmodule Sovite.Core.ClusterTest do
  # Whole Sovite servers clustered in VMs of their own (see
  # Sovite.Test.ClusterPeers): the shared configuration, shared rate
  # limits, copies of queued messages and taking over, leaving, and
  # handing mail to the node that should send it.
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias Sovite.Core.{CLI, Cluster}
  alias Sovite.Core.Cluster.Queue
  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.Test.{ClusterPeers, FakeMTA}

  @moduletag :tmp_dir
  @moduletag timeout: 120_000

  setup %{tmp_dir: dir} do
    mta = start_supervised!({FakeMTA, owner: self()})
    %{tls: ClusterPeers.tls(dir), mta: mta, dir: dir}
  end

  # A node's settings: its name, the last byte of its source address,
  # and extra TOML.
  defp node_config(context, name, opts) do
    dir = Path.join(context.dir, name)
    File.mkdir_p!(dir)
    tls = context.tls.(name)

    path = Path.join(dir, "sovite.toml")

    File.write!(path, """
    [server]
    hostname = "#{name}.example.com"
    shutdown_timeout = "1s"
    [database]
    path = "#{dir}/sovite.db"
    [queue]
    directory = "#{dir}/queue"
    min_backoff = "1h"
    max_backoff = "1h"
    [[listener]]
    address = "127.0.0.1"
    port = 0
    #{admin(dir, opts[:admin_port])}
    [log]
    level = "error"
    [dns]
    dnssec = "off"
    [delivery]
    relayhost = "[127.0.0.1]:#{FakeMTA.port(context.mta)}"
    tls = "none"
    source_address = ["127.0.0.#{opts[:source]}"]
    #{opts[:delivery]}
    [cluster]
    enabled = true
    node_name = "#{name}@127.0.0.1"
    address = "127.0.0.1"
    port = #{opts[:port]}
    seeds = #{inspect(opts[:seeds] || [])}
    cert_file = "#{tls[:cert_file]}"
    key_file = "#{tls[:key_file]}"
    ca_file = "#{tls[:ca_file]}"
    shared_config = "#{dir}/cluster.toml"
    join_interval = "200ms"
    sync_interval = "100ms"
    handover_after = "1s"
    #{opts[:cluster]}
    #{opts[:toml]}
    """)

    %{
      name: name,
      node: :"#{name}@127.0.0.1",
      dir: dir,
      path: path,
      queue: Path.join(dir, "queue")
    }
  end

  defp admin(_dir, nil), do: "[admin]\nenabled = false"

  defp admin(dir, port),
    do: "[admin]\nport = #{port}\ntoken_file = \"#{dir}/admin.token\""

  defp start_node(config) do
    peer = ClusterPeers.start!()
    {:ok, _apps} = ClusterPeers.call(peer, Application, :ensure_all_started, [:sovite])

    {:ok, _pid} =
      ClusterPeers.call(peer, Supervisor, :start_child, [
        Sovite.Supervisor,
        {Sovite.Core.Supervisor, config_path: config.path}
      ])

    Map.put(config, :peer, peer)
  end

  defp nodes(context, specs) do
    ports = Map.new(specs, fn {name, _opts} -> {name, ClusterPeers.free_port()} end)

    Map.new(specs, fn {name, opts} ->
      seeds = for seed <- opts[:seeds] || [], do: "#{seed}@127.0.0.1:#{ports[seed]}"
      opts = Keyword.merge(opts, port: ports[name], seeds: seeds)
      {String.to_atom(name), node_config(context, name, opts)}
    end)
  end

  defp call(node, module, function, args),
    do: ClusterPeers.call(node.peer, module, function, args)

  defp connected(a, b) do
    ClusterPeers.eventually(fn ->
      status = call(a, Cluster, :status, [])
      Enum.any?(status.members, &(&1.node == b.name <> "@127.0.0.1" and &1.status == "up"))
    end)
  end

  # Writes a message into a node's spool (incoming/), without telling its
  # queue manager.
  defp spool(node, recipients \\ ["b@example.net"]) do
    envelope = %Envelope{
      queue_id: ID.generate(),
      sender: "a@sender.example",
      recipients: recipients,
      received_at: DateTime.utc_now()
    }

    :ok = call(node, ClusterPeers, :write_message, [node.queue, envelope])
    envelope.queue_id
  end

  defp queued?(node, queue, id), do: File.exists?(Spool.path(node.queue, queue, id))

  test "nodes form a cluster, and share their configuration and rate limits", context do
    admin_port = ClusterPeers.free_port()

    %{a: a, b: b} =
      nodes(context, [{"a", source: 2, seeds: ["b"], admin_port: admin_port}, {"b", source: 3}])

    a = start_node(a)
    b = start_node(b)
    connected(a, b)
    connected(b, a)

    status = call(a, Cluster, :status, [[remote: true]])
    assert status.node == "a@127.0.0.1"

    assert %{status: "up", hostname: "b.example.com", queue: %{}} =
             Enum.find(status.members, &(&1.node == "b@127.0.0.1"))

    assert %{status: "self"} = Enum.find(status.members, &(&1.node == "a@127.0.0.1"))

    # The shared configuration goes to every node, which reloads.
    assert {:error, [reason]} = call(a, Cluster, :push_config, ["[smtp]\nmax_errors = 0"])
    assert reason =~ "smtp.max_errors"
    assert {:ok, 1} = call(a, Cluster, :push_config, ["[smtp]\nmax_errors = 7\n"])

    ClusterPeers.eventually(fn ->
      call(b, Sovite.Core.Config, :get, []).smtp.max_errors == 7
    end)

    assert File.read!(Path.join(b.dir, "cluster.toml")) =~
             ~r/\A# sovite shared config: version 1, from a@127.0.0.1, /

    assert call(b, Cluster, :status, []).shared_config == %{version: 1, origin: "a@127.0.0.1"}

    # sovitectl, through a's admin API.
    output = capture_io(fn -> assert CLI.run(["--config", a.path, "cluster", "status"]) == 0 end)
    assert output =~ "Node:           a@127.0.0.1"
    assert output =~ "Shared config:  version 1, from a@127.0.0.1"
    assert output =~ ~r/b@127.0.0.1 +up +b.example.com, sovite /

    shared = Path.join(context.dir, "shared.toml")
    File.write!(shared, "[smtp]\nmax_errors = 8\n")

    assert capture_io(fn ->
             assert CLI.run(["--config", a.path, "cluster", "config", "push", shared]) == 0
           end) == "sent #{shared} to the cluster as version 2\n"

    ClusterPeers.eventually(fn ->
      call(b, Sovite.Core.Config, :get, []).smtp.max_errors == 8
    end)

    File.write!(shared, "[smtp]\nmax_errors = -1\n")

    assert capture_io(:stderr, fn ->
             assert CLI.run(["--config", a.path, "cluster", "config", "push", shared]) == 1
           end) =~ "smtp.max_errors"

    assert capture_io(:stderr, fn ->
             assert CLI.run(["--config", a.path, "cluster", "join", "x@nowhere.invalid:1"]) == 1
           end) =~ "x@nowhere.invalid:1 has a host that does not resolve"

    assert capture_io(fn ->
             assert CLI.run(["--config", a.path, "ip-pool", "status"]) == 0
           end) =~ "no IP pools"

    # Events counted on one node count on the others.
    rate_limit = Sovite.Core.RateLimit
    call(a, Sovite.Abuse.RateLimit, :add, [rate_limit, {:client, :x}, 60_000, 3])

    ClusterPeers.eventually(fn ->
      call(b, Sovite.Abuse.RateLimit, :count, [rate_limit, {:client, :x}, 60_000]) == 3
    end)

    # A node that joins later gets the shared configuration.
    %{c: c} = nodes(context, [{"c", source: 4, seeds: ["a"]}])
    c = start_node(%{c | path: rewrite_seed(c.path, a)})
    connected(c, a)

    ClusterPeers.eventually(fn ->
      call(c, Sovite.Core.Config, :get, []).smtp.max_errors == 8
    end)
  end

  # Points the seed of a node started on its own at a running node.
  defp rewrite_seed(path, seed) do
    port = call(seed, :partisan_config, :get, [:listen_addrs]) |> hd() |> Map.fetch!(:port)
    text = File.read!(path)
    File.write!(path, Regex.replace(~r/seeds = .*/, text, ~s(seeds = ["#{seed.node}:#{port}"])))
    path
  end

  test "messages of a node that stays down are taken over, and dropped when it is back",
       context do
    %{a: a, b: b} = nodes(context, [{"a", source: 2, seeds: ["b"]}, {"b", source: 3}])
    a = start_node(a)
    b = start_node(b)
    connected(a, b)
    connected(b, a)

    # Held, so that nobody delivers it.
    id = spool(a)
    assert :ok = call(a, Sovite.Core.QueueManager, :hold, [Sovite.Core.QueueManager, id])

    ClusterPeers.eventually(fn -> call(b, Queue, :status, []).copies == %{"a@127.0.0.1" => 1} end)

    # Delivered messages lose their copies.
    done = spool(a)
    ClusterPeers.eventually(fn -> call(b, Queue, :status, []).copies == %{"a@127.0.0.1" => 2} end)
    assert :ok = call(a, Sovite.Core.QueueManager, :delete, [Sovite.Core.QueueManager, done])
    ClusterPeers.eventually(fn -> call(b, Queue, :status, []).copies == %{"a@127.0.0.1" => 1} end)

    :peer.stop(a.peer)
    ClusterPeers.eventually(fn -> queued?(b, :hold, id) end)

    assert call(b, Queue, :status, []) == %{
             copies: %{"a@127.0.0.1" => 0},
             taken_over: %{"a@127.0.0.1" => 1}
           }

    assert queued?(a, :hold, id)

    # a comes back, and learns that b has its message now.
    a = start_node(a)
    connected(a, b)
    ClusterPeers.eventually(fn -> not queued?(a, :hold, id) end)

    ClusterPeers.eventually(fn ->
      call(b, Queue, :status, []).taken_over == %{"a@127.0.0.1" => 0}
    end)

    assert queued?(b, :hold, id)
  end

  test "a node that leaves hands its queue over", context do
    %{a: a, b: b} = nodes(context, [{"a", source: 2, seeds: ["b"]}, {"b", source: 3}])
    a = start_node(a)
    b = start_node(b)
    connected(a, b)

    held = spool(a)
    assert :ok = call(a, Sovite.Core.QueueManager, :hold, [Sovite.Core.QueueManager, held])
    waiting = spool(a, ["x@nowhere.invalid"])
    assert :ok = call(a, Sovite.Core.QueueManager, :hold, [Sovite.Core.QueueManager, waiting])

    assert {:ok, %{handed_over: 2, failed: 0}} = call(a, Cluster, :leave, [])
    assert queued?(b, :hold, held)
    assert queued?(b, :hold, waiting)
    refute queued?(a, :hold, held)

    ClusterPeers.eventually(fn -> call(b, Sovite.Cluster, :members, []) == [b.node] end)
  end

  test "mail goes out from the node with the IP pool, or that owns the destination", context do
    mta = context.mta

    pool = """
    [[ip_pool]]
    name = "far"
    [[ip_pool.address]]
    address = "127.0.0.5"
    node = "b@127.0.0.1"
    """

    %{a: a, b: b} =
      nodes(context, [
        {"a", source: 2, seeds: ["b"], cluster: "destination_affinity = true", toml: pool},
        {"b", source: 3, cluster: "destination_affinity = true", toml: pool}
      ])

    a = start_node(a)
    b = start_node(b)
    connected(a, b)
    connected(b, a)

    # Each node sends one message to the relay host: both leave from its
    # owner.
    for node <- [a, b] do
      id = spool(node)
      call(node, Sovite.Core.QueueManager, :notify, [Sovite.Core.QueueManager, id])
    end

    # (The second may reuse the owner's connection.)
    assert_receive {:fake_mta, ^mta, {:peer, owner}}, 10_000
    assert owner in [{127, 0, 0, 2}, {127, 0, 0, 3}]
    assert_receive {:fake_mta, ^mta, {:message, %{helo: first}}}, 10_000
    assert_receive {:fake_mta, ^mta, {:message, %{helo: second}}}, 10_000
    assert first == second
    assert first == if(owner == {127, 0, 0, 2}, do: "a.example.com", else: "b.example.com")

    # A tenant whose pool is on b only.
    for node <- [a, b] do
      File.write!(
        node.path,
        File.read!(node.path) <> ~s([[tenant]]\nname = "t"\nip_pool = "far"\n)
      )

      assert :ok = call(node, Sovite.Core.Control, :reload, [Sovite.Core.Control])
    end

    envelope = %Envelope{
      queue_id: ID.generate(),
      sender: "a@sender.example",
      recipients: ["b@example.net"],
      received_at: DateTime.utc_now(),
      tenant: "t"
    }

    :ok = call(a, ClusterPeers, :write_message, [a.queue, envelope])
    call(a, Sovite.Core.QueueManager, :notify, [Sovite.Core.QueueManager, envelope.queue_id])
    assert_receive {:fake_mta, ^mta, {:peer, {127, 0, 0, 5}}}, 10_000
    assert_receive {:fake_mta, ^mta, {:message, %{rcpt_to: ["b@example.net"]}}}, 10_000
  end
end
