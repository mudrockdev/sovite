defmodule Sovite.Core.MTA.IPPoolsTest do
  # IP pools: picking addresses, warm-up limits, counts that survive a
  # restart, and deliveries from pool addresses.
  use ExUnit.Case, async: true

  alias Sovite.Core.Config
  alias Sovite.Core.MTA.{IPPools, QueueManager}
  alias Sovite.Core.Repo.Tables.IPAddressCounts
  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.Test.{Database, FakeDNS, FakeMTA, TelemetryForwarder}

  @moduletag :tmp_dir
  @moduletag :capture_log

  defp config(toml) do
    {:ok, config} = Config.parse(toml)
    config
  end

  defp start(context, toml) do
    name = :"ip_pools_#{System.unique_integer([:positive])}"
    opts = IPPools.opts(config(toml), name, context.repo)
    pid = start_supervised!({IPPools, opts}, id: name)
    Map.merge(context, %{pools: name, pid: pid, opts: opts})
  end

  setup %{tmp_dir: dir} do
    %{repo: Database.start!(dir)}
  end

  @pools """
  [[ip_pool]]
  name = "main"
  overflow = "spare"

  [[ip_pool.address]]
  address = "127.0.0.2"
  helo = "a.example.com"
  daily_limit = 2

  [[ip_pool.address]]
  address = "127.0.0.3"
  daily_limit = 1

  [[ip_pool.address]]
  address = "::1"
  helo = "six.example.com"

  [[ip_pool]]
  name = "spare"

  [[ip_pool.address]]
  address = "127.0.0.4"
  daily_limit = 1
  """

  test "warm-up limits" do
    today = Date.utc_today()
    address = %{warmup_start: Date.add(today, -1), warmup: [10, 20], daily_limit: nil}

    assert IPPools.limit(address, today) == 20
    assert IPPools.limit(address, Date.add(today, -1)) == 10
    assert IPPools.limit(address, Date.add(today, -2)) == 0
    assert IPPools.limit(address, Date.add(today, 1)) == :infinity
    assert IPPools.limit(%{address | daily_limit: 5}, Date.add(today, 1)) == 5
    assert IPPools.limit(%{warmup_start: nil, daily_limit: nil}, today) == :infinity
    assert IPPools.limit(%{warmup_start: nil, daily_limit: 3}, today) == 3
    assert IPPools.opts(config(""), :x, nil) == nil
  end

  test "picks the addresses with the most room, then overflows, then refuses", context do
    TelemetryForwarder.attach([[:sovite, :ip_pool, :exhausted]])
    %{pools: pools} = start(context, @pools)

    assert {:ok, source} = IPPools.source(pools, "main")
    assert source.source == %{ipv4: {127, 0, 0, 2}, ipv6: {0, 0, 0, 0, 0, 0, 0, 1}}
    assert source.helo == %{ipv4: "a.example.com", ipv6: "six.example.com"}

    IPPools.count(pools, {127, 0, 0, 2}, 1)
    # Half of .2's limit is left, all of .3's.
    assert {:ok, %{source: %{ipv4: {127, 0, 0, 3}}, helo: helo}} = IPPools.source(pools, "main")
    refute Map.has_key?(helo, :ipv4)

    IPPools.count(pools, {127, 0, 0, 3}, 1)
    IPPools.count(pools, {127, 0, 0, 2}, 1)
    # IPv4 is full; IPv6 has no limit.
    assert {:ok, %{source: source}} = IPPools.source(pools, "main")
    assert source == %{ipv6: {0, 0, 0, 0, 0, 0, 0, 1}}

    assert {:ok, %{source: %{ipv4: {127, 0, 0, 4}}}} = IPPools.source(pools, "spare")
    IPPools.count(pools, {127, 0, 0, 4}, 1)
    assert {:error, "IP pool spare has reached its daily limit"} = IPPools.source(pools, "spare")
    assert_received {:telemetry, _, _, %{pool: "spare"}}
    assert {:error, "there is no IP pool nope"} = IPPools.source(pools, "nope")
    assert IPPools.count(pools, {127, 0, 0, 4}, 0) == :ok

    assert [main, spare] = IPPools.status(pools)
    assert main.name == "main"

    assert Enum.map(main.addresses, &{&1.address, &1.sent_today, &1.limit_today}) == [
             {"127.0.0.2", 2, 2},
             {"127.0.0.3", 1, 1},
             {"::1", 0, nil}
           ]

    assert spare.overflow == nil
  end

  test "overflow pools take over when a pool is full", context do
    %{pools: pools} =
      start(context, """
      [[ip_pool]]
      name = "main"
      overflow = "spare"
      [[ip_pool.address]]
      address = "127.0.0.2"
      daily_limit = 1
      [[ip_pool]]
      name = "spare"
      [[ip_pool.address]]
      address = "127.0.0.4"
      """)

    IPPools.count(pools, {127, 0, 0, 2}, 1)
    assert {:ok, %{source: %{ipv4: {127, 0, 0, 4}}}} = IPPools.source(pools, "main")
  end

  test "counts are stored, and read back after a restart", context do
    %{pools: pools, pid: pid} = context = start(context, @pools)
    IPPools.count(pools, {127, 0, 0, 2}, 2)
    stop_supervised!(pools)
    refute Process.alive?(pid)

    assert IPAddressCounts.day(context.repo, Date.utc_today()) == %{"127.0.0.2" => 2}
    assert [%{address: "127.0.0.2", messages: 2}] = IPAddressCounts.list(context.repo)

    %{pools: pools} = start(context, @pools)
    assert {:ok, %{source: %{ipv4: {127, 0, 0, 3}}}} = IPPools.source(pools, "main")
    IPPools.count(pools, {127, 0, 0, 2}, 1)
    send(Process.whereis(pools), :flush)
    :sys.get_state(pools)
    assert IPAddressCounts.day(context.repo, Date.utc_today()) == %{"127.0.0.2" => 3}
    assert IPAddressCounts.delete_before(context.repo, Date.add(Date.utc_today(), 1)) == 1
  end

  test "pools with addresses on other nodes only are placed there", context do
    toml = """
    [cluster]
    enabled = true
    node_name = "a@127.0.0.1"
    address = "127.0.0.1"
    cert_file = "/c"
    key_file = "/k"
    ca_file = "/ca"
    [[ip_pool]]
    name = "remote"
    overflow = "mixed"
    [[ip_pool.address]]
    address = "192.0.2.1"
    node = "b@127.0.0.1"
    [[ip_pool]]
    name = "mixed"
    [[ip_pool.address]]
    address = "192.0.2.2"
    node = "c@127.0.0.1"
    [[ip_pool.address]]
    address = "192.0.2.3"
    node = "a@127.0.0.1"
    [[ip_pool]]
    name = "far"
    [[ip_pool.address]]
    address = "192.0.2.4"
    node = "c@127.0.0.1"
    [[ip_pool.address]]
    address = "192.0.2.5"
    node = "b@127.0.0.1"
    """

    %{pools: pools} = start(context, toml)
    assert IPPools.placement(pools, "mixed") == :local
    # Its overflow pool has an address here.
    assert IPPools.placement(pools, "remote") == :local
    assert IPPools.placement(pools, "far") == {:remote, ["b@127.0.0.1", "c@127.0.0.1"]}
    assert IPPools.placement(pools, "nope") == :local
    assert {:ok, %{source: %{ipv4: {192, 0, 2, 3}}}} = IPPools.source(pools, "remote")
  end

  describe "delivery" do
    setup context do
      dir = context.tmp_dir
      queue = Path.join(dir, "queue")
      :ok = Spool.init(queue)
      mta = start_supervised!({FakeMTA, owner: self()}, id: :mta)
      Map.merge(context, %{queue: queue, mta: mta})
    end

    defp start_manager(context, delivery, toml \\ "") do
      config =
        config("""
        [server]
        hostname = "mx.example.org"
        [queue]
        directory = "#{context.queue}"
        min_backoff = "1h"
        max_backoff = "1h"
        [delivery]
        source_address = ["127.0.0.9"]
        #{delivery}
        #{toml}
        #{@pools}
        """)

      context = start(context, @pools)

      manager_opts =
        QueueManager.opts(config) ++
          [
            ip_pools: context.pools,
            name: nil,
            resolver:
              FakeDNS.resolver(%{
                {"example.net", :mx} => [{10, "mx.example.net"}],
                {"mx.example.net", :a} => [{127, 0, 0, 1}]
              }),
            port: FakeMTA.port(context.mta),
            client: [command_timeout: 2_000]
          ]

      Map.put(context, :manager, start_supervised!({QueueManager, manager_opts}))
    end

    defp enqueue(context, fields \\ []) do
      envelope =
        struct!(
          Envelope,
          [
            queue_id: ID.generate(),
            sender: "a@sender.example",
            recipients: ["b@example.net"],
            received_at: DateTime.utc_now()
          ] ++ fields
        )

      {:ok, writer} = Spool.open(context.queue, envelope)
      {:ok, writer} = Spool.write(writer, "Subject: hi\r\n\r\nHello\r\n")
      {:ok, _path, _size} = Spool.commit(writer)
      QueueManager.notify(context.manager, envelope.queue_id)
      envelope.queue_id
    end

    test "tenant pools come before the default pool, and before source_address", context do
      context =
        start_manager(context, ~s(ip_pool = "spare"), """
        [[tenant]]
        name = "acme"
        domains = ["acme.example"]
        ip_pool = "main"
        """)

      mta = context.mta
      enqueue(context, tenant: "acme")
      assert_receive {:fake_mta, ^mta, {:peer, {127, 0, 0, 2}}}, 5_000
      assert_receive {:fake_mta, ^mta, {:message, %{helo: "a.example.com"}}}, 5_000

      enqueue(context)
      assert_receive {:fake_mta, ^mta, {:peer, {127, 0, 0, 4}}}, 5_000
      assert_receive {:fake_mta, ^mta, {:message, %{helo: "mx.example.org"}}}, 5_000

      # Counted once per message.
      Process.sleep(100)

      assert Enum.map(IPPools.status(context.pools), fn pool ->
               Enum.map(pool.addresses, & &1.sent_today)
             end) == [[1, 0, 0], [1]]

      # The spare pool is full now: deferred.
      TelemetryForwarder.attach([[:sovite, :queue, :message, :deferred]])
      id = enqueue(context)
      assert_receive {:telemetry, _, _, %{queue_id: ^id}}, 5_000
      {:ok, loaded} = Spool.load(Spool.path(context.queue, :deferred, id))

      assert [{:recipient, "b@example.net", :deferred, %{status: "4.7.0", reply: reply}} | _] =
               loaded.records

      assert reply == "IP pool spare has reached its daily limit"
    end

    test "without a pool, source_address applies", context do
      context = start_manager(context, "")
      mta = context.mta
      enqueue(context)
      assert_receive {:fake_mta, ^mta, {:peer, {127, 0, 0, 9}}}, 5_000
    end
  end
end
