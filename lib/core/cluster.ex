defmodule Sovite.Core.Cluster do
  @moduledoc """
  Runs Sovite as one node of a cluster (`[cluster]`), over
  `Sovite.Cluster` (Partisan, with mutual TLS).

      [cluster]
      enabled = true
      node_name = "mx1@10.0.0.1"
      address = "10.0.0.1"
      seeds = ["mx2@10.0.0.2", "mx3@10.0.0.3"]
      cert_file = "/etc/sovite/cluster/node.pem"
      key_file = "/etc/sovite/cluster/node.key"
      ca_file = "/etc/sovite/cluster/ca.pem"
      shared_config = "/var/lib/sovite/cluster.toml"

  Each node knows a few others (`seeds`); it joins them every
  `join_interval` until connected, and learns about the rest from them.
  Nodes connect over TLS 1.3, and accept only peers whose certificate
  `ca_file` signed, so that CA must be the cluster's own. The peer port
  (`port`, 4370) should only be reachable from the other nodes.

  The nodes share:

    * their configuration (`Sovite.Core.Cluster.SharedConfig`);
    * rate limits, failed-login bans, suspended accounts, and with
      SQLite, greylisting (`Sovite.Core.Cluster.Sync`): nodes that share
      a PostgreSQL or MySQL database share the rest of the database
      anyway, so use one for the domains, users, and other tables;
    * their queues (`Sovite.Core.MTA.Cluster.Queue`): copies of each queued
      message on other nodes, which deliver it when its node stays
      down; mail handed to the node that sends from the right IP pool,
      or that owns its destination; and the queue of a node that leaves.

  This process starts Partisan, which then keeps running until the VM
  stops, and answers other nodes' questions about this one.

  ## Telemetry

  See `Sovite.Cluster.Joiner` for nodes coming and going, and:

    * `[:sovite, :cluster, :config, :applied]` - `%{version}`, `%{origin}`,
      when this node takes a new shared configuration.
    * `[:sovite, :cluster, :config, :rejected]` - `%{version}`, `%{origin,
      reason}`, when it cannot.
  """

  use GenServer

  alias Sovite.Cluster, as: Mesh
  alias Sovite.Cluster.{Joiner, Peer}
  alias Sovite.Core.Cluster.{SharedConfig, Sync}
  alias Sovite.Core.Control
  alias Sovite.Core.MTA.Cluster.Queue
  alias Sovite.Core.MTA.QueueInfo

  @version Mix.Project.config()[:version]

  @doc """
  The cluster's child specs, in start order, or none when the cluster is
  off.
  """
  @spec child_specs(Sovite.Core.Config.t(), map()) :: [
          Supervisor.child_spec() | {module(), term()}
        ]
  def child_specs(%{cluster: %{enabled: false}}, _runtime), do: []

  def child_specs(config, runtime) do
    cluster = config.cluster

    [
      {__MODULE__,
       cluster: cluster,
       config_path: runtime.config_path,
       control: runtime.control,
       queue_manager: runtime.queue_manager,
       directory: config.queue.directory,
       hostname: config.server.hostname,
       stack: config.stack,
       max_message_size: config.smtp.max_message_size},
      {Joiner,
       name: Joiner, peers: cluster.seeds, port: cluster.port, interval: cluster.join_interval},
      {Sync, Sync.opts(config, runtime)}
    ] ++ if(runtime.queue_manager, do: [{Queue, Queue.opts(config, runtime)}], else: [])
  end

  @doc false
  # The clock of rate limits shared by the cluster, so that the nodes'
  # buckets line up: hosts must keep their clocks in sync (NTP).
  def clock, do: System.os_time(:millisecond)

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc """
  The cluster as this node sees it: its name, the members and whether
  each is connected, and the shared configuration's version. With
  `remote: true`, each connected node is also asked for its version,
  host name, uptime, and queue sizes. `:server` is this process, if not
  registered under its module name.
  """
  @spec status(keyword()) :: map()
  def status(opts \\ []) do
    status = GenServer.call(Keyword.get(opts, :server, __MODULE__), :status)

    if opts[:remote] do
      details =
        status.members
        |> Enum.filter(&(&1.status == "up"))
        |> Task.async_stream(&{&1.node, summary(&1.node)}, timeout: 6_000, on_timeout: :kill_task)
        |> Enum.flat_map(fn
          {:ok, {node, {:ok, summary}}} -> [{node, summary}]
          _ -> []
        end)
        |> Map.new()

      update_in(status.members, fn members ->
        Enum.map(members, &Map.merge(&1, Map.get(details, &1.node, %{})))
      end)
    else
      status
    end
  end

  defp summary(node) do
    Mesh.call(String.to_existing_atom(node), __MODULE__, :summary, 5_000)
  rescue
    ArgumentError -> {:error, :unknown_node}
  end

  @doc """
  Sends `content` (TOML) to every node as the new shared configuration,
  after checking that this node can run with it. Returns the new
  version, or the reasons it does not work here.
  """
  @spec push_config(GenServer.server(), String.t()) ::
          {:ok, non_neg_integer()} | {:error, [String.t()]}
  def push_config(server \\ __MODULE__, content),
    do: GenServer.call(server, {:push_config, content}, 30_000)

  @doc """
  Takes this node out of the cluster: drains it (see
  `Sovite.Core.Control`), so it stops receiving and delivering mail,
  hands its queue to the connected nodes (`Sovite.Core.MTA.Cluster.Queue`),
  and leaves. Stop the node then. Returns how many messages were handed
  over, and how many stay here.
  """
  @spec leave(GenServer.server()) ::
          {:ok, %{handed_over: non_neg_integer(), failed: non_neg_integer()}}
          | {:error, :no_peers}
  def leave(server \\ __MODULE__), do: GenServer.call(server, :leave, :infinity)

  @doc "Joins the cluster of the node at `peer` (`name@host:port`)."
  @spec join(GenServer.server(), String.t()) :: :ok | {:error, String.t()}
  def join(server \\ __MODULE__, peer), do: GenServer.call(server, {:join, peer}, 30_000)

  ## Server

  @impl true
  def init(opts) do
    cluster = Keyword.fetch!(opts, :cluster)
    # From the config file, which only the administrator writes.
    node = String.to_atom(cluster.node_name)

    case start_mesh(node, cluster, Keyword.fetch!(opts, :max_message_size)) do
      :ok ->
        :ok = Mesh.monitor_nodes(true)

        state = %{
          node: node,
          cluster: cluster,
          config_path: Keyword.fetch!(opts, :config_path),
          control: Keyword.fetch!(opts, :control),
          queue_manager: Keyword.fetch!(opts, :queue_manager),
          directory: Keyword.fetch!(opts, :directory),
          hostname: Keyword.fetch!(opts, :hostname),
          stack: Keyword.fetch!(opts, :stack),
          shared: SharedConfig.read(cluster.shared_config),
          since: %{},
          started_at: System.os_time(:second)
        }

        for other <- Mesh.connected(), do: offer(state, other)
        {:ok, state}

      {:error, reason} ->
        {:stop, {:cluster, reason}}
    end
  end

  defp start_mesh(node, cluster, max_message_size) do
    if Mesh.started?() do
      # Partisan outlives this process; only its node name is fixed.
      if Mesh.node() == node, do: :ok, else: {:error, :node_name_changed}
    else
      Mesh.start(
        name: node,
        ip: cluster.address,
        port: cluster.port,
        tls: [cert_file: cluster.cert_file, key_file: cluster.key_file, ca_file: cluster.ca_file],
        # Whole queue files go between nodes.
        max_message_size: max(64 * 1024 * 1024, 2 * max_message_size + 1024 * 1024)
      )
    end
  end

  @impl true
  def handle_call(:status, _from, state) do
    connected = MapSet.new(Mesh.connected())

    members =
      for member <- Mesh.members() do
        status =
          cond do
            member == state.node -> "self"
            MapSet.member?(connected, member) -> "up"
            true -> "down"
          end

        %{node: Atom.to_string(member), status: status, since: state.since[member]}
      end

    {:reply,
     %{
       node: Atom.to_string(state.node),
       members: members,
       shared_config: state.shared && Map.take(state.shared, [:version, :origin])
     }, state}
  end

  def handle_call({:push_config, _content}, _from, %{cluster: %{shared_config: nil}} = state),
    do: {:reply, {:error, ["cluster.shared_config is not set"]}, state}

  def handle_call({:push_config, content}, _from, state) do
    shared = %{
      version: if(state.shared, do: state.shared.version, else: 0) + 1,
      origin: Atom.to_string(state.node),
      content: content
    }

    with :ok <- SharedConfig.check(state.config_path, content),
         {:ok, state} <- apply_shared(state, shared) do
      for other <- Mesh.connected(), do: send_shared(other, shared)
      {:reply, {:ok, shared.version}, state}
    else
      {:error, reasons} -> {:reply, {:error, List.wrap(reasons)}, state}
    end
  end

  def handle_call(:leave, _from, state) do
    if Mesh.connected() == [] do
      {:reply, {:error, :no_peers}, state}
    else
      :ok = Control.drain(state.control)
      # Without the MTA there is no queue to hand over.
      result =
        if state.queue_manager,
          do: Queue.hand_over_all(),
          else: {:ok, %{handed_over: 0, failed: 0}}

      _ = Mesh.leave(state.node)
      {:reply, result, state}
    end
  end

  def handle_call({:join, text}, _from, state) do
    with {:ok, peer} <- Peer.parse(text, state.cluster.port),
         :ok <- Mesh.join(peer) do
      {:reply, :ok, state}
    else
      {:error, reason} when is_binary(reason) -> {:reply, {:error, text <> " " <> reason}, state}
      {:error, reason} -> {:reply, {:error, inspect(reason)}, state}
    end
  end

  @impl true
  def handle_info({:nodeup, node}, state) do
    offer(state, node)
    {:noreply, put_in(state.since[node], now())}
  end

  def handle_info({:nodedown, node}, state), do: {:noreply, put_in(state.since[node], now())}

  # Another node's shared configuration version: the older of the two
  # asks for the newer.
  def handle_info({:shared_config_offer, node, offered}, state) when is_atom(node) do
    cond do
      state.shared != nil and SharedConfig.newer?(state.shared, offered) ->
        send_shared(node, state.shared)

      SharedConfig.newer?(offered, state.shared) ->
        Mesh.send(node, __MODULE__, {:shared_config_request, state.node})

      true ->
        :ok
    end

    {:noreply, state}
  end

  def handle_info({:shared_config_request, node}, state) when is_atom(node) do
    if state.shared, do: send_shared(node, state.shared)
    {:noreply, state}
  end

  def handle_info(
        {:shared_config, %{version: version, origin: origin, content: content} = shared},
        state
      )
      when is_integer(version) and is_binary(origin) and is_binary(content) do
    if SharedConfig.newer?(shared, state.shared),
      do: {:noreply, take_shared(state, shared)},
      else: {:noreply, state}
  end

  def handle_info({:"$cluster_call", from, :summary}, state) do
    # Not here: the status of Control and the queue can take a while.
    %{hostname: hostname, directory: directory, started_at: started_at} = state
    mta = state.queue_manager != nil
    parts = for {part, true} <- state.stack, do: part

    spawn(fn ->
      Mesh.reply(from, %{
        version: @version,
        hostname: hostname,
        uptime: System.os_time(:second) - started_at,
        parts: Enum.sort(parts),
        queue: if(mta, do: QueueInfo.counts(directory))
      })
    end)

    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp offer(state, node) do
    offered = if state.shared, do: Map.take(state.shared, [:version, :origin]), else: nil
    if offered, do: Mesh.send(node, __MODULE__, {:shared_config_offer, state.node, offered})
  end

  defp send_shared(node, shared),
    do: Mesh.send(node, __MODULE__, {:shared_config, shared}, channel: :bulk)

  defp take_shared(%{cluster: %{shared_config: nil}} = state, shared) do
    rejected(shared, "cluster.shared_config is not set")
    state
  end

  defp take_shared(state, shared) do
    with :ok <- SharedConfig.check(state.config_path, shared.content),
         {:ok, state} <- apply_shared(state, shared) do
      state
    else
      {:error, reasons} ->
        rejected(shared, reasons |> List.wrap() |> Enum.join("; "))
        state
    end
  end

  defp apply_shared(state, shared) do
    case SharedConfig.write(state.cluster.shared_config, shared) do
      :ok ->
        :telemetry.execute([:sovite, :cluster, :config, :applied], %{version: shared.version}, %{
          origin: shared.origin
        })

        # Not waited for: the reload may restart this process.
        control = state.control
        spawn(fn -> Control.reload(control) end)
        {:ok, %{state | shared: shared}}

      {:error, reason} ->
        {:error, "cannot write #{state.cluster.shared_config}: #{:file.format_error(reason)}"}
    end
  end

  defp rejected(shared, reason) do
    :telemetry.execute([:sovite, :cluster, :config, :rejected], %{version: shared.version}, %{
      origin: shared.origin,
      reason: reason
    })
  end

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
end
