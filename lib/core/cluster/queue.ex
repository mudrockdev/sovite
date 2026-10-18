defmodule Sovite.Core.Cluster.Queue do
  @moduledoc """
  The queues of a cluster's nodes. Each node delivers the mail in its
  own spool (`queue.directory`); this process keeps copies of it on
  other nodes, hands mail to the node that should send it, and hands a
  node's queue to the others when it leaves.

  ## Copies, and taking over from a node that is down

  With `cluster.queue_replicas` (1 by default, up to 2), each message a
  node queues is copied to that many other nodes, picked by the
  message's queue ID among those connected, and copied again whenever
  it is deferred or held, so that the copy has its delivery records.
  When the message is done (delivered, bounced, expired, or deleted),
  the copies are deleted.

  When a node stays down for `cluster.handover_after` (10 minutes), the
  first of its message's copy holders that is still up queues the copy
  and delivers it, under the same queue ID, and tells the others to
  delete theirs. When the node comes back, it is told which of its
  messages were taken over, and deletes them.

  Mail is delivered at least once, as SMTP allows, but in some cases
  more than once: when a node is cut off from the others without being
  down, or comes back while taking over is under way, both deliver; and
  a copy that missed its last update is delivered again to the
  recipients it had pending then. A long `handover_after` makes this
  rare. Messages queued while a node had no peer have no copies.

  Copies are in `<queue.directory>/cluster/`, outside the queues.

  ## Handing mail to another node

  A message's recipients for a destination go to another node, as a new
  message, when:

    * their IP pool (`Sovite.Core.IPPools`) has no address on this node:
      to a node that has some;
    * with `cluster.destination_affinity`, another node owns their
      destination (MX domain or relay host): each destination is owned
      by one node, picked by its name among those connected, so all the
      cluster's mail for it leaves from that node, which keeps fewer
      connections to it busier.

  The new message, with only those recipients and with `forwarded_from`
  set, is delivered by that node, which never hands it on. The
  recipients count as delivered here, without a success notification:
  the other node sends those.

  ## Leaving

  `Sovite.Core.Cluster.leave/1` (`sovitectl cluster leave`) drains this
  node, and hands every queued message to the connected nodes
  (`hand_over_all/1`), before it takes the node out of the cluster.

  ## Telemetry

    * `[:sovite, :cluster, :queue, :taken_over]` - `%{messages}`,
      `%{node}`, when this node queues the copies of a node that is down.
    * `[:sovite, :cluster, :queue, :handed_over]` - `%{messages, failed}`,
      `%{}`, when this node leaves.
  """

  use GenServer

  require Logger

  alias Sovite.Cluster, as: Mesh
  alias Sovite.Core.Cluster.Placement
  alias Sovite.Core.QueueManager
  alias Sovite.Queue.{Envelope, ID, Spool}

  @events [
    [:sovite, :queue, :message, :enqueued],
    [:sovite, :queue, :message, :deferred],
    [:sovite, :queue, :message, :held],
    [:sovite, :queue, :message, :released],
    [:sovite, :queue, :message, :requeued],
    [:sovite, :queue, :message, :removed],
    [:sovite, :queue, :message, :corrupt]
  ]

  @flush_interval 1_000
  @magic "SOVITE-REPLICA 1 "

  @doc false
  def opts(config, runtime) do
    [
      node: config.cluster.node_name,
      directory: config.queue.directory,
      queue_manager: runtime.queue_manager,
      replicas: config.cluster.queue_replicas,
      handover_after: config.cluster.handover_after
    ]
  end

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: Placement.queue())

  @doc """
  Hands every queued message to the connected nodes, for a node that
  leaves (see `Sovite.Core.Cluster.leave/1`, which drains it first).
  Returns how many messages were handed over, and how many could not be
  (they stay here).
  """
  @spec hand_over_all(GenServer.server()) ::
          {:ok, %{handed_over: non_neg_integer(), failed: non_neg_integer()}}
          | {:error, :no_peers}
  def hand_over_all(server \\ Placement.queue()),
    do: GenServer.call(server, :hand_over_all, :infinity)

  @doc "The copies this node holds, by node, and the messages it took over and has to report."
  @spec status(GenServer.server()) :: map()
  def status(server \\ Placement.queue()), do: GenServer.call(server, :status)

  ## Server

  @impl true
  def init(opts) do
    me = self()
    handler = {__MODULE__, me}
    :ok = :telemetry.attach_many(handler, @events, &__MODULE__.handle_event/4, me)
    :ok = Mesh.monitor_nodes(true)

    state = %{
      node: Keyword.fetch!(opts, :node),
      directory: Keyword.fetch!(opts, :directory),
      root: Path.join(Keyword.fetch!(opts, :directory), "cluster"),
      queue_manager: Keyword.fetch!(opts, :queue_manager),
      replicas: Keyword.fetch!(opts, :replicas),
      handover_after: Keyword.fetch!(opts, :handover_after),
      handler: handler,
      drops: [],
      timers: %{},
      held: %{},
      taken: %{}
    }

    state = load(state)
    # Nodes already down when this node started.
    state = Enum.reduce(Map.keys(state.held), state, &watch(&2, &1))
    Process.send_after(self(), :flush, @flush_interval)
    {:ok, state}
  end

  @doc false
  def handle_event([:sovite, :queue, :message, event], _measurements, %{queue_id: id}, server) do
    case event do
      :removed -> GenServer.cast(server, {:drop, id})
      :corrupt -> GenServer.cast(server, {:drop, id})
      :held -> GenServer.cast(server, {:replicate, id, :hold})
      :deferred -> GenServer.cast(server, {:replicate, id, :deferred})
      :released -> GenServer.cast(server, {:replicate, id, :deferred})
      _ -> GenServer.cast(server, {:replicate, id, :incoming})
    end
  end

  @impl true
  def terminate(_reason, state), do: :telemetry.detach(state.handler)

  @impl true
  def handle_cast({:replicate, _id, _queue}, %{replicas: 0} = state), do: {:noreply, state}

  def handle_cast({:replicate, id, queue}, state) do
    with {:ok, queue, data} <- read_queued(state, id, queue),
         [_ | _] = holders <-
           id |> Placement.rank(Placement.connected()) |> Enum.take(state.replicas) do
      for holder <- holders,
          do: send_to(holder, {:replica, state.node, id, queue, holders, data}, channel: :bulk)
    end

    {:noreply, state}
  end

  def handle_cast({:drop, id}, state), do: {:noreply, %{state | drops: [id | state.drops]}}

  @impl true
  def handle_call(:status, _from, state) do
    {:reply,
     %{
       copies: Map.new(state.held, fn {node, ids} -> {node, MapSet.size(ids)} end),
       taken_over: Map.new(state.taken, fn {node, ids} -> {node, MapSet.size(ids)} end)
     }, state}
  end

  def handle_call(:hand_over_all, _from, state) do
    case Placement.connected() do
      [] ->
        {:reply, {:error, :no_peers}, state}

      nodes ->
        result = hand_over_queue(state, nodes)
        :telemetry.execute([:sovite, :cluster, :queue, :handed_over], result, %{})
        {:reply, {:ok, %{handed_over: result.messages, failed: result.failed}}, state}
    end
  end

  @impl true
  def handle_info(:flush, state) do
    Process.send_after(self(), :flush, @flush_interval)

    if state.drops != [] do
      for node <- Placement.connected(),
          do: send_to(node, {:replica_drop, state.node, state.drops})
    end

    {:noreply, %{state | drops: []}}
  end

  def handle_info({:nodeup, node}, state) do
    node = Atom.to_string(node)
    {timer, timers} = Map.pop(state.timers, node)
    if timer, do: Process.cancel_timer(timer)
    state = %{state | timers: timers}

    # Which of its messages are gone, and which this node took over.
    ids = Map.get(state.held, node, MapSet.new())
    if MapSet.size(ids) > 0, do: send_to(node, {:replica_check, state.node, MapSet.to_list(ids)})

    taken = Map.get(state.taken, node, MapSet.new())

    if MapSet.size(taken) > 0,
      do: send_to(node, {:taken_over, node, MapSet.to_list(taken), state.node})

    {:noreply, state}
  end

  def handle_info({:nodedown, node}, state), do: {:noreply, watch(state, Atom.to_string(node))}

  def handle_info({:handover, node}, state) do
    state = %{state | timers: Map.delete(state.timers, node)}

    if node in Placement.connected(),
      do: {:noreply, state},
      else: {:noreply, take_over(state, node)}
  end

  # A copy of another node's message.
  def handle_info({:replica, origin, id, queue, holders, data}, state)
      when is_binary(origin) and is_binary(data) and queue in [:incoming, :deferred, :hold] do
    if ID.valid?(id) and Enum.all?(holders, &is_binary/1) do
      {:noreply, store_replica(state, origin, id, queue, holders, data)}
    else
      {:noreply, state}
    end
  end

  def handle_info({:replica_drop, origin, ids}, state) when is_binary(origin) and is_list(ids),
    do: {:noreply, drop_replicas(state, origin, ids)}

  # A holder asks which of its copies of this node's messages are gone.
  def handle_info({:replica_check, holder, ids}, state)
      when is_binary(holder) and is_list(ids) do
    gone = Enum.reject(ids, &queued?(state, &1))
    if gone != [], do: send_to(holder, {:replica_drop, state.node, gone})
    {:noreply, state}
  end

  # Messages of `origin` that `by` took over.
  def handle_info({:taken_over, origin, ids, by}, state)
      when is_binary(origin) and is_list(ids) and is_binary(by) do
    if origin == state.node do
      # This node was down: the others delivered these.
      for id <- ids, is_binary(id), do: QueueManager.delete(state.queue_manager, id)
      send_to(by, {:taken_over_ack, state.node, ids})
      {:noreply, state}
    else
      {:noreply, drop_replicas(state, origin, ids)}
    end
  end

  def handle_info({:taken_over_ack, origin, ids}, state)
      when is_binary(origin) and is_list(ids) do
    taken = state.taken |> Map.get(origin, MapSet.new()) |> MapSet.difference(MapSet.new(ids))
    state = put_in(state.taken[origin], taken)
    write_taken(state, origin)
    {:noreply, state}
  end

  def handle_info({:"$cluster_call", from, {:adopt, id, queue, data}}, state)
      when is_binary(data) do
    Mesh.reply(from, adopt(state, id, queue, data))
    {:noreply, state}
  end

  def handle_info({:"$cluster_call", from, {:forwarded, envelope, message}}, state)
      when is_map(envelope) and is_binary(message) do
    Mesh.reply(from, enqueue(state, envelope, message))
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  ## Copies

  defp read_queued(state, id, queue) do
    Enum.find_value(
      [queue, :active, :incoming, :deferred, :hold],
      :error,
      &read_queued(File.read(Spool.path(state.directory, &1, id)), &1)
    )
  end

  # Copies of active messages are queued again when taken over.
  defp read_queued({:ok, data}, :active), do: {:ok, :incoming, data}
  defp read_queued({:ok, data}, queue), do: {:ok, queue, data}
  defp read_queued({:error, _reason}, _queue), do: nil

  defp queued?(state, id) do
    ID.valid?(id) and
      Enum.any?(Spool.queues() -- [:corrupt], &File.exists?(Spool.path(state.directory, &1, id)))
  end

  defp store_replica(state, origin, id, queue, holders, data) do
    dir = origin_dir(state, origin)
    path = Path.join(dir, id)
    tmp = path <> ".tmp"
    header = [@magic, Atom.to_string(queue), " ", Enum.join(holders, ","), "\n"]

    with :ok <- File.mkdir_p(dir),
         :ok <- File.write(tmp, [header, data]),
         :ok <- File.rename(tmp, path) do
      update_in(
        state.held,
        &Map.update(&1, origin, MapSet.new([id]), fn ids -> MapSet.put(ids, id) end)
      )
    else
      {:error, reason} ->
        Logger.error(
          "cannot store a copy of a message of #{origin}: #{:file.format_error(reason)}",
          queue_id: id
        )

        state
    end
  end

  defp drop_replicas(state, origin, ids) do
    case Map.fetch(state.held, origin) do
      {:ok, held} ->
        dir = origin_dir(state, origin)
        dropped = for id <- ids, is_binary(id), MapSet.member?(held, id), do: id
        for id <- dropped, do: File.rm(Path.join(dir, id))
        put_in(state.held[origin], MapSet.difference(held, MapSet.new(dropped)))

      :error ->
        state
    end
  end

  defp read_replica(state, origin, id) do
    with {:ok, text} <- File.read(Path.join(origin_dir(state, origin), id)),
         [header, data] <- :binary.split(text, "\n"),
         @magic <> rest <- header,
         [queue, holders] <- String.split(rest, " ", parts: 2),
         queue when queue in ["incoming", "deferred", "hold"] <- queue do
      {:ok, String.to_existing_atom(queue), String.split(holders, ","), data}
    else
      _ -> :error
    end
  end

  defp watch(state, node) do
    if Map.has_key?(state.held, node) and not Map.has_key?(state.timers, node) do
      timer = Process.send_after(self(), {:handover, node}, state.handover_after)
      put_in(state.timers[node], timer)
    else
      state
    end
  end

  # Queues the copies of `origin` that this node is the first holder of
  # still up.
  defp take_over(state, origin) do
    up = MapSet.new([state.node | Placement.connected()])
    ids = state.held |> Map.get(origin, MapSet.new()) |> Enum.sort()

    taken =
      for id <- ids,
          {:ok, queue, holders, data} <- [read_replica(state, origin, id)],
          [first | _] = Enum.filter(holders, &MapSet.member?(up, &1)),
          first == state.node,
          adopt(state, id, queue, data) == :ok,
          do: id

    if taken != [] do
      :telemetry.execute([:sovite, :cluster, :queue, :taken_over], %{messages: length(taken)}, %{
        node: origin
      })

      for node <- Placement.connected(),
          do: send_to(node, {:taken_over, origin, taken, state.node})
    end

    state = drop_replicas(state, origin, taken)

    state =
      update_in(
        state.taken,
        &Map.update(&1, origin, MapSet.new(taken), fn t -> MapSet.union(t, MapSet.new(taken)) end)
      )

    write_taken(state, origin)
    state
  end

  ## Queuing messages from other nodes

  # A whole queue file, from a copy or a node that leaves. Deferred
  # messages are retried at once: their node is gone.
  defp adopt(state, id, queue, data) do
    queue = if queue == :hold, do: :hold, else: :incoming

    cond do
      not ID.valid?(id) ->
        {:error, "invalid queue ID"}

      queued?(state, id) ->
        :ok

      true ->
        write_adopted(state, id, queue, data)
    end
  end

  defp write_adopted(state, id, queue, data) do
    # tmp/ is emptied at startup.
    tmp = Path.join([state.directory, "tmp", id <> ".cluster"])

    # Checked before it goes in a queue.
    with :ok <- File.write(tmp, data),
         {:ok, %{envelope: %{queue_id: ^id}}} <- Spool.load(tmp),
         :ok <- File.chmod(tmp, 0o600),
         :ok <- File.rename(tmp, Spool.path(state.directory, queue, id)) do
      if queue == :incoming, do: QueueManager.notify(state.queue_manager, id)
      GenServer.cast(self(), {:replicate, id, queue})
      :ok
    else
      error ->
        _ = File.rm(tmp)
        {:error, "invalid queue file: #{inspect(error)}"}
    end
  end

  # A message another node handed over for delivery.
  defp enqueue(state, map, message) do
    with {:ok, %{forwarded_from: from} = envelope} when is_binary(from) <-
           Envelope.from_map(map),
         id = ID.generate(),
         {:ok, writer} <- Spool.open(state.directory, %{envelope | queue_id: id}),
         {:ok, writer} <- Spool.write(writer, message),
         {:ok, _path, _size} <- Spool.commit(writer) do
      QueueManager.notify(state.queue_manager, id)
      {:ok, id}
    else
      {:error, reason} -> {:error, inspect(reason)}
      _ -> {:error, "invalid message"}
    end
  end

  defp hand_over_queue(state, nodes) do
    ids =
      for queue <- [:active, :incoming, :deferred, :hold],
          {:ok, ids} <- [Spool.list(state.directory, queue)],
          id <- ids,
          do: {queue, id}

    ids
    |> Enum.with_index()
    |> Enum.reduce(%{messages: 0, failed: 0}, fn {{queue, id}, index}, acc ->
      node = String.to_existing_atom(Enum.at(nodes, rem(index, length(nodes))))
      path = Spool.path(state.directory, queue, id)

      with {:ok, data} <- File.read(path),
           {:ok, :ok} <-
             Mesh.call(node, Placement.queue(), {:adopt, id, queue, data}, 120_000,
               channel: :bulk
             ),
           :ok <- Spool.remove(state.directory, queue, id, :handed_over) do
        %{acc | messages: acc.messages + 1}
      else
        _ -> %{acc | failed: acc.failed + 1}
      end
    end)
  end

  ## Files

  defp origin_dir(state, origin),
    do: Path.join([state.root, "copies", Base.url_encode64(origin, padding: false)])

  defp taken_file(state, origin),
    do: Path.join([state.root, "taken", Base.url_encode64(origin, padding: false)])

  defp write_taken(state, origin) do
    path = taken_file(state, origin)

    case Map.get(state.taken, origin, MapSet.new()) |> Enum.sort() do
      [] ->
        _ = File.rm(path)

      ids ->
        File.mkdir_p!(Path.dirname(path))
        File.write!(path <> ".tmp", Enum.map(ids, &[&1, "\n"]))
        File.rename!(path <> ".tmp", path)
    end

    :ok
  rescue
    error ->
      Logger.error("cannot write #{taken_file(state, origin)}: #{Exception.message(error)}")
  end

  # The copies and takeovers from before a restart.
  defp load(state) do
    held =
      for {origin, dir} <- origins(state, "copies"),
          {:ok, names} <- [File.ls(dir)],
          into: %{} do
        {origin, names |> Enum.filter(&ID.valid?/1) |> MapSet.new()}
      end

    taken =
      for {origin, path} <- origins(state, "taken"),
          {:ok, text} <- [File.read(path)],
          into: %{} do
        {origin,
         text |> String.split("\n", trim: true) |> Enum.filter(&ID.valid?/1) |> MapSet.new()}
      end

    %{state | held: held, taken: taken}
  end

  defp origins(state, kind) do
    dir = Path.join(state.root, kind)

    case File.ls(dir) do
      {:ok, names} ->
        for name <- names,
            {:ok, origin} <- [Base.url_decode64(name, padding: false)],
            do: {origin, Path.join(dir, name)}

      {:error, _} ->
        []
    end
  end

  defp send_to(node, message, opts \\ []) do
    case Placement.existing_node(node) do
      {:ok, node} -> Mesh.send(node, Placement.queue(), message, opts)
      error -> error
    end
  end
end
