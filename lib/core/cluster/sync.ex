defmodule Sovite.Core.Cluster.Sync do
  @moduledoc """
  Shares anti-abuse state between the nodes of a cluster, so that limits
  hold for the cluster as a whole:

    * rate limits (`[rate_limit]`, tenant limits, and the counts of
      `[outbound]`): the events each node counted;
    * failed logins (`[auth]` and the admin API): each node counts every
      node's failures, so a client cannot spread its guesses, and is
      banned everywhere;
    * accounts suspended by `[outbound]`;
    * greylisting, when the nodes have their own SQLite databases.

  Every `cluster.sync_interval` (1 second), each node sends what changed
  to the others. What a node counted while it was cut off from the
  others is not sent again, and limits are looser by what the nodes
  have not told each other yet.
  """

  use GenServer

  alias Sovite.Abuse.{Cache, Penalty, RateLimit}
  alias Sovite.Cluster, as: Mesh

  @max_pending 10_000

  @doc false
  def opts(config, runtime) do
    [
      interval: config.cluster.sync_interval,
      rate_limit: runtime.rate_limit,
      penalties: Enum.reject([runtime.penalty, runtime.args.names.web_penalty], &is_nil/1),
      suspensions: runtime.suspensions,
      repo: runtime.repo,
      # Stores a greylist entry: the MTA's, so it comes from the runtime.
      greylist_merge: runtime.greylist_merge
    ]
  end

  @doc """
  Whether greylist entries need sharing: only between SQLite databases.
  """
  @spec greylist?(Sovite.Core.Config.t()) :: boolean()
  def greylist?(config), do: config.cluster.enabled and config.database.adapter == :sqlite

  @doc "Shares a greylist entry that this node stored."
  @spec greylist(GenServer.server(), map()) :: :ok
  def greylist(server \\ __MODULE__, entry), do: GenServer.cast(server, {:greylist, entry})

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(opts) do
    me = self()
    handler = {__MODULE__, me}

    :ok =
      :telemetry.attach(
        handler,
        [:sovite, :outbound, :suspended],
        &__MODULE__.handle_event/4,
        me
      )

    Process.send_after(self(), :tick, opts[:interval])
    state = opts |> Map.new() |> Map.put_new(:greylist_merge, nil)
    {:ok, Map.merge(state, %{handler: handler, greylist: [], suspended: []})}
  end

  @doc false
  def handle_event(_event, _measurements, %{user: user, suspend_time: time}, server),
    do: GenServer.cast(server, {:suspended, user, time})

  @impl true
  def handle_cast({:greylist, entry}, state) when length(state.greylist) < @max_pending,
    do: {:noreply, %{state | greylist: [entry | state.greylist]}}

  def handle_cast({:suspended, user, time}, state) when length(state.suspended) < @max_pending,
    do: {:noreply, %{state | suspended: [{user, time} | state.suspended]}}

  def handle_cast(_message, state), do: {:noreply, state}

  @impl true
  def handle_info(:tick, state) do
    Process.send_after(self(), :tick, state.interval)

    payload = %{
      rate: if(state.rate_limit, do: RateLimit.take_deltas(state.rate_limit), else: []),
      penalties:
        for(
          name <- state.penalties,
          deltas = take(name),
          deltas != %{},
          into: %{},
          do: {name, deltas}
        ),
      greylist: state.greylist,
      suspended: state.suspended
    }

    if payload.rate != [] or payload.penalties != %{} or payload.greylist != [] or
         payload.suspended != [] do
      for node <- Mesh.connected(), do: Mesh.send(node, __MODULE__, {:sync, payload})
    end

    {:noreply, %{state | greylist: [], suspended: []}}
  end

  def handle_info({:sync, payload}, state) when is_map(payload) do
    merge(state, payload)
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state), do: :telemetry.detach(state.handler)

  defp take(name) do
    Penalty.take_deltas(name)
  catch
    :exit, _reason -> %{}
  end

  defp merge(state, payload) do
    with rate when is_list(rate) and state.rate_limit != nil <- payload[:rate],
         do: RateLimit.merge(state.rate_limit, rate)

    for {name, failures} <- Map.get(payload, :penalties, %{}),
        name in state.penalties,
        is_map(failures),
        do: Penalty.merge(name, failures)

    for {user, time} <- List.wrap(payload[:suspended]),
        is_binary(user) and is_integer(time) and time > 0 and state.suspensions != nil,
        do: Cache.put(state.suspensions, {:suspended, user}, true, time)

    merge_greylist(state, List.wrap(payload[:greylist]))
  end

  # Only on nodes that run the MTA, which greylists.
  defp merge_greylist(%{repo: repo, greylist_merge: merge}, entries)
       when repo != nil and merge != nil do
    for %{triplet: triplet} = entry <- entries, is_binary(triplet), do: merge.(repo, entry)
    :ok
  end

  defp merge_greylist(_state, _entries), do: :ok
end
