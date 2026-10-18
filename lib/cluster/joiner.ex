defmodule Sovite.Cluster.Joiner do
  @moduledoc """
  Keeps joining known peers (`Sovite.Cluster.Peer`), and reports nodes
  coming and going. Start it once `Sovite.Cluster.start/1` returned.

      children = [
        {Sovite.Cluster.Joiner, peers: [peer1, peer2], interval: 10_000}
      ]

  Every `:interval` milliseconds, it joins the peers this node is not
  connected to. A cluster forms when every node knows at least one
  other; nodes learn the rest from each other. Peers that are down are
  tried again on the next round.

  ## Options

    * `:peers` - `Sovite.Cluster.Peer` structs, or `name@host:port`
      strings, parsed (and their hosts resolved) on each round. Defaults
      to none.
    * `:port` - the port of peers given as strings without one.
      Defaults to 4370.
    * `:interval` - milliseconds between rounds. Defaults to 10 seconds.
    * `:name` - a registered name, or `nil` for none (the default).

  ## Telemetry

    * `[:sovite, :cluster, :node, :up]` - `%{}`, `%{node}`, when a
      connection to a node opens.
    * `[:sovite, :cluster, :node, :down]` - `%{}`, `%{node}`, when the
      last connection to a node closes.
    * `[:sovite, :cluster, :join, :error]` - `%{}`, `%{peer, reason}`,
      when joining a peer fails at once, or a peer string does not parse.
  """

  use GenServer

  alias Sovite.Cluster
  alias Sovite.Cluster.Peer

  @doc false
  def child_spec(opts),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}

  @doc "Starts the joiner."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    opts = Keyword.validate!(opts, [:name, peers: [], port: 4370, interval: 10_000])
    GenServer.start_link(__MODULE__, opts, name: opts[:name])
  end

  @doc "Replaces the peers to join."
  @spec set_peers(GenServer.server(), [Peer.t() | String.t()]) :: :ok
  def set_peers(server, peers), do: GenServer.call(server, {:set_peers, peers})

  @impl true
  def init(opts) do
    :ok = Cluster.monitor_nodes(true)

    state = %{
      peers: opts[:peers],
      port: opts[:port] || 4370,
      interval: opts[:interval],
      timer: nil
    }

    {:ok, state, {:continue, :join}}
  end

  @impl true
  def handle_call({:set_peers, peers}, _from, state) do
    {:reply, :ok, %{state | peers: peers}, {:continue, :join}}
  end

  @impl true
  def handle_continue(:join, state), do: {:noreply, join(state)}

  @impl true
  def handle_info(:join, state), do: {:noreply, join(state)}

  def handle_info({:nodeup, node}, state) do
    :telemetry.execute([:sovite, :cluster, :node, :up], %{}, %{node: node})
    {:noreply, state}
  end

  def handle_info({:nodedown, node}, state) do
    :telemetry.execute([:sovite, :cluster, :node, :down], %{}, %{node: node})
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp join(state) do
    if state.timer, do: Process.cancel_timer(state.timer)
    connected = MapSet.new([Cluster.node() | Cluster.connected()])

    for peer <- state.peers do
      case resolve(peer, state.port) do
        {:ok, peer} -> join(peer, connected)
        {:error, reason} -> join_error(peer, reason)
      end
    end

    %{state | timer: Process.send_after(self(), :join, state.interval)}
  end

  defp join(peer, connected) do
    if not MapSet.member?(connected, peer.name) do
      with {:error, reason} <- Cluster.join(peer), do: join_error(Peer.format(peer), reason)
    end
  end

  defp resolve(%Peer{} = peer, _port), do: {:ok, peer}
  defp resolve(text, port), do: Peer.parse(text, port)

  defp join_error(peer, reason),
    do: :telemetry.execute([:sovite, :cluster, :join, :error], %{}, %{peer: peer, reason: reason})
end
