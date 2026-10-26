defmodule Sovite.Core.MTA.Cluster.Placement do
  @moduledoc """
  Which node of a cluster delivers what (see "Handing mail to another
  node" in `Sovite.Core.MTA.Cluster.Queue`): `place/3` decides for the
  routes of a message, and `hand_over/2` hands a delivery job to
  another node, from a delivery worker.
  """

  alias Sovite.Cluster, as: Mesh
  alias Sovite.Core.MTA.IPPools
  alias Sovite.Queue.{Envelope, ID, Spool}

  # The registered name of Sovite.Core.MTA.Cluster.Queue, which queues the
  # messages other nodes hand over: this module needs it, but must not
  # depend on that module, which depends on the queue manager.
  @queue :sovite_cluster_queue

  @doc false
  def queue, do: @queue

  @doc false
  # The options QueueManager places deliveries with, or nil.
  def placement_opts(%{cluster: %{enabled: true}} = config) do
    %{
      node: config.cluster.node_name,
      affinity: config.cluster.destination_affinity,
      ip_pools: if(config.ip_pool != [], do: IPPools)
    }
  end

  def placement_opts(_config), do: nil

  @doc """
  Where a route of a message goes: as it is, or, for an SMTP
  destination another node should send to, to that node (a `:cluster`
  destination), or deferred when no node that could send it is up.
  """
  @spec place(term(), map() | nil, Envelope.t()) :: term()
  def place({:deliver, %{transport: :smtp} = destination} = route, %{} = opts, envelope)
      when envelope.forwarded_from == nil do
    case owner(destination, opts) do
      :local ->
        route

      {:node, node} ->
        {:deliver, %{transport: :cluster, node: node, destination: destination}}

      {:defer, text} ->
        {:defer, "4.4.0", text}
    end
  end

  def place(route, _opts, _envelope), do: route

  defp owner(%{pool: pool} = destination, %{ip_pools: pools} = opts) when pools != nil do
    case IPPools.placement(pools, pool) do
      :local ->
        affinity(destination, opts)

      {:remote, nodes} ->
        case rank(key(destination), Enum.filter(nodes, &(&1 in connected()))) do
          [node | _] -> {:node, node}
          [] -> {:defer, "no cluster node with an address of IP pool #{pool} is up"}
        end
    end
  end

  defp owner(destination, opts), do: affinity(destination, opts)

  defp affinity(destination, %{affinity: true, node: me}) do
    case rank(key(destination), [me | connected()]) do
      [^me | _] -> :local
      [node | _] -> {:node, node}
    end
  end

  defp affinity(_destination, _opts), do: :local

  defp key(%{nexthop: {:mx, domain}}), do: domain
  defp key(%{nexthop: {:host, %{host: host, port: port}}}), do: "#{host}:#{port}"
  defp key(%{nexthop: {:literal, ip}}), do: ip |> :inet.ntoa() |> to_string()

  @doc false
  def connected do
    if Mesh.started?(), do: Enum.map(Mesh.connected(), &Atom.to_string/1), else: []
  end

  # Rendezvous hashing: every node ranks the candidates for a key the
  # same way, and a key moves only when its first node comes or goes.
  @doc false
  def rank(key, nodes),
    do: nodes |> Enum.uniq() |> Enum.sort_by(&:crypto.hash(:sha256, [key, 0, &1]), :desc)

  @doc false
  # Delivers a :cluster job: a new message with its recipients, queued
  # on the destination's node. Runs in a delivery worker.
  def hand_over(job, node) do
    with {:ok, envelope, _size} <- Spool.read(job.path),
         {:ok, node} <- existing_node(node) do
      envelope = %{
        envelope
        | queue_id: ID.generate(),
          sender: job.sender,
          recipients: job.recipients,
          dsn: Map.take(envelope.dsn, job.recipients),
          rrvs: Map.take(envelope.rrvs, job.recipients),
          expanded: [],
          forwarded_from: Mesh.node() |> Atom.to_string()
      }

      message =
        job.path
        |> Spool.stream_message(job.message_offset, job.message_size, job.prefix || "")
        |> Enum.into([])
        |> IO.iodata_to_binary()

      request = {:forwarded, Envelope.to_map(envelope), message}

      case Mesh.call(node, @queue, request, 120_000, channel: :bulk) do
        {:ok, {:ok, id}} ->
          {:ok, "handed to cluster node #{node} as #{id}"}

        {:ok, {:error, reason}} ->
          {:error, "cluster node #{node} cannot queue the message: #{reason}"}

        {:error, reason} ->
          {:error, "cannot hand the message to cluster node #{node}: #{inspect(reason)}"}
      end
    else
      {:error, reason} -> {:error, "cannot hand the message over: #{inspect(reason)}"}
    end
  end

  @doc false
  def existing_node(name) do
    {:ok, String.to_existing_atom(name)}
  rescue
    ArgumentError -> {:error, :unknown_node}
  end
end
