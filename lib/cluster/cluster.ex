defmodule Sovite.Cluster do
  @moduledoc """
  A cluster of BEAM nodes over Partisan, without Distributed Erlang.

      :ok =
        Sovite.Cluster.start(
          name: :"mx1@10.0.0.1",
          ip: {10, 0, 0, 1},
          port: 4370,
          tls: [cert_file: "node.pem", key_file: "node.key", ca_file: "cluster-ca.pem"]
        )

      {:ok, peer} = Sovite.Cluster.Peer.parse("mx2@10.0.0.2:4370")
      :ok = Sovite.Cluster.join(peer)

      Sovite.Cluster.send(:"mx2@10.0.0.2", MyApp.Server, {:hello, Sovite.Cluster.node()})

  Every node is connected to every other one (Partisan's full mesh
  manager), over TLS 1.3 with mutual authentication: a node accepts
  only peers whose certificate the cluster CA (`:ca_file`) signed, and
  presents its own. There is no plaintext mode. Peers can send any
  message to any registered process, so the cluster CA must sign the
  certificates of cluster nodes and nothing else, and the peer port
  should still only be reachable from the other nodes.

  Partisan is one per VM: `start/1` configures and starts the
  `:partisan` application, and only one cluster runs at a time.

  Messages go to processes registered by name on the other node (see
  `send/4`); they are delivered as sent, and like Erlang messages, they
  can be lost when a connection drops. `call/4` waits for a reply that
  the receiving process sends with `reply/2`. `monitor_nodes/1`
  subscribes to `{:nodeup, node}` and `{:nodedown, node}` messages.
  `Sovite.Cluster.Joiner` keeps joining a list of known peers.

  Messages are on two channels: `:control`, for small messages, and
  `:bulk` (`send/4` with `channel: :bulk`), for large ones such as
  message files, so they do not hold up the others.
  """

  alias Sovite.Cluster.Peer

  @channels %{
    control: %{parallelism: 1, monotonic: false, compression: false},
    bulk: %{parallelism: 2, monotonic: false, compression: false}
  }

  @typedoc "A request's sender, for `reply/2`."
  @opaque from :: {term(), integer()}

  @doc """
  Configures and starts Partisan.

  ## Options

    * `:name` - the node's name, an atom such as `:"mx1@10.0.0.1"`.
      Required.
    * `:ip` - the address to accept peers on. Required.
    * `:port` - the port to accept peers on. Required.
    * `:tls` - `:cert_file` and `:key_file`, the node's certificate and
      key, and `:ca_file`, the cluster CA. Required.
    * `:max_message_size` - the largest message, in bytes, a peer may
      send. Defaults to 64 MB.

  Returns `{:error, :already_started}` if Partisan runs already.
  """
  @spec start(keyword()) :: :ok | {:error, term()}
  def start(opts) do
    opts = Keyword.validate!(opts, [:name, :ip, :port, :tls, max_message_size: 67_108_864])

    if started?() do
      {:error, :already_started}
    else
      configure(opts)

      case Application.ensure_all_started(:partisan) do
        {:ok, _apps} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp configure(opts) do
    tls = Keyword.fetch!(opts, :tls)

    common = [
      certfile: to_charlist(Keyword.fetch!(tls, :cert_file)),
      keyfile: to_charlist(Keyword.fetch!(tls, :key_file)),
      cacertfile: to_charlist(Keyword.fetch!(tls, :ca_file)),
      verify: :verify_peer,
      versions: [:"tlsv1.3"]
    ]

    env = [
      name: Keyword.fetch!(opts, :name),
      listen_addrs: [%{ip: Keyword.fetch!(opts, :ip), port: Keyword.fetch!(opts, :port)}],
      peer_service_manager: :partisan_pluggable_peer_service_manager,
      connect_disterl: false,
      channels: @channels,
      max_message_size: Keyword.fetch!(opts, :max_message_size),
      tls: true,
      tls_server_options: common ++ [fail_if_no_peer_cert: true],
      # Peers are reached by address, and known by the CA that signed
      # their certificate, not by a host name in it.
      tls_client_options: common ++ [server_name_indication: :disable]
    ]

    :ok = load()
    for {key, value} <- env, do: Application.put_env(:partisan, key, value, persistent: true)
    :ok
  end

  defp load do
    case Application.load(:partisan) do
      :ok -> :ok
      {:error, {:already_loaded, :partisan}} -> :ok
    end
  end

  @doc "Stops Partisan. Not from a process that an application stop is waiting for."
  @spec stop() :: :ok
  def stop do
    _ = Application.stop(:partisan)
    :ok
  end

  @doc "Whether Partisan runs."
  @spec started?() :: boolean()
  def started?, do: List.keymember?(Application.started_applications(), :partisan, 0)

  @doc "This node's name."
  @spec node() :: node()
  def node, do: :partisan.node()

  @doc "The members of the cluster, this node included, whether connected or not."
  @spec members() :: [node()]
  def members do
    {:ok, members} = :partisan_peer_service.members()
    Enum.sort(members)
  end

  @doc "The other members this node is connected to."
  @spec connected() :: [node()]
  def connected, do: Enum.sort(:partisan.nodes())

  @doc "Whether this node is connected to `node`."
  @spec connected?(node()) :: boolean()
  def connected?(node), do: :partisan.is_connected(node)

  @doc "Joins the cluster `peer` is in."
  @spec join(Peer.t()) :: :ok | {:error, term()}
  def join(%Peer{} = peer) do
    case :partisan_peer_service.join(spec(peer)) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Removes `node` from the cluster, or this node when `node` is this
  node: its peers forget it, and it forgets them.
  """
  @spec leave(node()) :: :ok | {:error, term()}
  def leave(node) do
    if node == __MODULE__.node() do
      :partisan_peer_service.leave()
    else
      case :partisan.node_spec(node) do
        {:ok, spec} -> :partisan_peer_service.leave(spec)
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp spec(%Peer{} = peer) do
    %{
      name: peer.name,
      listen_addrs: [%{ip: peer.ip, port: peer.port}],
      channels: :partisan_config.get(:channels)
    }
  end

  @doc """
  Sends `message` to the process registered as `name` on `node`.
  Returns `{:error, reason}` when it could not be handed to a
  connection, mostly because `node` is not connected.

  ## Options

    * `:channel` - `:control` (the default) or `:bulk`, for large messages.
  """
  @spec send(node(), atom(), term(), keyword()) :: :ok | {:error, term()}
  def send(node, name, message, opts \\ []) when is_atom(name) do
    channel = Keyword.get(opts, :channel, :control)

    case :partisan.forward_message(node, name, message, %{channel: channel}) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Sends `request` to the process registered as `name` on `node`, and
  waits for its reply. The process gets `{:"$cluster_call", from,
  request}`, and answers with `reply/2`.

  Returns `{:ok, reply}`, or `{:error, :timeout}`, or `{:error, reason}`
  when the request could not be sent. A reply that comes after the
  timeout stays in the caller's mailbox as `{:"$cluster_reply", tag,
  reply}`. Takes the options of `send/4`.
  """
  @spec call(node(), atom(), term(), timeout(), keyword()) :: {:ok, term()} | {:error, term()}
  def call(node, name, request, timeout \\ 5_000, opts \\ []) do
    tag = System.unique_integer([:positive])
    reply_to = :partisan.self()

    with :ok <- __MODULE__.send(node, name, {:"$cluster_call", {reply_to, tag}, request}, opts) do
      receive do
        {:"$cluster_reply", ^tag, reply} -> {:ok, reply}
      after
        timeout -> {:error, :timeout}
      end
    end
  end

  @doc "Answers a `call/4`."
  @spec reply(from(), term()) :: :ok | {:error, term()}
  def reply({reply_to, tag}, reply) do
    case :partisan.forward_message(reply_to, {:"$cluster_reply", tag, reply}) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Subscribes the calling process to `{:nodeup, node}` and `{:nodedown,
  node}` messages, or unsubscribes it.
  """
  @spec monitor_nodes(boolean()) :: :ok | {:error, term()}
  def monitor_nodes(flag) do
    case :partisan.monitor_nodes(flag) do
      :ok -> :ok
      error -> {:error, error}
    end
  end
end
