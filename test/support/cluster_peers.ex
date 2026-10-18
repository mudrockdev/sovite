defmodule Sovite.Test.ClusterPeers do
  @moduledoc """
  Other VMs for cluster tests. Each runs this project's code and talks
  to the test VM only through `:peer`'s standard I/O, so Partisan (one
  per VM) never runs in the test VM itself.

      tls = ClusterPeers.tls(dir)
      peer = ClusterPeers.start!()
      :ok = ClusterPeers.call(peer, Sovite.Cluster, :start, [[name: ..., tls: tls.("a")]])
  """

  alias Sovite.Queue.Spool
  alias Sovite.Test.Certs

  @doc """
  Writes a cluster CA to `dir`, and returns a function that issues and
  writes a certificate for a node, returning `Sovite.Cluster.start/1`'s
  `:tls` options.
  """
  def tls(dir, ca \\ Certs.ca()) do
    ca_file = Path.join(dir, "ca-#{System.unique_integer([:positive])}.crt")
    File.write!(ca_file, Certs.pem_chain(ca.chain))

    fn name ->
      {cert_file, key_file} = Certs.write!(dir, name, Certs.issue(ca, names: [name]))
      [cert_file: cert_file, key_file: key_file, ca_file: ca_file]
    end
  end

  @doc "Starts a VM. It stops with the calling process."
  def start! do
    paths = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])
    args = paths ++ [~c"-kernel", ~c"logger_level", ~c"error"]
    {:ok, peer, _node} = :peer.start_link(%{connection: :standard_io, args: args})
    {:ok, _} = :peer.call(peer, :application, :ensure_all_started, [:elixir])
    # Peers that stop or refuse each other are what the tests are about.
    :ok = :peer.call(peer, :application, :load, [:partisan])
    :ok = :peer.call(peer, :logger, :set_application_level, [:partisan, :none])
    peer
  end

  @doc "Calls a function in the VM."
  def call(peer, module, function, args, timeout \\ 30_000),
    do: :peer.call(peer, module, function, args, timeout)

  @doc "Writes a message into a spool, in a VM: queued, but its queue manager is not told."
  def write_message(queue, envelope) do
    {:ok, writer} = Spool.open(queue, envelope)
    {:ok, writer} = Spool.write(writer, "Subject: hi\r\n\r\nHello\r\n")
    {:ok, _path, _size} = Spool.commit(writer)
    :ok
  end

  @doc "A free TCP port on 127.0.0.1."
  def free_port do
    {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    port
  end

  @doc "Waits until `fun` returns a truthy value, for up to `timeout` milliseconds."
  def eventually(fun, timeout \\ 10_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    wait(fun, deadline)
  end

  defp wait(fun, deadline) do
    case fun.() do
      result when result not in [nil, false] ->
        result

      _ ->
        if System.monotonic_time(:millisecond) > deadline do
          raise ExUnit.AssertionError, message: "condition not met in time"
        end

        Process.sleep(50)
        wait(fun, deadline)
    end
  end
end

defmodule Sovite.Test.ClusterEcho do
  @moduledoc """
  A process for cluster tests, started in a peer VM: it answers
  `Sovite.Cluster.call/4` with `{:echo, request}`, and keeps what it
  was sent and the nodes that came and went.
  """

  use GenServer

  def start(name), do: GenServer.start(__MODULE__, nil, name: name)

  def received(name), do: GenServer.call(name, :received)

  @impl true
  def init(nil) do
    :ok = Sovite.Cluster.monitor_nodes(true)
    {:ok, []}
  end

  @impl true
  def handle_call(:received, _from, received), do: {:reply, Enum.reverse(received), received}

  @impl true
  def handle_info({:"$cluster_call", from, request}, received) do
    Sovite.Cluster.reply(from, {:echo, request})
    {:noreply, received}
  end

  def handle_info(message, received), do: {:noreply, [message | received]}
end
