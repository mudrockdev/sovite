defmodule Sovite.Core.Cluster.Parts do
  @moduledoc false
  # The parts of the stack the other nodes run, as they told this one:
  # written by Sovite.Core.Cluster when a node says hello, read by
  # Sovite.Core.Stack. Apart from both, so the stack does not depend on
  # the cluster process. Changes are rare (a node joins), so it is a
  # persistent term.

  alias Sovite.Cluster, as: Mesh

  @key {__MODULE__, :peers}

  @spec put(node(), [Sovite.Core.Config.part()]) :: :ok
  def put(node, parts), do: :persistent_term.put(@key, Map.put(all(), node, parts))

  # Only the nodes connected now.
  @spec connected() :: %{node() => [Sovite.Core.Config.part()]}
  def connected do
    if Mesh.started?(), do: Map.take(all(), Mesh.connected()), else: %{}
  end

  defp all, do: :persistent_term.get(@key, %{})
end
