defmodule Sovite.Core.Stack do
  @moduledoc """
  The parts of the stack, and where they run: the MTA, the filter, and
  the mailbox part (`[stack]`, see `Sovite.Core.Config.part?/2`).

  The parts never use each other's modules. They meet through the
  interfaces under `Sovite.Core.Stack`, such as
  `Sovite.Core.Stack.Mailbox`, which do the work here when this node
  runs the part, or ask a node of the cluster that does (each node tells
  the others which parts it runs, see `Sovite.Core.Cluster.parts/0`).
  """

  alias Sovite.Core.Cluster.Parts
  alias Sovite.Core.Config

  @typedoc "Which parts this node runs, and whether it is in a cluster."
  @type t :: %{local: %{Config.part() => boolean()}, cluster: boolean()}

  @doc "The stack as `config` sets it up."
  @spec new(Config.t()) :: t()
  def new(config), do: %{local: config.stack, cluster: config.cluster.enabled}

  @doc """
  Where `part` runs for `key` (an address or a domain, so the same key
  goes to the same node): on this node, on another node of the cluster,
  or nowhere.
  """
  @spec where(t(), Config.part(), String.t()) :: :local | {:node, node()} | :none
  def where(%{local: local}, part, _key) when :erlang.map_get(part, local) == true, do: :local
  def where(%{cluster: false}, _part, _key), do: :none

  def where(_stack, part, key) do
    case nodes(part) do
      [] ->
        :none

      nodes ->
        {:node,
         nodes
         |> Enum.sort_by(&:crypto.hash(:sha256, [key, 0, Atom.to_string(&1)]), :desc)
         |> hd()}
    end
  end

  @doc "The other nodes of the cluster that run `part` and are connected now."
  @spec nodes(Config.part()) :: [node()]
  def nodes(part) do
    for {node, parts} <- Parts.connected(), part in parts, do: node
  end
end
