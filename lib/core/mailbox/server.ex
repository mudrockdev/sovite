defmodule Sovite.Core.Mailbox.Server do
  @moduledoc """
  Takes mail for the store from other nodes of a cluster: the MTA on a
  node without the mailbox part sends it here (see
  `Sovite.Core.Stack.Mailbox`). Registered as `:sovite_mailbox`, which
  the other nodes call over the cluster's mutual TLS.

  Each request is stored in its own process, so one slow disk write does
  not hold up the others.
  """

  use GenServer

  alias Sovite.Cluster, as: Mesh
  alias Sovite.Core.Mailbox.Store

  @name :sovite_mailbox

  @doc "The name other nodes call."
  @spec name() :: atom()
  def name, do: @name

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: @name)

  @impl true
  def init(opts), do: {:ok, %{store: Keyword.fetch!(opts, :store)}}

  @impl true
  def handle_info({:"$cluster_call", from, {:deliver, sender, recipients, message}}, state)
      when is_binary(sender) and is_list(recipients) and recipients != [] and is_binary(message) do
    if Enum.all?(recipients, &is_binary/1) do
      store = state.store

      spawn(fn ->
        Mesh.reply(from, {:ok, Store.deliver(store, sender, recipients, [message])})
      end)
    else
      Mesh.reply(from, {:error, :invalid_request})
    end

    {:noreply, state}
  end

  def handle_info({:"$cluster_call", from, _request}, state) do
    Mesh.reply(from, {:error, :invalid_request})
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}
end
