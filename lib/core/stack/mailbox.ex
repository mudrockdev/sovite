defmodule Sovite.Core.Stack.Mailbox do
  @moduledoc """
  The mailbox part's interface, for the other parts of the stack.

    * The user directory (`Sovite.Core.Mailbox.Directory`): users, their
      passwords and sender addresses, and the mailboxes. It is in the
      shared database, so it is read on every node. As a
      `Sovite.SASL.Backend` (`{Sovite.Core.Stack.Mailbox, repo: repo}`)
      it is the `database` backend of `[auth]`, and as a
      `Sovite.Core.MTA.Lookup` table routing finds hosted mailboxes in it.
    * Delivery to the store (`deliver/4`): on this node when it runs the
      mailbox part, or on a node of the cluster that does. Without one,
      the mail is deferred: the MTA then delivers hosted mail with LMTP
      instead (Dovecot, `routing.mailbox_transport`).

  Quotas come with the mailbox part's own store (3.0).
  """

  @behaviour Sovite.SASL.Backend
  @behaviour Sovite.Core.MTA.Lookup

  alias Sovite.Cluster, as: Mesh
  alias Sovite.Core.{Config, Stack}
  alias Sovite.Core.Mailbox.{Directory, Server, Store}

  @typedoc "Where delivery goes: the stack, and the local store's options."
  @type opts :: %{stack: Stack.t(), store: Store.opts()}

  # Large messages take a while over the cluster.
  @remote_timeout 120_000

  @doc "The options for `deliver/4` from the config."
  @spec opts(Config.t()) :: opts()
  def opts(config), do: %{stack: Stack.new(config), store: Store.opts(config)}

  ## The directory

  @impl Sovite.SASL.Backend
  defdelegate verify_password(username, password, opts), to: Directory

  @impl Sovite.SASL.Backend
  defdelegate scram_credentials(username, opts), to: Directory

  @doc "The sender addresses a user may use, besides their login."
  @spec senders(Sovite.Core.Repo.t(), String.t()) :: [String.t()]
  defdelegate senders(repo, username), to: Directory

  @doc "When the mailbox at exactly `address` was added (for `RRVS`), or `:error`."
  @spec added_at(Sovite.Core.Repo.t(), String.t()) :: {:ok, DateTime.t()} | :error
  defdelegate added_at(repo, address), to: Directory

  @impl Sovite.Core.MTA.Lookup
  def lookup(%{repo: repo}, address), do: Directory.mailbox(repo, address)

  ## Delivery

  @doc """
  Stores `message` (an enumerable of iodata, the message as queued) in
  the mailboxes of `recipients`. Returns each recipient's enhanced status
  code and a text.
  """
  @spec deliver(opts(), String.t(), [String.t(), ...], Enumerable.t()) :: [Store.result()]
  def deliver(opts, sender, [first | _] = recipients, message) do
    case Stack.where(opts.stack, :mailbox, first) do
      :local -> Store.deliver(opts.store, sender, recipients, message)
      {:node, node} -> remote(node, sender, recipients, message)
      :none -> deferred(recipients, "no node runs the mailbox part ([stack] mailbox)")
    end
  end

  defp remote(node, sender, recipients, message) do
    message = message |> Enum.into([]) |> IO.iodata_to_binary()
    request = {:deliver, sender, recipients, message}

    case Mesh.call(node, Server.name(), request, @remote_timeout, channel: :bulk) do
      {:ok, {:ok, results}} ->
        checked(results, recipients, node)

      {:ok, {:error, reason}} ->
        deferred(recipients, "mailbox node #{node} refused: #{inspect(reason)}")

      {:error, reason} ->
        deferred(recipients, "cannot reach mailbox node #{node}: #{inspect(reason)}")
    end
  end

  # One result per recipient, with a status code: anything else from the
  # other node is not believed.
  defp checked(results, recipients, node) do
    valid =
      is_list(results) and length(results) == length(recipients) and
        Enum.all?(Enum.zip(results, recipients), fn
          {{rcpt, <<class, ?., _::binary>>, text}, rcpt} when class in ~c"245" -> is_binary(text)
          _ -> false
        end)

    if valid, do: results, else: deferred(recipients, "mailbox node #{node} answered nonsense")
  end

  defp deferred(recipients, text), do: for(rcpt <- recipients, do: {rcpt, "4.3.0", text})
end
