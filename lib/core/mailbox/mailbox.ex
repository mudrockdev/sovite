defmodule Sovite.Core.Mailbox do
  @moduledoc """
  The mailbox part of the stack (`[stack] mailbox`), in place of Dovecot.

  So far it is the user directory (`Sovite.Core.Mailbox.Directory`) and
  the Maildir store (`Sovite.Core.Mailbox.Store`); IMAP, POP3, and the
  rest come in 3.0 (see `ROADMAP.md`). The other parts use it only
  through `Sovite.Core.Stack.Mailbox`.
  """

  alias Sovite.Core.Config
  alias Sovite.Core.Mailbox.{Server, Store}

  @doc """
  The part's processes: in a cluster, the server that takes mail for
  the store from the other nodes. None when the part is off.
  """
  @spec child_specs(Config.t()) :: [Supervisor.child_spec() | {module(), term()}]
  def child_specs(config) do
    if Config.part?(config, :mailbox) and config.cluster.enabled,
      do: [{Server, store: Store.opts(config)}],
      else: []
  end
end
