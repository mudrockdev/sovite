defmodule Sovite.Core.Mailbox.Directory do
  @moduledoc """
  The user directory of the mailbox part: the users of `sovitectl user`
  (their passwords and the sender addresses they may use) and the
  mailboxes of `sovitectl mailbox`.

  It is kept in Sovite's database, which every node shares, so every
  node reads it here, whether or not it runs the mailbox part. The other
  parts use it only through `Sovite.Core.Stack.Mailbox`.
  """

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Tables.{Mailboxes, Users}

  @doc "Checks a user's password (see `Sovite.SASL.Backend`); `opts` has the `:repo`."
  @spec verify_password(String.t(), String.t(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  defdelegate verify_password(username, password, opts), to: Users

  @doc "A user's SCRAM-SHA-256 credentials (see `Sovite.SASL.Backend`)."
  @spec scram_credentials(String.t(), keyword()) :: {:ok, map(), String.t()} | {:error, term()}
  defdelegate scram_credentials(username, opts), to: Users

  @doc "The sender addresses a user may use, besides their login."
  @spec senders(Repo.t(), String.t()) :: [String.t()]
  defdelegate senders(repo, username), to: Users

  @doc "Looks up an enabled mailbox: its address, `:error` if none, `{:error, reason}` on failure."
  @spec mailbox(Repo.t(), String.t()) :: {:ok, String.t()} | :error | {:error, term()}
  def mailbox(repo, address), do: Mailboxes.lookup(%{repo: repo}, address)

  @doc "When the mailbox at exactly `address` was added, or `:error` if there is none."
  @spec added_at(Repo.t(), String.t()) :: {:ok, DateTime.t()} | :error
  defdelegate added_at(repo, address), to: Mailboxes
end
