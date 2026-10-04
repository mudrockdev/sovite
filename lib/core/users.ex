defmodule Sovite.Core.Users do
  @moduledoc """
  Users stored in Sovite's database (`Sovite.Core.Repo`), and a
  `Sovite.SASL.Backend` that authenticates against them.

  Passwords are stored as `Sovite.SASL.Password` hashes; new ones are
  `{SCRAM-SHA-256}`, so users can log in with `PLAIN`, `LOGIN`, and
  `SCRAM-SHA-256`. Disabled users cannot log in.

  Manage users with `sovitectl user`. Every function takes the repo
  reference first; as a backend, pass it as `repo:` in the options.
  """

  @behaviour Sovite.SASL.Backend

  import Ecto.Query, only: [from: 2, order_by: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Users.{SenderLogin, User}
  alias Sovite.SASL.Password

  @doc "Creates a user. The password is hashed with `Sovite.SASL.Password.hash/1`."
  @spec create(Repo.t(), String.t(), String.t()) :: {:ok, User.t()} | {:error, Ecto.Changeset.t()}
  def create(repo, username, password) do
    Repo.run(repo, fn module ->
      %User{}
      |> User.changeset(%{username: username, password_hash: Password.hash(password)})
      |> module.insert()
    end)
  end

  @doc "Returns the user, or `nil`."
  @spec get(Repo.t(), String.t()) :: User.t() | nil
  def get(repo, username) do
    Repo.run(repo, & &1.get_by(User, username: User.normalize(username)))
  end

  @doc "Lists all users, by name, with their sender addresses."
  @spec list(Repo.t()) :: [User.t()]
  def list(repo) do
    Repo.run(repo, fn module ->
      User
      |> order_by(:username)
      |> module.all()
      |> module.preload(sender_logins: from(s in SenderLogin, order_by: s.address))
    end)
  end

  @doc "Sets a new password."
  @spec set_password(Repo.t(), String.t(), String.t()) ::
          {:ok, User.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def set_password(repo, username, password),
    do: change_user(repo, username, %{password_hash: Password.hash(password)})

  @doc "Enables or disables a user."
  @spec set_enabled(Repo.t(), String.t(), boolean()) ::
          {:ok, User.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def set_enabled(repo, username, enabled), do: change_user(repo, username, %{enabled: enabled})

  defp change_user(repo, username, attrs) do
    Repo.run(repo, fn module ->
      case module.get_by(User, username: User.normalize(username)) do
        nil -> {:error, :not_found}
        user -> user |> User.changeset(attrs) |> module.update()
      end
    end)
  end

  @doc "Deletes a user and their sender addresses."
  @spec delete(Repo.t(), String.t()) :: :ok | {:error, :not_found}
  def delete(repo, username) do
    Repo.run(repo, fn module ->
      case module.delete_all(from(u in User, where: u.username == ^User.normalize(username))) do
        {0, _} -> {:error, :not_found}
        {_, _} -> :ok
      end
    end)
  end

  @doc "Allows a user to send as `address`, see `Sovite.Core.Users.SenderLogin`."
  @spec add_sender(Repo.t(), String.t(), String.t()) ::
          {:ok, SenderLogin.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def add_sender(repo, username, address) do
    Repo.run(repo, fn module ->
      case module.get_by(User, username: User.normalize(username)) do
        nil ->
          {:error, :not_found}

        user ->
          %SenderLogin{user_id: user.id}
          |> SenderLogin.changeset(%{address: address})
          |> module.insert()
      end
    end)
  end

  @doc "Removes a sender address from a user."
  @spec remove_sender(Repo.t(), String.t(), String.t()) :: :ok | {:error, :not_found}
  def remove_sender(repo, username, address) do
    Repo.run(repo, fn module ->
      # SQLite cannot DELETE with a JOIN.
      user_ids = from(u in User, where: u.username == ^User.normalize(username), select: u.id)

      query =
        from(s in SenderLogin,
          where: s.user_id in subquery(user_ids),
          where: s.address == ^String.downcase(String.trim(address), :ascii)
        )

      case module.delete_all(query) do
        {0, _} -> {:error, :not_found}
        {_, _} -> :ok
      end
    end)
  end

  @doc "Returns the sender addresses a user may use (empty for unknown users)."
  @spec senders(Repo.t(), String.t()) :: [String.t()]
  def senders(repo, username) do
    Repo.run(repo, fn module ->
      from(s in SenderLogin,
        join: u in User,
        on: u.id == s.user_id,
        where: u.username == ^User.normalize(username),
        order_by: s.address,
        select: s.address
      )
      |> module.all()
    end)
  end

  ## Sovite.SASL.Backend

  @impl Sovite.SASL.Backend
  def verify_password(username, password, opts) do
    case lookup(username, opts) do
      {:ok, %User{enabled: true} = user} ->
        case Password.verify(user.password_hash, password) do
          :ok -> {:ok, user.username}
          {:error, _} -> {:error, :invalid}
        end

      {:ok, _disabled_or_missing} ->
        Password.dummy_verify(password)
        {:error, :unknown_user}

      {:error, _} = error ->
        error
    end
  end

  @impl Sovite.SASL.Backend
  def scram_credentials(username, opts) do
    case lookup(username, opts) do
      {:ok, %User{enabled: true} = user} ->
        case Password.scram_credentials(user.password_hash) do
          {:ok, credentials} -> {:ok, credentials, user.username}
          :error -> {:error, :unavailable}
        end

      {:ok, _} ->
        {:error, :unknown_user}

      {:error, _} = error ->
        error
    end
  end

  # A database failure must not look like a wrong password.
  defp lookup(username, opts) do
    {:ok, get(Keyword.fetch!(opts, :repo), username)}
  rescue
    error -> {:error, {:temporary, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:temporary, reason}}
  end
end
