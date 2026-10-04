defmodule Sovite.SASL.Backend.Static do
  @moduledoc """
  A `Sovite.SASL.Backend` that reads users from a file, one per line:

      # user:password-hash[:anything else]
      alice@example.com:{SCRAM-SHA-256}4096,...
      bob@example.com:$6$rounds=5000$...

  The format is compatible with Dovecot's `passwd-file`: fields after the
  second are ignored. Blank lines and lines starting with `#` are
  skipped. User names are matched case-insensitively. Hashes are in a
  format `Sovite.SASL.Password` knows; `sovitectl hash-password` makes
  them.

  The file is read on first use and again whenever it changes, so users
  can be added without a restart. If a changed file cannot be read, the
  previous contents stay in use.

  ## Options

    * `:file` - path to the users file. Required.
  """

  @behaviour Sovite.SASL.Backend

  alias Sovite.SASL.Password

  @typedoc "Why a users file was refused: the line number and the problem."
  @type parse_error :: {:line, pos_integer(), :syntax | :unsupported_hash}

  @impl true
  def verify_password(username, password, opts) do
    with {:ok, users} <- users(opts) do
      case Map.fetch(users, normalize(username)) do
        {:ok, hash} ->
          case Password.verify(hash, password) do
            :ok -> {:ok, normalize(username)}
            {:error, _} -> {:error, :invalid}
          end

        :error ->
          Password.dummy_verify(password)
          {:error, :unknown_user}
      end
    end
  end

  @impl true
  def scram_credentials(username, opts) do
    with {:ok, users} <- users(opts) do
      case Map.fetch(users, normalize(username)) do
        {:ok, hash} ->
          case Password.scram_credentials(hash) do
            {:ok, credentials} -> {:ok, credentials, normalize(username)}
            :error -> {:error, :unavailable}
          end

        :error ->
          {:error, :unknown_user}
      end
    end
  end

  @doc """
  Reads and checks a users file. Returns the users, keyed by lower-cased
  name, or the first problem.
  """
  @spec load(Path.t()) ::
          {:ok, %{String.t() => String.t()}} | {:error, File.posix() | parse_error()}
  def load(path) do
    with {:ok, contents} <- File.read(path), do: parse(contents)
  end

  @doc "Parses the contents of a users file, see `load/1`."
  @spec parse(String.t()) :: {:ok, %{String.t() => String.t()}} | {:error, parse_error()}
  def parse(contents) do
    contents
    |> String.split(["\r\n", "\n"])
    |> Enum.with_index(1)
    |> Enum.reduce_while({:ok, %{}}, fn {line, number}, {:ok, users} ->
      case parse_line(String.trim(line)) do
        :skip -> {:cont, {:ok, users}}
        {:ok, user, hash} -> {:cont, {:ok, Map.put(users, user, hash)}}
        {:error, reason} -> {:halt, {:error, {:line, number, reason}}}
      end
    end)
  end

  defp parse_line(""), do: :skip
  defp parse_line("#" <> _), do: :skip

  defp parse_line(line) do
    case String.split(line, ":", parts: 3) do
      [user, hash | _] when user != "" and hash != "" ->
        if Password.supported?(hash),
          do: {:ok, normalize(user), hash},
          else: {:error, :unsupported_hash}

      _ ->
        {:error, :syntax}
    end
  end

  defp normalize(username), do: String.downcase(username)

  # Cached per path, keyed by the file's size, mtime, and inode.
  defp users(opts) do
    path = Keyword.fetch!(opts, :file)
    key = {__MODULE__, path}
    cached = :persistent_term.get(key, nil)

    case {File.stat(path), cached} do
      {{:ok, stat}, {stamp, users}} when stamp == {stat.size, stat.mtime, stat.inode} ->
        {:ok, users}

      {{:ok, stat}, _} ->
        case load(path) do
          {:ok, users} ->
            :persistent_term.put(key, {{stat.size, stat.mtime, stat.inode}, users})
            {:ok, users}

          {:error, reason} ->
            keep(cached, reason)
        end

      {{:error, reason}, _} ->
        keep(cached, reason)
    end
  end

  defp keep({_stamp, users}, _reason), do: {:ok, users}
  defp keep(nil, reason), do: {:error, {:temporary, reason}}
end
