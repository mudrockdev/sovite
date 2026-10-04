defmodule Sovite.Core.CLI do
  @moduledoc """
  The `sovitectl` command line.

  Releases ship a `bin/sovitectl` wrapper that runs `main/1` with
  `bin/sovite eval`. The VM is not started as a server, so these commands
  work whether or not the MTA is running.

      sovitectl config check [PATH]
      sovitectl user list
      sovitectl user add alice@example.com        # reads the password from stdin
      sovitectl user sender add alice@example.com @example.org
      sovitectl hash-password                     # for auth.backend = "file"

  Commands that use the database read the config file given with
  `--config PATH`, or the default one.
  """

  alias Sovite.Core.{Config, Repo, Users}
  alias Sovite.SASL.Password

  @version Mix.Project.config()[:version]

  @usage """
  Usage: sovitectl [--config PATH] COMMAND

  Commands:
    config check [PATH]              Validate the config file (default: $SOVITE_CONFIG or /etc/sovite/sovite.toml)
    user list                        List users and the sender addresses they may use
    user add NAME                    Create a user; the password is read from standard input
    user passwd NAME                 Set a new password, read from standard input
    user delete NAME                 Delete a user
    user enable NAME                 Allow a user to log in again
    user disable NAME                Stop a user from logging in
    user sender add NAME PATTERN     Let a user send as PATTERN: an address, @domain, or *
    user sender remove NAME PATTERN  Take that permission away
    hash-password [SCHEME]           Hash a password from standard input for an auth.file users file.
                                     SCHEME: scram-sha-256 (default), sha512-crypt, sha256-crypt
    version                          Print the Sovite version
    help                             Show this help
  """

  @doc "Runs the command in `argv` and halts the VM with its exit status."
  @spec main([String.t()]) :: no_return()
  def main(argv), do: argv |> run() |> System.halt()

  @doc "Runs the command in `argv` and returns its exit status."
  @spec run([String.t()]) :: non_neg_integer()
  def run(["--config", path | rest]), do: run(rest, path)
  def run(argv), do: run(argv, Config.default_path())

  defp run(["config", "check"], path), do: config_check(path)
  defp run(["config", "check", path], _default), do: config_check(path)

  defp run(["user", "list"], path), do: with_repo(path, &list_users/1)

  defp run(["user", "add", name], path) do
    with_password(fn password -> with_repo(path, &create_user(&1, name, password)) end)
  end

  defp run(["user", "passwd", name], path) do
    with_password(fn password ->
      with_repo(path, fn repo ->
        result(Users.set_password(repo, name, password), "password changed for #{name}")
      end)
    end)
  end

  defp run(["user", "delete", name], path),
    do: with_repo(path, &result(Users.delete(&1, name), "deleted #{name}"))

  defp run(["user", "enable", name], path),
    do: with_repo(path, &result(Users.set_enabled(&1, name, true), "enabled #{name}"))

  defp run(["user", "disable", name], path),
    do: with_repo(path, &result(Users.set_enabled(&1, name, false), "disabled #{name}"))

  defp run(["user", "sender", "add", name, pattern], path),
    do:
      with_repo(
        path,
        &result(Users.add_sender(&1, name, pattern), "#{name} may now send as #{pattern}")
      )

  defp run(["user", "sender", "remove", name, pattern], path),
    do:
      with_repo(
        path,
        &result(
          Users.remove_sender(&1, name, pattern),
          "#{name} may no longer send as #{pattern}"
        )
      )

  defp run(["hash-password" | scheme], _path) do
    case scheme(scheme) do
      {:ok, scheme} ->
        with_password(fn password ->
          IO.puts(Password.hash(password, scheme))
          0
        end)

      :error ->
        usage_error()
    end
  end

  defp run(["version"], _path) do
    IO.puts("sovite #{@version}")
    0
  end

  defp run([help], _path) when help in ["help", "--help", "-h"] do
    IO.write(@usage)
    0
  end

  defp run(_argv, _path), do: usage_error()

  defp usage_error do
    IO.write(:stderr, @usage)
    64
  end

  defp scheme([]), do: {:ok, :scram_sha256}
  defp scheme(["scram-sha-256"]), do: {:ok, :scram_sha256}
  defp scheme(["sha512-crypt"]), do: {:ok, :sha512_crypt}
  defp scheme(["sha256-crypt"]), do: {:ok, :sha256_crypt}
  defp scheme(_), do: :error

  defp config_check(path) do
    case Config.load(path) do
      {:ok, _config} ->
        IO.puts("#{path}: OK")
        0

      {:error, errors} ->
        print_config_errors(path, errors)
        1
    end
  end

  defp print_config_errors(path, errors) do
    for error <- errors, do: IO.puts(:stderr, "#{path}: " <> Exception.message(error))
  end

  ## Users

  defp create_user(repo, name, password) do
    case Users.create(repo, name, password) do
      {:ok, user} -> done("created #{user.username}")
      error -> result(error, nil)
    end
  end

  defp list_users(repo) do
    for user <- Users.list(repo) do
      state = if user.enabled, do: "enabled", else: "disabled"
      senders = Enum.map_join(user.sender_logins, ", ", & &1.address)
      senders = if senders == "", do: "", else: "  senders: " <> senders
      IO.puts("#{user.username}  #{state}#{senders}")
    end

    0
  end

  defp result({:ok, _}, message), do: done(message)
  defp result(:ok, message), do: done(message)
  defp result({:error, :not_found}, _message), do: fail("no such user")

  defp result({:error, %Ecto.Changeset{} = changeset}, _message) do
    changeset
    |> Ecto.Changeset.traverse_errors(fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Enum.map_join("; ", fn {field, messages} -> "#{field} #{Enum.join(messages, ", ")}" end)
    |> fail()
  end

  defp done(message) do
    IO.puts(message)
    0
  end

  defp fail(message) do
    IO.puts(:stderr, "error: " <> message)
    1
  end

  # Starts the database from the config, runs `fun` with it, and stops it.
  defp with_repo(path, fun) do
    case Config.load(path) do
      {:ok, config} ->
        database = config.database
        {:ok, _} = Application.ensure_all_started(:ecto_sql)
        {:ok, _} = Application.ensure_all_started(Repo.driver(database.adapter))

        case Repo.start_link(database, nil) do
          {:ok, pid} ->
            try do
              fun.({Repo.module(database.adapter), pid})
            after
              Supervisor.stop(pid)
            end

          {:error, reason} ->
            fail("cannot open the database: #{inspect(reason)}")
        end

      {:error, errors} ->
        print_config_errors(path, errors)
        1
    end
  end

  # Reads one line. On a terminal the input is not echoed.
  defp with_password(fun) do
    IO.write(:stderr, "Password: ")
    echo = :io.getopts(:standard_io)[:echo]
    _ = :io.setopts(:standard_io, echo: false)

    line =
      try do
        IO.gets(:standard_io, "")
      after
        if echo != nil, do: :io.setopts(:standard_io, echo: echo)
        IO.write(:stderr, "\n")
      end

    case line do
      line when is_binary(line) ->
        case String.trim_trailing(line, "\n") |> String.trim_trailing("\r") do
          "" -> fail("empty password")
          password -> fun.(password)
        end

      _ ->
        fail("no password given")
    end
  end
end
