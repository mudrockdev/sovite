defmodule Sovite.Core.CLI.Helpers do
  @moduledoc false
  # Output, database, and password helpers shared by the sovitectl
  # commands.

  alias Sovite.Core.{Config, Repo}

  @doc "Prints config errors."
  def print_config_errors(path, errors) do
    for error <- errors, do: IO.puts(:stderr, "#{path}: " <> Exception.message(error))
  end

  @doc """
  Prints `message` for a success, or the error. `not_found` is the text
  for `{:error, :not_found}`.
  """
  def result(result, message, not_found \\ "no such user")
  def result({:ok, _}, message, _not_found), do: done(message)
  def result(:ok, message, _not_found), do: done(message)
  def result({:error, :not_found}, _message, not_found), do: fail(not_found)

  def result({:error, %Ecto.Changeset{} = changeset}, _message, _not_found) do
    changeset
    |> Ecto.Changeset.traverse_errors(fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Enum.map_join("; ", fn {field, messages} -> "#{field} #{Enum.join(messages, ", ")}" end)
    |> fail()
  end

  def done(message) do
    IO.puts(message)
    0
  end

  def fail(message) do
    IO.puts(:stderr, "error: " <> message)
    1
  end

  @doc "Starts the database from the config, runs `fun` with it, and stops it."
  def with_repo(path, fun) do
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

  @doc "Reads a password line. On a terminal the input is not echoed."
  def with_password(fun) do
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
