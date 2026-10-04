defmodule Sovite.Core.CLI do
  @moduledoc """
  The `sovitectl` command line.

  Releases ship a `bin/sovitectl` wrapper that runs `main/1` with
  `bin/sovite eval`. The VM is not started as a server, so commands that
  only read files work even while the MTA is stopped.

      sovitectl config check [PATH]
  """

  alias Sovite.Core.Config

  @version Mix.Project.config()[:version]

  @usage """
  Usage: sovitectl COMMAND

  Commands:
    config check [PATH]   Validate the config file (default: $SOVITE_CONFIG or /etc/sovite/sovite.toml)
    version               Print the Sovite version
    help                  Show this help
  """

  @doc "Runs the command in `argv` and halts the VM with its exit status."
  @spec main([String.t()]) :: no_return()
  def main(argv), do: argv |> run() |> System.halt()

  @doc "Runs the command in `argv` and returns its exit status."
  @spec run([String.t()]) :: non_neg_integer()
  def run(["config", "check"]), do: config_check(Config.default_path())
  def run(["config", "check", path]), do: config_check(path)

  def run(["version"]) do
    IO.puts("sovite #{@version}")
    0
  end

  def run([help]) when help in ["help", "--help", "-h"] do
    IO.write(@usage)
    0
  end

  def run(_argv) do
    IO.write(:stderr, @usage)
    64
  end

  defp config_check(path) do
    case Config.load(path) do
      {:ok, _config} ->
        IO.puts("#{path}: OK")
        0

      {:error, errors} ->
        for error <- errors, do: IO.puts(:stderr, "#{path}: " <> Exception.message(error))
        1
    end
  end
end
