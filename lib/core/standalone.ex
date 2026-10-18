defmodule Sovite.Core.Standalone do
  @moduledoc """
  The single-binary build of Sovite (`mix build.release.x86` and
  `mix build.release.aarch64`, made with Burrito): one executable that
  is the server and every command.

      sovite                       # runs the server
      sovite ctl status            # sovitectl status
      sovite sendmail -t < mail    # sendmail(1)
      sovite mailq                 # mailq(1)
      sovite newaliases            # newaliases(1)
      sovite version

  The packages install `sovitectl`, `sendmail`, `mailq`, and
  `newaliases` as small scripts that run these commands.

  The binary starts the VM with Elixir's command line, which would take
  the first argument for a script to run, and stop the VM once the boot
  is done. So `Sovite` runs a command here, before that, and halts; with
  no arguments, it keeps the VM running for the server.
  """

  alias Sovite.Core.{CLI, Sendmail}

  @version Mix.Project.config()[:version]

  @usage """
  Usage: sovite [COMMAND [ARGS...]]

  Without a command, runs the server (config: $SOVITE_CONFIG or
  /etc/sovite/sovite.toml). Commands:

    ctl ARGS...           The admin CLI, as sovitectl: sovite ctl help
    sendmail ARGS...      sendmail(1), for local programs
    mailq                 mailq(1): the queue
    newaliases            newaliases(1)
    version               Print the version
    help                  Show this help
  """

  @typedoc "What a run of the binary does."
  @type command :: :server | {:run, (-> non_neg_integer())}

  @doc """
  What this run of the VM does: `nil` outside the single binary, else
  `:server` or a command to run.
  """
  @spec command() :: command() | nil
  def command do
    if System.get_env("__BURRITO") == "1",
      do: command(Enum.map(:init.get_plain_arguments(), &List.to_string/1)),
      else: nil
  end

  @doc false
  @spec command([String.t()]) :: command()
  def command([]), do: :server
  def command(["ctl" | args]), do: {:run, fn -> CLI.run(args) end}
  def command(["sendmail" | args]), do: {:run, fn -> Sendmail.run(args) end}
  def command(["mailq" | args]), do: {:run, fn -> Sendmail.run(["-bp" | args]) end}
  def command(["newaliases" | args]), do: {:run, fn -> Sendmail.run(["-bi" | args]) end}
  def command(["version"]), do: {:run, fn -> print("sovite #{@version}", 0) end}

  def command([help]) when help in ["help", "--help", "-h"],
    do: {:run, fn -> print(String.trim_trailing(@usage), 0) end}

  def command(_args), do: {:run, fn -> usage_error() end}

  @doc """
  For the server: keeps Elixir's command line from stopping the VM once
  the boot is done (it calls the exit handlers before halting), and
  stops the VM gracefully when the binary that started it goes away.

  The binary runs the VM as a child process and waits for it: a signal
  to the binary alone (`kill PID`) would leave the VM running.
  systemd signals both, as do Ctrl+C and `kill` of the process group.
  """
  @spec keep_running() :: :ok
  def keep_running do
    System.at_exit(fn _status -> Process.sleep(:infinity) end)

    with {:ok, parent} <- parent_pid(), do: spawn(fn -> watch_parent(parent) end)
    :ok
  end

  defp watch_parent(parent) do
    Process.sleep(1_000)

    case parent_pid() do
      {:ok, ^parent} -> watch_parent(parent)
      # Gone: this process now belongs to init or a subreaper.
      _ -> System.stop(0)
    end
  end

  @doc false
  # The VM's parent process, from /proc (Linux).
  @spec parent_pid(String.t()) :: {:ok, pos_integer()} | :error
  def parent_pid(stat_file \\ "/proc/self/stat") do
    with {:ok, stat} <- File.read(stat_file),
         # After the command name, in parentheses, which can hold ") ".
         [_ | _] = matches <- :binary.matches(stat, ") "),
         {position, length} = List.last(matches),
         after_name = binary_part(stat, position + length, byte_size(stat) - position - length),
         [_state, ppid | _] <- String.split(after_name, " "),
         {ppid, ""} <- Integer.parse(ppid) do
      {:ok, ppid}
    else
      _ -> :error
    end
  end

  defp print(text, status) do
    IO.puts(text)
    status
  end

  defp usage_error do
    IO.write(:stderr, @usage)
    64
  end
end
