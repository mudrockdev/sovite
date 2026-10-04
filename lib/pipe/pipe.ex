defmodule Sovite.Pipe do
  @moduledoc """
  Runs an external command with a file as its standard input, for
  delivery to programs such as `procmail`, `dovecot-lda`, or a list
  manager.

      {:ok, 0, _output} = Sovite.Pipe.run(["/usr/bin/procmail", "-a", "lists"], "/tmp/message")

  The command is run directly, never through a shell, so its arguments
  are passed exactly as given. It starts with an empty environment, apart
  from `PATH` and the `:env` option, in the given working directory, and
  is killed when it runs longer than the timeout. Standard output and
  standard error are collected together, up to a limit, for error
  reports.

  To confine the command further, put a sandbox program in front of it,
  such as `systemd-run --pipe --wait --collect -p DynamicUser=yes` or
  `bwrap`: they take the command as their arguments and pass standard
  input through.
  """

  # Standard input is redirected by /bin/sh from the file: an Erlang port
  # cannot close a program's standard input while still reading its
  # output. The file name and the command are positional parameters, so
  # nothing is interpreted by the shell.
  @script ~S(f="$1"; shift; exec "$@" <"$f")

  @default_path "/usr/local/bin:/usr/bin:/bin"

  @typedoc "Why the command did not run to its end."
  @type error :: :timeout | File.posix()

  @doc """
  Runs `command` (the program, an absolute path, and its arguments) with
  the file `input` as its standard input.

  Returns `{:ok, exit_status, output}` when the command ran: an exit
  status above 128 means it was killed by signal `status - 128`. Returns
  `{:error, :timeout, output}` when it was killed for running too long,
  and `{:error, reason}` when it could not be started (`:enoent`,
  `:eacces`).

  ## Options

    * `:env` - environment variables, a map of names to values. `PATH`
      defaults to `#{@default_path}`.
    * `:directory` - the working directory. Defaults to `/`.
    * `:timeout` - milliseconds. Defaults to 10 minutes.
    * `:max_output` - bytes of output to keep. Defaults to 4096.
  """
  @spec run([String.t(), ...], Path.t(), keyword()) ::
          {:ok, non_neg_integer(), binary()} | {:error, :timeout, binary()} | {:error, error()}
  def run([program | args], input, opts \\ []) do
    with :ok <- check_executable(program) do
      port =
        Port.open({:spawn_executable, shell()}, [
          :binary,
          :exit_status,
          :stderr_to_stdout,
          :hide,
          args: ["-c", @script, "sovite-pipe", input, program | args],
          env: environment(Keyword.get(opts, :env, %{})),
          cd: Keyword.get(opts, :directory, "/")
        ])

      deadline = System.monotonic_time(:millisecond) + Keyword.get(opts, :timeout, 600_000)
      collect(port, deadline, Keyword.get(opts, :max_output, 4096), [])
    end
  end

  defp check_executable(program) do
    with true <- Path.type(program) == :absolute,
         {:ok, %File.Stat{type: :regular, mode: mode}} <- File.stat(program) do
      if Bitwise.band(mode, 0o111) != 0, do: :ok, else: {:error, :eacces}
    else
      false -> {:error, :enoent}
      {:ok, _not_a_file} -> {:error, :eacces}
      {:error, reason} -> {:error, reason}
    end
  end

  defp shell, do: System.find_executable("sh") || "/bin/sh"

  # Every inherited variable is unset, then the given ones are set.
  defp environment(env) do
    env = Map.put_new(env, "PATH", @default_path)
    unset = for {name, _} <- System.get_env(), not Map.has_key?(env, name), do: {name, false}

    Enum.map(unset ++ Map.to_list(env), fn
      {name, false} -> {String.to_charlist(name), false}
      {name, value} -> {String.to_charlist(name), String.to_charlist(value)}
    end)
  end

  defp collect(port, deadline, room, acc) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, data}} ->
        kept = binary_part(data, 0, min(byte_size(data), room))
        collect(port, deadline, room - byte_size(kept), [acc, kept])

      {^port, {:exit_status, status}} ->
        {:ok, status, IO.iodata_to_binary(acc)}
    after
      remaining ->
        kill(port)
        {:error, :timeout, IO.iodata_to_binary(acc)}
    end
  end

  defp kill(port) do
    case Port.info(port, :os_pid) do
      {:os_pid, pid} -> signal_kill(pid)
      nil -> :ok
    end

    try do
      Port.close(port)
    rescue
      ArgumentError -> :ok
    end

    flush(port)
  end

  defp signal_kill(pid) do
    case System.find_executable("kill") do
      nil -> :ok
      kill -> System.cmd(kill, ["-KILL", Integer.to_string(pid)], stderr_to_stdout: true)
    end
  end

  defp flush(port) do
    receive do
      {^port, _} -> flush(port)
    after
      0 -> :ok
    end
  end
end
