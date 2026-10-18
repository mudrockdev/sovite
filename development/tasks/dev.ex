defmodule Mix.Tasks.Dev do
  @shortdoc "Runs the MTA and the web UI's dev server"

  @moduledoc """
  Runs the MTA (as `mix dev.mta`) and the web UI's Vite dev server (`bun
  dev` in `lib/core/sovite_web`) together, for development.

      mix dev
      mix dev --config path/to/sovite.toml

  The dev server reloads the UI as its files change, and forwards `/api`
  to the MTA's admin API. Its output is shown with the MTA's. Stop both
  with Ctrl+C. `bun install` runs first if the UI's packages are missing.
  """

  use Mix.Task

  alias Mix.Tasks.Dev.Mta

  @web "lib/core/sovite_web"

  # Runs the dev server in its own process group, and stops the group
  # when standard input closes, that is when the VM exits: Vite does not
  # stop by itself when its parent goes away.
  @wrapper """
  set -m
  "$0" run dev &
  pid=$!
  trap 'kill -TERM -- -$pid 2>/dev/null' EXIT INT TERM
  while read -r _; do :; done
  """

  @impl Mix.Task
  def run(args) do
    bun = System.find_executable("bun") || Mix.raise("bun is not installed: see https://bun.sh")
    config = Mta.start(args)

    unless File.dir?(Path.join(@web, "node_modules")) do
      {_, 0} = System.cmd(bun, ["install"], into: IO.stream(), stderr_to_stdout: true)
    end

    admin = config.admin
    scheme = if admin.tls, do: "https", else: "http"

    port =
      Port.open({:spawn_executable, System.find_executable("sh")}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        args: ["-c", @wrapper, bun],
        cd: @web,
        # Where the dev server forwards /api (see vite.config.ts).
        env: [{~c"SOVITE_API", ~c"#{scheme}://#{:inet.ntoa(admin.address)}:#{admin.port}"}]
      ])

    forward(port)
  end

  defp forward(port) do
    receive do
      {^port, {:data, data}} ->
        IO.write(data)
        forward(port)

      {^port, {:exit_status, status}} ->
        Mix.raise("the web UI's dev server stopped (exit status #{status})")
    end
  end
end
