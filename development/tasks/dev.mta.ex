defmodule Mix.Tasks.Dev.Mta do
  @shortdoc "Runs the MTA for development"

  @moduledoc """
  Runs the MTA on this machine, for development.

      mix dev.mta
      mix dev.mta --config path/to/sovite.toml
      iex -S mix dev.mta

  The config file is `--config`, else `$SOVITE_CONFIG`, else `sovite.toml`
  in the project, else `development/sovite.toml`. That last one is
  written on the first run, with settings for development:

    * data (database, queue, logs, admin token) in `development/`
    * SMTP on `127.0.0.1:2525`
    * the web UI and admin API on `127.0.0.1:9025`
    * mail for `sovite.test` delivered to Maildir folders in
      `development/mail/`, and all other mail relayed to
      `127.0.0.1:1025`, where a mail catcher such as Mailpit can show it,
      so nothing is sent to the internet

  It prints where it listens and the admin token for the web UI. Stop it
  with Ctrl+C. `mix dev` also runs the web UI's dev server.
  """

  use Mix.Task

  alias Sovite.Core.Config

  @generated "development/sovite.toml"

  @impl Mix.Task
  def run(args) do
    start(args)
    unless iex?(), do: Process.sleep(:infinity)
  end

  @doc false
  # Starts the MTA and returns its config. `mix dev` uses it too.
  def start(args) do
    {opts, _rest} = OptionParser.parse!(args, strict: [config: :string])
    path = opts |> config_path() |> Path.expand()

    System.put_env("SOVITE_CONFIG", path)
    System.put_env("SOVITE_START_MTA", "1")
    Application.put_env(:sovite, :start_mta, true)
    Mix.Task.run("app.start")

    {:ok, config} = Config.load(path)
    banner(path, config)
    config
  end

  defp iex?, do: Code.ensure_loaded?(IEx) and IEx.started?()

  defp config_path(opts) do
    cond do
      opts[:config] -> opts[:config]
      System.get_env("SOVITE_CONFIG") -> System.get_env("SOVITE_CONFIG")
      File.exists?("sovite.toml") -> "sovite.toml"
      File.exists?(@generated) -> @generated
      true -> generate(@generated)
    end
  end

  @doc false
  def generate(path) do
    root = File.cwd!()
    data = Path.join(root, "development")

    File.write!(path, """
    # Sovite development config, written by `mix dev.mta`. Edit it freely,
    # or delete it to get a fresh one. See docs/configuration.md.

    [server]
    hostname = "mx.sovite.test"
    shutdown_timeout = "5s"

    [database]
    path = "#{data}/sovite.db"

    [queue]
    directory = "#{data}/spool"
    min_backoff = "30s"
    max_backoff = "5m"

    [[listener]]
    address = "127.0.0.1"
    port = 2525

    [domains]
    local = ["sovite.test", "mx.sovite.test"]

    [maildir]
    local = "#{data}/mail/{user}/"

    # Everything else goes to a local mail catcher, such as Mailpit
    # (`mailpit --smtp 127.0.0.1:1025`), never to the internet.
    [delivery]
    relayhost = "[127.0.0.1]:1025"
    tls = "may"

    [dns]
    dnssec = "off"

    [admin]
    address = "127.0.0.1"
    port = 9025
    token_file = "#{data}/admin.token"
    web_root = "#{root}/lib/core/sovite_web/build"

    [log]
    level = "debug"
    """)

    Mix.shell().info("Wrote #{path}")
    path
  end

  defp banner(path, config) do
    listeners =
      Enum.map(config.listener, fn listener ->
        "  #{listener.mode}: #{:inet.ntoa(listener.address)}:#{listener.port}"
      end)

    admin = config.admin

    web =
      if admin.enabled do
        scheme = if admin.tls, do: "https", else: "http"

        token =
          case File.read(admin.token_file) do
            {:ok, token} -> String.trim(token)
            {:error, _} -> "(see #{admin.token_file})"
          end

        [
          "  web UI and admin API: #{scheme}://#{:inet.ntoa(admin.address)}:#{admin.port}",
          "  admin token: #{token}"
        ]
      else
        []
      end

    lines = ["", "Sovite is running with #{Path.relative_to_cwd(path)}"] ++ listeners ++ web
    Mix.shell().info(Enum.join(lines, "\n") <> "\n")
  end
end
