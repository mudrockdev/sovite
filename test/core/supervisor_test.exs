defmodule Sovite.Core.SupervisorTest do
  # Changes global logger configuration and the stored config.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Sovite.Core.{Config, Telemetry}
  alias Sovite.Core.Logging.FileHandler

  @moduletag :tmp_dir
  @moduletag :capture_log

  setup do
    # With :capture_log the default handler is swapped out during the test,
    # so only restore its formatter when it exists.
    level = Logger.level()
    handler = :logger.get_handler_config(:default)

    on_exit(fn ->
      Logger.configure(level: level)
      Telemetry.detach_logger()

      with {:ok, %{formatter: formatter}} <- handler do
        :logger.update_handler_config(:default, :formatter, formatter)
      end
    end)
  end

  test "starts with a valid config file and stores the config", %{tmp_dir: dir} do
    path = Path.join(dir, "sovite.toml")
    File.write!(path, ~s([server]\nhostname = "mx.example.org"\n[log]\nlevel = "warning"\n))

    pid = start_supervised!({Sovite.Core.Supervisor, config_path: path, name: nil})

    assert Process.alive?(pid)
    assert Config.get().server.hostname == "mx.example.org"
    assert Logger.level() == :warning
  end

  test "writes logs to files when log.directory is set", %{tmp_dir: dir} do
    logs = Path.join(dir, "logs")

    {:ok, config} =
      Config.parse("""
      [server]
      hostname = "mx.example.org"
      [log]
      directory = "#{logs}"
      file_name = "mta.{n}.log"
      symlink = "current.log"
      """)

    start_supervised!({Sovite.Core.Supervisor, config: config, name: nil})
    :ok = FileHandler.sync(:sovite_file)

    assert File.read!(Path.join(logs, "current.log")) =~ "[info] sovite started on mx.example.org"

    stop_supervised!(Sovite.Core.Supervisor)
    assert {:error, {:not_found, :sovite_file}} = :logger.get_handler_config(:sovite_file)
  end

  test "accepts an already validated config" do
    {:ok, config} = Config.parse(~s([server]\nhostname = "embedded.example"\n))
    start_supervised!({Sovite.Core.Supervisor, config: config, name: nil})

    assert Config.get().server.hostname == "embedded.example"
  end

  test "refuses to start with an invalid config and logs why", %{tmp_dir: dir} do
    path = Path.join(dir, "bad.toml")
    File.write!(path, ~s([queue]\ndirectory = "relative"\n))

    log =
      capture_log(fn ->
        assert {:error, {:invalid_config, [_]}} =
                 Sovite.Core.Supervisor.start_link(config_path: path)
      end)

    assert log =~
             ~s(invalid configuration in #{path}: queue.directory: "relative" is not an absolute path)
  end
end
