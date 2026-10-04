defmodule Sovite.Core.SupervisorTest do
  # Changes global logger configuration and the stored config.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Sovite.Core.{Config, Telemetry}
  alias Sovite.Core.Logging.FileHandler
  alias Sovite.Queue.Spool
  alias Sovite.Test.SMTPClient

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

  # A config with the queue in the test directory and no listeners, unless
  # `top` (top-level keys) defines some.
  defp toml(dir, rest, top \\ "listener = []") do
    """
    #{top}
    [server]
    hostname = "mx.example.org"
    [queue]
    directory = "#{Path.join(dir, "queue")}"
    #{rest}
    """
  end

  defp listener_port(supervisor) do
    {_id, listener, _type, _modules} =
      supervisor
      |> Supervisor.which_children()
      |> Enum.find(&match?({{Sovite.Listener, _}, _, _, _}, &1))

    {:ok, {_ip, port}} = Sovite.Listener.sockname(listener)
    port
  end

  test "starts with a valid config file and stores the config", %{tmp_dir: dir} do
    path = Path.join(dir, "sovite.toml")
    File.write!(path, toml(dir, ~s([log]\nlevel = "warning")))

    pid = start_supervised!({Sovite.Core.Supervisor, config_path: path, name: nil})

    assert Process.alive?(pid)
    assert Config.get().server.hostname == "mx.example.org"
    assert Logger.level() == :warning
  end

  test "writes logs to files when log.directory is set", %{tmp_dir: dir} do
    logs = Path.join(dir, "logs")

    {:ok, config} =
      Config.parse(
        toml(dir, """
        [log]
        directory = "#{logs}"
        file_name = "mta.{n}.log"
        symlink = "current.log"
        """)
      )

    start_supervised!({Sovite.Core.Supervisor, config: config, name: nil})
    :ok = FileHandler.sync(:sovite_file)

    assert File.read!(Path.join(logs, "current.log")) =~ "[info] sovite started on mx.example.org"

    stop_supervised!(Sovite.Core.Supervisor)
    assert {:error, {:not_found, :sovite_file}} = :logger.get_handler_config(:sovite_file)
  end

  test "accepts an already validated config", %{tmp_dir: dir} do
    {:ok, config} = Config.parse(toml(dir, ""))
    start_supervised!({Sovite.Core.Supervisor, config: config, name: nil})

    assert Config.get().server.hostname == "mx.example.org"
  end

  test "receives mail on its listeners and spools it", %{tmp_dir: dir} do
    {:ok, config} =
      Config.parse(
        toml(dir, ~s([domains]\nlocal = ["example.com"]), """
        [[listener]]
        address = "127.0.0.1"
        port = 0
        """)
      )

    supervisor = start_supervised!({Sovite.Core.Supervisor, config: config, name: nil})
    {:ok, client} = SMTPClient.connect(listener_port(supervisor))

    assert {:ok, {250, ["2.0.0 Ok: queued as " <> queue_id]}} =
             SMTPClient.send_message(
               client,
               "a@example.net",
               ["b@example.com"],
               "Subject: hi\r\n\r\nhello\r\n"
             )

    path = Path.join([dir, "queue", "incoming", queue_id])
    assert {:ok, envelope, offset} = Spool.read(path)
    assert envelope.recipients == ["b@example.com"]

    message = path |> File.read!() |> binary_part(offset, File.stat!(path).size - offset)

    assert message =~
             ~r/\AReceived: from client.test \(\[127.0.0.1\]\)\r\n\tby mx.example.org with ESMTP id #{queue_id}\r\n/

    assert String.ends_with?(message, "\r\nSubject: hi\r\n\r\nhello\r\n")
  end

  test "refuses to start without a usable queue directory", %{tmp_dir: dir} do
    File.write!(Path.join(dir, "queue"), "a file, not a directory")
    {:ok, config} = Config.parse(toml(dir, ""))

    capture_log(fn ->
      assert {:error, {:queue_directory, :enotdir}} =
               Sovite.Core.Supervisor.start_link(config: config, name: nil)
    end)
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
