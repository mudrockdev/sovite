defmodule Sovite.Core.SupervisorTest do
  # Changes global logger configuration and the stored config.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Sovite.Core.{Config, Repo, Telemetry}
  alias Sovite.Core.Logging.FileHandler
  alias Sovite.Core.Repo.Tables.Users
  alias Sovite.Queue.Spool
  alias Sovite.Test.{Certs, FakeDNS, FakeMTA, SMTPClient}

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
    [database]
    path = "#{Path.join(dir, "sovite.db")}"
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

    handler_id = "supervisor-test-#{System.unique_integer([:positive])}"
    event = [:sovite, :queue, :message, :deferred]
    test = self()

    :telemetry.attach(handler_id, event, &__MODULE__.forward_event/4, test)
    on_exit(fn -> :telemetry.detach(handler_id) end)

    supervisor = start_supervised!({Sovite.Core.Supervisor, config: config, name: nil})
    {:ok, client} = SMTPClient.connect(listener_port(supervisor))

    assert {:ok, {250, ["2.0.0 Ok: queued as " <> queue_id]}} =
             SMTPClient.send_message(
               client,
               "a@example.net",
               ["b@example.com"],
               "Subject: hi\r\n\r\nhello\r\n"
             )

    # The queue manager picks the message up at once. Local delivery comes
    # in a later phase, so mail for a local domain is deferred.
    assert_receive {:deferred, %{queue_id: ^queue_id}}, 5_000
    path = Path.join([dir, "queue", "deferred", queue_id])
    assert {:ok, loaded} = Spool.load(path)
    assert loaded.envelope.recipients == ["b@example.com"]

    assert [{:recipient, "b@example.com", :deferred, %{status: "4.3.2"}}, {:retry, 1, _}] =
             loaded.records

    message = path |> File.read!() |> binary_part(loaded.message_offset, loaded.message_size)

    assert message =~
             ~r/\AReceived: from client.test \(\[127.0.0.1\]\)\r\n\tby mx.example.org with ESMTP id #{queue_id}\r\n/

    assert String.ends_with?(message, "\r\nSubject: hi\r\n\r\nhello\r\n")
  end

  test "relays mail from trusted clients to remote servers", %{tmp_dir: dir} do
    {:ok, mta} = FakeMTA.start_link()

    {:ok, config} =
      Config.parse(
        toml(dir, ~s([smtp]\ntrusted_networks = ["127.0.0.1"]), """
        [[listener]]
        address = "127.0.0.1"
        port = 0
        """)
      )

    resolver =
      FakeDNS.resolver(%{
        {"example.net", :mx} => [{10, "mx.example.net"}],
        {"mx.example.net", :a} => [{127, 0, 0, 1}]
      })

    supervisor =
      start_supervised!(
        {Sovite.Core.Supervisor,
         config: config, name: nil, queue_manager: [resolver: resolver, port: FakeMTA.port(mta)]}
      )

    {:ok, client} = SMTPClient.connect(listener_port(supervisor))

    assert {:ok, {250, ["2.0.0 Ok: queued as " <> queue_id]}} =
             SMTPClient.send_message(
               client,
               "a@example.org",
               ["b@example.net"],
               "Subject: hi\r\n\r\nhello\r\n"
             )

    assert_receive {:fake_mta, ^mta, {:message, message}}, 5_000
    assert message.rcpt_to == ["b@example.net"]
    assert message.data =~ ~r/\AReceived: from client.test .* id #{queue_id}\r\n/s
    assert String.ends_with?(message.data, "\r\nSubject: hi\r\n\r\nhello\r\n")
  end

  test "serves authenticated submission over TLS and relays the fixed message", %{tmp_dir: dir} do
    {:ok, mta} = FakeMTA.start_link()
    ca = Certs.ca()
    {cert_file, key_file} = Certs.write!(dir, "mx", Certs.issue(ca, names: ["mx.example.org"]))

    {:ok, config} =
      Config.parse(
        toml(dir, "", """
        [[listener]]
        address = "127.0.0.1"
        port = 0
        mode = "submission"
        [[tls.certificate]]
        cert_file = "#{cert_file}"
        key_file = "#{key_file}"
        [auth]
        failure_delay = 1
        """)
      )

    resolver =
      FakeDNS.resolver(%{
        {"example.net", :mx} => [{10, "mx.example.net"}],
        {"mx.example.net", :a} => [{127, 0, 0, 1}]
      })

    supervisor =
      start_supervised!(
        {Sovite.Core.Supervisor,
         config: config, name: nil, queue_manager: [resolver: resolver, port: FakeMTA.port(mta)]}
      )

    repo = Repo.ref(config.database)
    {:ok, _} = Users.create(repo, "alice@example.org", "secret")

    {:ok, client} = SMTPClient.connect(listener_port(supervisor))
    {:ok, {220, _}} = SMTPClient.read_reply(client)
    {:ok, {250, lines}} = SMTPClient.command(client, "EHLO client.test")
    assert "STARTTLS" in lines
    refute Enum.any?(lines, &String.starts_with?(&1, "AUTH"))
    assert {:ok, {530, _}} = SMTPClient.command(client, "MAIL FROM:<alice@example.org>")

    tls = Sovite.TLS.client_options(verify: :peer, hostname: "mx.example.org", cacerts: [ca.cert])
    {:ok, client} = SMTPClient.starttls(client, tls)
    {:ok, {250, lines}} = SMTPClient.command(client, "EHLO client.test")
    assert "AUTH SCRAM-SHA-256 PLAIN LOGIN" in lines

    assert {:ok, {235, _}} =
             SMTPClient.command(
               client,
               "AUTH PLAIN " <> Base.encode64("\0alice@example.org\0secret")
             )

    assert {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<alice@example.org>")
    assert {:ok, {250, _}} = SMTPClient.command(client, "RCPT TO:<bob@example.net>")
    assert {:ok, {354, _}} = SMTPClient.command(client, "DATA")
    assert {:ok, {250, _}} = SMTPClient.send_data(client, "Subject: hi\r\n\r\nhello\r\n")

    assert_receive {:fake_mta, ^mta, {:message, message}}, 5_000
    assert message.data =~ "with ESMTPSA id"
    assert message.data =~ "(using TLSv1.3 with cipher"

    assert message.data =~
             ~r/\r\nSubject: hi\r\nDate: .+\r\nMessage-ID: <.+@mx.example.org>\r\n\r\nhello\r\n\z/
  end

  def forward_event(_event, _measurements, metadata, pid), do: send(pid, {:deferred, metadata})

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
