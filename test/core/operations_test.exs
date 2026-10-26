defmodule Sovite.Core.OperationsTest do
  # The admin API, sovitectl against a running server, reloads, metrics,
  # and draining. Changes global logger configuration and the stored
  # config.
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Sovite.Core.{CLI, Control, Telemetry}
  alias Sovite.Core.Logging.FileHandler
  alias Sovite.Queue.Spool
  alias Sovite.Test.{FakeDNS, FakeHTTP, SMTPClient, TelemetryForwarder}

  @moduletag :tmp_dir
  @moduletag :capture_log

  setup %{tmp_dir: dir} do
    level = Logger.level()
    handler = :logger.get_handler_config(:default)

    on_exit(fn ->
      Logger.configure(level: level)
      Telemetry.detach_logger()

      with {:ok, %{formatter: formatter}} <- handler do
        :logger.update_handler_config(:default, :formatter, formatter)
      end
    end)

    %{dir: dir, path: Path.join(dir, "sovite.toml"), admin_port: free_port()}
  end

  defp free_port do
    {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    port
  end

  defp toml(context, extra \\ "") do
    """
    [server]
    hostname = "mx.example.org"
    shutdown_timeout = "2s"
    [queue]
    directory = "#{Path.join(context.dir, "queue")}"
    [database]
    path = "#{Path.join(context.dir, "sovite.db")}"
    [dns]
    dnssec = "off"
    [domains]
    local = ["example.com"]
    [admin]
    port = #{context.admin_port}
    token_file = "#{Path.join(context.dir, "admin.token")}"
    [log]
    directory = "#{Path.join(context.dir, "log")}"
    [[listener]]
    address = "127.0.0.1"
    port = 0
    #{extra}
    """
  end

  defp start_mta(context, extra \\ "") do
    File.write!(context.path, toml(context, extra))

    supervisor =
      start_supervised!(
        {Sovite.Core.Supervisor,
         config_path: context.path, name: nil, queue_manager: [resolver: FakeDNS.resolver(%{})]}
      )

    Map.merge(context, %{
      supervisor: supervisor,
      token: File.read!(token_file(context)) |> String.trim()
    })
  end

  defp token_file(context), do: Path.join(context.dir, "admin.token")

  defp child(supervisor, match) do
    Enum.find_value(Supervisor.which_children(supervisor), fn {id, pid, _type, _modules} ->
      match.(id) && pid
    end)
  end

  defp smtp_listener(supervisor),
    do: child(supervisor, &match?({Sovite.Listener, "smtp/" <> _}, &1))

  defp smtp_port(supervisor) do
    {:ok, {_ip, port}} = supervisor |> smtp_listener() |> Sovite.Listener.sockname()
    port
  end

  defp control(supervisor), do: child(supervisor, &(&1 == Control))

  defp http(context, method, path, token \\ :default) do
    token = if token == :default, do: context.token, else: token

    headers =
      if token, do: [{~c"authorization", ~c"Bearer " ++ String.to_charlist(token)}], else: []

    url = ~c"http://127.0.0.1:#{context.admin_port}#{path}"

    request =
      if method == :post, do: {url, headers, ~c"application/json", ""}, else: {url, headers}

    {:ok, {{_, status, _}, _headers, body}} =
      :httpc.request(method, request, [], body_format: :binary)

    {status, body}
  end

  defp cli(context, args), do: CLI.run(["--config", context.path | args])

  defp send_mail(context, recipients \\ ["bob@example.com"]) do
    {:ok, client} = SMTPClient.connect(smtp_port(context.supervisor))

    {:ok, {250, ["2.0.0 Ok: queued as " <> id]}} =
      SMTPClient.send_message(
        client,
        "alice@example.net",
        recipients,
        "Message-ID: <ops@example.net>\r\nSubject: ops\r\n\r\nhello\r\n"
      )

    SMTPClient.close(client)
    id
  end

  # Local delivery is not configured: the message is deferred.
  defp wait_deferred(context, id) do
    path = Spool.path(Path.join(context.dir, "queue"), :deferred, id)
    wait_until(fn -> File.exists?(path) end)
  end

  defp wait_until(fun, attempts \\ 300) do
    cond do
      fun.() -> :ok
      attempts > 0 -> Process.sleep(10) && wait_until(fun, attempts - 1)
      true -> flunk("condition not met in time")
    end
  end

  describe "parts of the stack" do
    test "a node without the MTA opens no MTA port, and still runs the admin API", context do
      context = start_mta(context, "[stack]\nmta = false")

      # No listener, queue manager, or other MTA process.
      assert Control.listener_connections(context.supervisor) == []

      refute Enum.any?(Supervisor.which_children(context.supervisor), fn {id, _, _, _} ->
               id in [Sovite.Core.MTA.QueueManager, Sovite.Core.Repo.Tables.DomainCache]
             end)

      assert {200, body} = http(context, :get, "/api/status")
      status = JSON.decode!(body)
      assert status["stack"] == %{"mta" => false, "filter" => true, "mailbox" => true}
      refute Map.has_key?(status, "queue")

      assert {404, body} = http(context, :get, "/api/queue")
      assert JSON.decode!(body)["error"] =~ "the MTA is off"

      assert {200, metrics} = http(context, :get, "/metrics")
      refute metrics =~ "sovite_queue_messages"

      output = capture_io(fn -> assert cli(context, ["status"]) == 0 end)
      assert output =~ "parts: filter, mailbox"
      refute output =~ "queue:"

      # Turning a part on or off needs a restart.
      File.write!(context.path, toml(context, "[stack]\nmta = true"))

      assert {:error, {:restart_required, ["stack"]}} =
               Control.reload(control(context.supervisor))
    end
  end

  describe "web server" do
    test "needs the token, and serves status, config, and metrics", context do
      context = start_mta(context)
      assert Bitwise.band(File.stat!(token_file(context)).mode, 0o777) == 0o600

      assert {401, _} = http(context, :get, "/api/status", nil)
      assert {401, _} = http(context, :get, "/api/status", "wrong-token-wrong-token")
      assert {401, _} = http(context, :get, "/metrics", nil)

      assert {200, body} = http(context, :get, "/api/status")

      assert %{
               "hostname" => "mx.example.org",
               "queue" => %{"deferred" => 0},
               "listeners" => listeners
             } =
               JSON.decode!(body)

      assert Enum.any?(listeners, &String.starts_with?(&1["id"], "smtp/"))

      assert {200, body} = http(context, :get, "/api/config")
      assert ["admin.port", "#{context.admin_port}", false] in JSON.decode!(body)["settings"]

      id = send_mail(context)
      wait_deferred(context, id)
      assert {200, metrics} = http(context, :get, "/metrics")
      assert metrics =~ "sovite_messages_received_total 1"
      assert metrics =~ ~s(sovite_queue_messages{queue="deferred"} 1)
      assert metrics =~ "sovite_build_info{version="

      assert {200, body} = http(context, :get, "/api/queue?queue=deferred")
      assert [%{"queue_id" => ^id}] = JSON.decode!(body)["messages"]
      assert {200, body} = http(context, :get, "/api/queue/#{id}")
      assert %{"message_id" => "<ops@example.net>"} = JSON.decode!(body)
      assert {404, _} = http(context, :get, "/api/queue/8CrIr95AD2x90M")
      assert {400, _} = http(context, :get, "/api/queue?queue=nope")
      assert {400, _} = http(context, :get, "/api/queue?limit=0")

      assert {200, body} = http(context, :get, "/api/route?address=bob@example.com")

      assert %{"class" => "local", "recipients" => [%{"transport" => "local"}]} =
               JSON.decode!(body)

      assert {400, _} = http(context, :get, "/api/route")

      :ok = FileHandler.sync(:sovite_file)
      assert {200, body} = http(context, :get, "/api/trace?id=%3Cops@example.net%3E")

      assert %{"queue_ids" => [^id], "lines" => [_ | _], "queued" => [%{"queue" => "deferred"}]} =
               JSON.decode!(body)

      assert {404, _} = http(context, :get, "/api/nothing")
      assert {405, _} = http(context, :delete, "/api/status")
    end
  end

  describe "sovitectl" do
    test "cluster and IP pool commands on a server that is not clustered", context do
      context =
        start_mta(context, """
        [[ip_pool]]
        name = "main"
        [[ip_pool.address]]
        address = "127.0.0.2"
        helo = "out.example.org"
        daily_limit = 100
        """)

      assert {200, body} = http(context, :get, "/api/cluster")
      assert JSON.decode!(body) == %{"enabled" => false}

      assert {200, body} = http(context, :get, "/api/ip_pools")

      assert %{"pools" => [%{"name" => "main", "addresses" => [address]}]} = JSON.decode!(body)
      assert address["sent_today"] == 0
      assert address["limit_today"] == 100

      assert {200, metrics} = http(context, :get, "/metrics")
      assert metrics =~ ~r/sovite_ip_pool_sent_today\{[^}]*address="127.0.0.2"[^}]*\} 0/
      assert metrics =~ ~r/sovite_ip_pool_limit_today\{[^}]*pool="main"[^}]*\} 100/
      refute metrics =~ "sovite_cluster_nodes{"

      assert capture_io(fn -> assert cli(context, ["cluster", "status"]) == 0 end) =~
               "the cluster is not enabled"

      assert capture_io(fn -> assert cli(context, ["ip-pool", "status"]) == 0 end) =~
               ~r/main\n  127.0.0.2 +0\/100/

      file = Path.join(context.dir, "shared.toml")
      File.write!(file, "")

      for args <- [
            ["cluster", "config", "push", file],
            ["cluster", "leave"],
            ["cluster", "join", "b@h:1"]
          ] do
        assert capture_io(:stderr, fn -> assert cli(context, args) == 1 end) =~
                 "the cluster is not enabled"
      end

      assert capture_io(:stderr, fn ->
               assert cli(context, ["cluster", "config", "push", "/nonexistent"]) == 1
             end) =~ "cannot read /nonexistent"

      assert capture_io(:stderr, fn -> assert cli(context, ["cluster", "nope"]) == 64 end) =~
               "Usage"

      assert {409, _} = http(context, :post, "/api/cluster/config")
    end

    test "lists, shows, holds, releases, and deletes queued messages", context do
      context = start_mta(context)
      id = send_mail(context)
      wait_deferred(context, id)
      queue = Path.join(context.dir, "queue")

      output = capture_io(fn -> assert cli(context, ["queue", "list"]) == 0 end)
      assert output =~ id
      assert output =~ "local delivery is not configured"
      assert capture_io(fn -> assert cli(context, ["queue", "list", "hold"]) == 0 end) =~ "empty"

      output = capture_io(fn -> assert cli(context, ["queue", "show", id]) == 0 end)
      assert output =~ "Message-ID:     <ops@example.net>"
      assert output =~ "bob@example.com  deferred"

      assert capture_io(fn -> assert cli(context, ["queue", "hold", id]) == 0 end) ==
               "#{id}: held\n"

      assert File.exists?(Spool.path(queue, :hold, id))

      assert capture_io(fn -> assert cli(context, ["queue", "release", id]) == 0 end) =~
               "released"

      assert File.exists?(Spool.path(queue, :deferred, id))
      assert capture_io(fn -> assert cli(context, ["queue", "flush", id]) == 0 end) =~ "retrying"
      wait_deferred(context, id)
      assert capture_io(fn -> assert cli(context, ["queue", "flush"]) == 0 end) =~ "flushed"
      wait_deferred(context, id)

      assert capture_io(fn ->
               assert capture_io(:stderr, fn ->
                        assert cli(context, ["queue", "delete", id, "8CrIr95AD2x90M"]) == 1
                      end) =~
                        "8CrIr95AD2x90M: no such message"
             end) =~ "#{id}: deleted"

      refute File.exists?(Spool.path(queue, :deferred, id))

      assert capture_io(:stderr, fn -> assert cli(context, ["queue", "show", id]) == 1 end) =~
               "no such message"
    end

    test "status, route, trace, and report", context do
      context = start_mta(context)
      id = send_mail(context)
      wait_deferred(context, id)
      :ok = FileHandler.sync(:sovite_file)

      output = capture_io(fn -> assert cli(context, ["status"]) == 0 end)
      assert output =~ "sovite #{Mix.Project.config()[:version]} on mx.example.org"
      assert output =~ "1 deferred"

      output = capture_io(fn -> assert cli(context, ["route", "bob@example.com"]) == 0 end)
      assert output =~ "bob@example.com: deliver via local"

      output = capture_io(fn -> assert cli(context, ["trace", "<ops@example.net>"]) == 0 end)
      assert output =~ "event=smtp.message.accepted"
      assert output =~ "#{id} is still in the deferred queue"

      output =
        capture_io(fn ->
          assert cli(context, ["report", "--top", "3", "--date", "today"]) == 0
        end)

      assert output =~ ~r/\s+1   received/

      for args <- [["report", "--top", "x"], ["report", "--date", "someday"]] do
        capture_io(:stderr, fn -> assert cli(context, args) == 1 end)
      end
    end

    test "commands that need the server say when it is not running", context do
      File.write!(context.path, toml(context))
      File.write!(token_file(context), String.duplicate("x", 32))

      assert capture_io(:stderr, fn -> assert cli(context, ["status"]) == 3 end) =~ "not running"

      assert capture_io(:stderr, fn ->
               assert cli(context, ["queue", "hold", "8CrIr95AD2x90M"]) == 1
             end) =~
               "not running"

      File.rm!(token_file(context))

      assert capture_io(:stderr, fn -> assert cli(context, ["config", "reload"]) == 1 end) =~
               "does not exist"
    end

    test "config show and diff", context do
      File.write!(context.path, toml(context))
      other = Path.join(context.dir, "other.toml")
      File.write!(other, toml(context, "[smtp]\nmax_recipients = 5"))

      output = capture_io(fn -> assert cli(context, ["config", "show", "-n"]) == 0 end)
      assert output =~ ~s(server.hostname = "mx.example.org"\n)
      refute output =~ "smtp.max_message_size"

      assert capture_io(fn -> assert cli(context, ["config", "show"]) == 0 end) =~
               ~s(smtp.max_message_size = "25M")

      assert capture_io(fn ->
               assert cli(context, ["config", "diff", context.path, other]) == 0
             end) ==
               "- smtp.max_recipients = 100\n+ smtp.max_recipients = 5\n"

      assert capture_io(fn -> assert cli(context, ["config", "diff", other, other]) == 0 end) ==
               "no differences\n"

      File.write!(other, "[log]\nlevel = 1")
      capture_io(:stderr, fn -> assert cli(context, ["config", "show", other]) == 1 end)
    end
  end

  describe "reload" do
    test "applies a new config without restarting listeners", context do
      context = start_mta(context)
      listener = smtp_listener(context.supervisor)
      web = child(context.supervisor, &match?({Plug.Cowboy, _}, &1))
      assert is_pid(web)
      TelemetryForwarder.attach([[:sovite, :config, :reloaded]])

      File.write!(context.path, toml(context, "[smtp]\nmax_recipients = 1"))
      output = capture_io(fn -> assert cli(context, ["config", "diff"]) == 0 end)
      assert output == "- smtp.max_recipients = 100\n+ smtp.max_recipients = 1\n"
      assert capture_io(fn -> assert cli(context, ["config", "reload"]) == 0 end) =~ "reloaded"

      assert_receive {:telemetry, [:sovite, :config, :reloaded], _, %{changed: changed}}
      assert Enum.any?(changed, &(&1 =~ "smtp/"))
      assert smtp_listener(context.supervisor) == listener
      # The web server reads the config per request: not restarted.
      assert child(context.supervisor, &match?({Plug.Cowboy, _}, &1)) == web

      assert capture_io(fn -> assert cli(context, ["config", "diff"]) == 0 end) ==
               "no differences\n"

      {:ok, client} = SMTPClient.connect(smtp_port(context.supervisor))
      {:ok, {220, _}} = SMTPClient.read_reply(client)
      {:ok, {250, _}} = SMTPClient.command(client, "EHLO c.test")
      {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<a@example.net>")
      {:ok, {250, _}} = SMTPClient.command(client, "RCPT TO:<b@example.com>")
      assert {:ok, {452, _}} = SMTPClient.command(client, "RCPT TO:<c@example.com>")

      assert %{last_reload: %{result: "ok"}} = Control.status(control(context.supervisor))
    end

    test "an invalid file or one that needs a restart changes nothing", context do
      context = start_mta(context)
      control = control(context.supervisor)

      File.write!(context.path, toml(context, "[smtp]\nmax_recipients = 0"))

      stderr = capture_io(:stderr, fn -> assert cli(context, ["config", "reload"]) == 1 end)
      assert stderr =~ "smtp.max_recipients"
      assert {:error, [_ | _]} = Control.reload(control)
      assert %{last_reload: %{result: "smtp.max_recipients" <> _}} = Control.status(control)

      File.write!(context.path, String.replace(toml(context), "sovite.db", "other.db"))
      assert {:error, {:restart_required, ["database"]}} = Control.reload(control)

      assert capture_io(:stderr, fn -> assert cli(context, ["config", "reload"]) == 1 end) =~
               "need a restart: database"
    end

    test "starts new listeners and drains removed ones", context do
      context = start_mta(context)
      control = control(context.supervisor)
      port = free_port()

      extra = "[[listener]]\naddress = \"127.0.0.1\"\nport = #{port}\nmode = \"lmtp\""
      File.write!(context.path, toml(context, extra))
      assert Control.reload(control) == :ok
      assert {:ok, client} = SMTPClient.connect(port)
      assert {:ok, {220, ["mx.example.org LMTP"]}} = SMTPClient.read_reply(client)

      File.write!(context.path, toml(context))
      assert Control.reload(control) == :ok
      assert {:ok, {421, _}} = SMTPClient.read_reply(client)

      wait_until(fn ->
        child(context.supervisor, &match?({Sovite.Listener, "lmtp/" <> _}, &1)) == nil
      end)

      assert {:error, :econnrefused} = :gen_tcp.connect(~c"127.0.0.1", port, [])
    end

    test "restarts other children with their new options", context do
      context = start_mta(context)
      metrics = child(context.supervisor, &match?({Sovite.Metrics, _}, &1))
      assert is_pid(metrics)

      File.write!(context.path, toml(context, "[metrics]\nenabled = false"))
      assert Control.reload(control(context.supervisor)) == :ok
      assert child(context.supervisor, &match?({Sovite.Metrics, _}, &1)) == nil
      assert {404, _} = http(context, :get, "/metrics")
    end

    test "SIGHUP-style reloads come in as messages", context do
      context = start_mta(context)
      control = control(context.supervisor)
      TelemetryForwarder.attach([[:sovite, :config, :reloaded]])

      send(control, :sighup)
      assert_receive {:telemetry, [:sovite, :config, :reloaded], _, %{changed: []}}
    end
  end

  describe "drain" do
    test "idle sessions get 421 when the server stops", context do
      context = start_mta(context)
      TelemetryForwarder.attach([[:sovite, :server, :drain, :stop]])

      {:ok, client} = SMTPClient.connect(smtp_port(context.supervisor))
      {:ok, {220, _}} = SMTPClient.read_reply(client)

      stop_supervised!(Sovite.Core.Supervisor)

      assert {:ok, {421, ["4.3.2 mx.example.org Service shutting down"]}} =
               SMTPClient.read_reply(client)

      assert_receive {:telemetry, [:sovite, :server, :drain, :stop], %{connections: 0},
                      %{deliveries: :ok}}
    end

    test "status shows a drained server", context do
      context = start_mta(context)
      control = control(context.supervisor)
      assert Control.drain(control) == :ok
      assert %{draining: true} = Control.status(control)
      assert Sovite.Listener.sockname(smtp_listener(context.supervisor)) == {:error, :closed}
    end
  end

  describe "tracing" do
    test "exports the spans of a session and its deliveries", context do
      test = self()

      {:ok, collector} =
        FakeHTTP.start_link(fn %{path: "/v1/traces", body: body} ->
          send(test, {:spans, JSON.decode!(body)})
          {200, [], "{}"}
        end)

      endpoint = FakeHTTP.url(collector, "/v1/traces")
      context = start_mta(context, "[tracing]\nenabled = true\nendpoint = \"#{endpoint}\"")
      id = send_mail(context)
      wait_deferred(context, id)

      tracing = child(context.supervisor, &match?({Sovite.Tracing, _}, &1))
      :ok = Sovite.Tracing.flush(tracing)

      spans = collect_spans([])
      names = Enum.map(spans, & &1["name"])
      assert "smtp.session" in names or "smtp MAIL" in names
      assert "delivery" in names
      assert "smtp DATA" in names or "smtp END-OF-MESSAGE" in names
    end
  end

  defp collect_spans(acc) do
    receive do
      {:spans, %{"resourceSpans" => resources}} ->
        spans = for r <- resources, scope <- r["scopeSpans"], span <- scope["spans"], do: span
        collect_spans(acc ++ spans)
    after
      500 -> acc
    end
  end

  test "SIGHUP reaches the Control process" do
    alias Sovite.Core.Control.Signals
    :ok = Signals.install(self())
    :gen_event.notify(:erl_signal_server, :sighup)
    assert_receive :sighup
    Signals.remove(self())
    Signals.remove(self())
  end
end
