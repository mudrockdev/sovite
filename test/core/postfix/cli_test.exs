defmodule Sovite.Core.CLI.MigrateTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias Sovite.Core.{CLI, Config}

  @moduletag :tmp_dir

  @fixtures Path.expand("../../fixtures/postfix", __DIR__)

  defp migrate(args), do: run_cli(["migrate", "postfix" | args])

  defp run_cli(args, input \\ "") do
    ref = make_ref()
    parent = self()

    stdout =
      capture_io(input, fn ->
        stderr = capture_io(:stderr, fn -> send(parent, {ref, CLI.run(args)}) end)
        send(parent, {ref, :stderr, stderr})
      end)

    assert_received {^ref, status}
    assert_received {^ref, :stderr, stderr}
    {status, stdout, stderr}
  end

  defp fixture(name, output) do
    root = Path.join(@fixtures, name)
    migrate([Path.join(root, "etc/postfix"), "--root", root, "--output", output])
  end

  # The commands of import.sh, unquoted: argument lists, or
  # {:stdin, password, args}.
  defp script_commands(script) do
    for line <- String.split(script, "\n"),
        command = script_command(line),
        command != nil,
        do: command
  end

  defp script_command(~s("$sovitectl" ) <> rest), do: unquote_args(rest)

  defp script_command("printf '%s\\n' " <> rest) do
    [password, command] = String.split(rest, ~s( | "$sovitectl" ), parts: 2)
    [password] = unquote_args(password)
    {:stdin, password, unquote_args(command)}
  end

  defp script_command(_line), do: nil

  defp unquote_args(text) do
    for [_, arg] <- Regex.scan(~r/'((?:[^']|'\\'')*)'/, text),
        do: String.replace(arg, ~S('\''), "'")
  end

  # Runs the commands of import.sh with the generated config and a
  # database in `dir`: each one must succeed.
  defp import!(dir, output) do
    config = Path.join(dir, "import.toml")
    database = ~s(\n[database]\npath = "#{Path.join(dir, "sovite.db")}"\n)
    File.write!(config, File.read!(Path.join(output, "sovite.toml")) <> database)

    for command <- script_commands(File.read!(Path.join(output, "import.sh"))) do
      {args, input} =
        case command do
          {:stdin, password, args} -> {args, password <> "\n"}
          args -> {args, ""}
        end

      {status, _stdout, stderr} = run_cli(["--config", config | args], input)
      assert status == 0, "#{Enum.join(args, " ")} failed: #{stderr}"
    end

    config
  end

  test "a stock Postfix, Rspamd, and Dovecot setup", %{tmp_dir: dir} do
    output = Path.join(dir, "out")
    assert {0, stdout, ""} = fixture("stock", output)
    assert stdout =~ "Needs attention"
    assert stdout =~ "Wrote #{output}/sovite.toml, import.sh, and report.txt"

    assert File.stat!(Path.join(output, "sovite.toml")).mode |> Bitwise.band(0o777) == 0o600
    assert File.stat!(Path.join(output, "import.sh")).mode |> Bitwise.band(0o777) == 0o600
    assert File.read!(Path.join(output, "report.txt")) <> "Wrote" =~ "Postfix migration report"

    assert {:ok, config} = Config.load(Path.join(output, "sovite.toml"))
    assert config.server.hostname == "mail.example.com"
    assert config.domains.hosted == ["example.com", "example.org"]
    assert config.domains.local == ["mail.example.com", "localhost.example.com", "localhost"]
    assert config.auth.backend == :dovecot
    assert config.auth.dovecot.socket == "/var/spool/postfix/private/auth"
    assert config.routing.extension_delimiter == "+"
    assert config.smtp.max_message_size == 52_428_800
    assert {{127, 0, 0, 0}, 8} in config.smtp.trusted_networks

    assert config.routing.mailbox_transport ==
             %{transport: :lmtp, nexthop: {:unix, "/var/spool/postfix/private/dovecot-lmtp"}}

    assert config.tls.certificate == [
             %{
               cert_file: "/etc/letsencrypt/live/mail.example.com/fullchain.pem",
               key_file: "/etc/letsencrypt/live/mail.example.com/privkey.pem"
             }
           ]

    ports = for l <- config.listener, uniq: true, do: {l.port, l.mode, l.require_auth}
    assert ports == [{25, :smtp, false}, {587, :submission, true}, {465, :submissions, true}]

    assert [%{name: "inet:localhost:11332", default_action: :accept}] = config.milter

    assert config.restrictions.rcpt == [
             "permit_trusted",
             "permit_authenticated",
             "require_known_recipient_domain",
             "check_policy_service spawn:/usr/bin/policyd-spf"
           ]

    report = File.read!(Path.join(output, "report.txt"))
    assert report =~ "auth.dovecot.socket = \"/var/spool/postfix/private/auth\" is inside"
    assert report =~ "/var/spool/postfix/private/dovecot-lmtp is inside"
    assert report =~ "user=policyd-spf is not supported"
    assert report =~ "|/usr/local/bin/backup-mail: commands are not supported"

    script = File.read!(Path.join(output, "import.sh"))
    commands = script_commands(script)
    assert ["alias", "add", "postmaster", "root@mail.example.com"] in commands

    assert ["alias", "add", "sales@example.com", "alice@example.com", "bob@example.org"] in commands

    assert ["mailbox", "add", "alice@example.com"] in commands

    config_path = import!(dir, output)
    assert {0, aliases, _} = data(config_path, ["alias", "list"])
    assert aliases =~ "sales@example.com  -> alice@example.com, bob@example.org"
    assert {0, mailboxes, _} = data(config_path, ["mailbox", "list"])
    assert mailboxes =~ "bob@example.org"
  end

  test "amavis, postscreen, a relay host, and lookup tables", %{tmp_dir: dir} do
    output = Path.join(dir, "out")
    assert {0, _stdout, ""} = fixture("amavis", output)
    assert {:ok, config} = Config.load(Path.join(output, "sovite.toml"))

    assert config.smtp.content_filter == "smtp:[127.0.0.1]:10024"
    assert config.smtp.xforward_networks == [{{127, 0, 0, 0}, 8}]
    assert config.delivery.relayhost == %{host: "smtp.provider.example", port: 587, mx: false}
    assert config.delivery.relayhost_username == "relayuser"
    assert config.delivery.relayhost_password == "s3cret'pass"
    assert config.delivery.tls == :encrypt
    assert config.delivery.ip_versions == [:ipv4]
    assert config.screen.threshold == 3
    assert [%{zone: "zen.spamhaus.org", weight: 3} | _] = config.screen.dnsbl
    assert config.queue.max_lifetime == 3 * 86_400_000
    assert config.domains.relay == ["backup.example.com"]
    assert config.sendmail.origin == "example.net"

    assert config.pipe["procmail"].command == [
             "/usr/bin/procmail",
             "-a",
             "{extension}",
             "-d",
             "{user}"
           ]

    reinjection = Enum.find(config.listener, & &1.reinjection)
    assert reinjection.port == 10_025
    assert reinjection.content_filter == nil
    assert reinjection.milters == []

    submission = Enum.find(config.listener, &(&1.mode == :submission))
    assert submission.content_filter == "smtp:[127.0.0.1]:10026"

    report = File.read!(Path.join(output, "report.txt"))
    assert report =~ "qmqpd(8)"
    assert report =~ "Before-queue content filters are not supported"
    assert report =~ "Not migrated: [backup.provider.example]:587"

    config_path = import!(dir, output)
    assert {0, relays, _} = data(config_path, ["sender-relay", "list"])
    assert relays =~ "@sales.example.net  relayhost [smtp.sales.example]:587, login salesuser"
    assert {0, access, _} = data(config_path, ["access", "list"])
    assert access =~ "client  192.0.2.66  REJECT Spammer"
    assert {0, transports, _} = data(config_path, ["transport", "list"])
    assert transports =~ "lists.example.net  pipe:procmail"
  end

  defp data(config, args), do: run_cli(["--config", config | args])

  test "existing files are kept unless --force", %{tmp_dir: dir} do
    output = Path.join(dir, "out")
    File.mkdir_p!(output)
    File.write!(Path.join(output, "report.txt"), "mine")

    assert {1, "", stderr} = fixture("stock", output)
    assert stderr =~ "report.txt already exists in #{output}: use --force"
    assert File.read!(Path.join(output, "report.txt")) == "mine"

    root = Path.join(@fixtures, "stock")

    assert {0, _, ""} =
             migrate([
               Path.join(root, "etc/postfix"),
               "--root",
               root,
               "--output",
               output,
               "--force"
             ])

    assert File.read!(Path.join(output, "report.txt")) =~ "Postfix migration report"
  end

  test "without master.cf, or main.cf", %{tmp_dir: dir} do
    postfix = Path.join(dir, "postfix")
    File.mkdir_p!(postfix)
    output = Path.join(dir, "out")

    assert {1, "", stderr} = migrate([postfix, "--output", output])
    assert stderr =~ "cannot read #{postfix}/main.cf"

    File.write!(Path.join(postfix, "main.cf"), "myhostname = mx.example.com\n")
    assert {0, stdout, ""} = migrate([postfix, "--output", output])
    assert stdout =~ "There is no master.cf"
  end

  test "the default directory is under --root", %{tmp_dir: dir} do
    root = Path.join(@fixtures, "stock")
    assert {0, _, ""} = migrate(["--root", root, "--output", dir])
    assert File.exists?(Path.join(dir, "sovite.toml"))
  end

  test "usage errors" do
    for args <- [["a", "b"], ["--bogus"]] do
      stderr = capture_io(:stderr, fn -> assert CLI.run(["migrate", "postfix" | args]) == 64 end)
      assert stderr =~ "migrate postfix [DIR]"
    end

    capture_io(:stderr, fn -> assert CLI.run(["migrate", "exim"]) == 64 end)
  end
end
