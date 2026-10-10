defmodule Sovite.Core.ConfigTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Config
  alias Sovite.DKIM.SigningKey

  @moduletag :tmp_dir

  test "fills in defaults for an empty file" do
    assert {:ok, config} = Config.parse("")
    assert config.queue.directory == "/var/spool/sovite"

    assert config.log == %{
             level: :info,
             format: :text,
             directory: nil,
             file_name: "sovite.{date}.{n}.log",
             date_format: "%Y-%m-%d",
             max_size: 100 * 1024 * 1024,
             rotation: :daily,
             max_files: 14,
             symlink: nil
           }

    assert is_binary(config.server.hostname)
  end

  test "parses a full config" do
    toml = """
    [server]
    hostname = "mail.example.com"

    [queue]
    directory = "/srv/sovite/queue"

    [log]
    level = "debug"
    format = "json"
    directory = "/var/log/sovite"
    file_name = "mta-{date}-{n}.log"
    date_format = "%Y%m%d"
    max_size = "512M"
    rotation = "hourly"
    max_files = 0
    symlink = "current.log"
    """

    assert {:ok, config} = Config.parse(toml)

    assert Map.take(config, [:server, :queue, :log]) == %{
             server: %{hostname: "mail.example.com", authserv_id: "mail.example.com"},
             queue: %{
               directory: "/srv/sovite/queue",
               max_lifetime: 5 * 86_400_000,
               min_backoff: 300_000,
               max_backoff: 3_600_000,
               delay_warning: nil
             },
             log: %{
               level: :debug,
               format: :json,
               directory: "/var/log/sovite",
               file_name: "mta-{date}-{n}.log",
               date_format: "%Y%m%d",
               max_size: 512 * 1024 * 1024,
               rotation: :hourly,
               max_files: 0,
               symlink: "current.log"
             }
           }
  end

  test "defaults to one SMTP listener and no relaying" do
    assert {:ok, config} = Config.parse(~s([server]\nhostname = "MX.Example.org"))
    assert [listener] = config.listener

    assert listener == %{
             address: {0, 0, 0, 0},
             port: 25,
             mode: :smtp,
             auth: false,
             require_tls: false,
             require_auth: false,
             tls_min_version: nil,
             tls_ciphers: nil
           }

    assert config.smtp.trusted_networks == []
    assert config.smtp.max_message_size == 25 * 1024 * 1024
    assert config.smtp.command_timeout == 300_000

    assert config.domains == %{
             local: ["mx.example.org"],
             relay: [],
             aliased: [],
             hosted: [],
             local_recipients: nil
           }
  end

  test "parses listeners, SMTP limits, and domains" do
    toml = """
    [[listener]]
    address = "::"
    port = 2525

    [[listener]]
    address = "192.0.2.1"

    [smtp]
    max_message_size = "50M"
    command_timeout = "30s"
    data_timeout = 600
    bare_line_endings = "normalize"
    trusted_networks = ["127.0.0.1", "192.0.2.0/24", "2001:db8::/32"]

    [domains]
    local = ["Example.COM"]
    relay = ["backup.example"]
    local_recipients = ["Alice@Example.com"]
    """

    assert {:ok, config} = Config.parse(toml)

    assert Enum.map(config.listener, &Map.take(&1, [:address, :port])) == [
             %{address: {0, 0, 0, 0, 0, 0, 0, 0}, port: 2525},
             %{address: {192, 0, 2, 1}, port: 25}
           ]

    assert config.smtp.max_message_size == 50 * 1024 * 1024
    assert config.smtp.command_timeout == 30_000
    assert config.smtp.data_timeout == 600_000
    assert config.smtp.bare_line_endings == :normalize

    assert config.smtp.trusted_networks == [
             {{127, 0, 0, 1}, 32},
             {{192, 0, 2, 0}, 24},
             {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32}
           ]

    assert config.domains == %{
             local: ["example.com"],
             relay: ["backup.example"],
             local_recipients: ["alice@example.com"],
             aliased: [],
             hosted: []
           }
  end

  test "defaults the queue, delivery, and bounce settings" do
    assert {:ok, config} = Config.parse("")

    assert config.delivery == %{
             relayhost: nil,
             max_deliveries: 100,
             destination_concurrency: 20,
             destination_rate_delay: nil,
             max_recipients: 50,
             max_addresses: 5,
             ip_versions: [:ipv6, :ipv4],
             connect_timeout: 30_000,
             tls: :may,
             tls_policy: %{},
             tls_ca_file: nil,
             relayhost_username: nil,
             relayhost_password: nil,
             source_address: []
           }

    assert config.bounce == %{double_bounce_recipient: nil}
  end

  test "parses queue, delivery, and bounce settings" do
    toml = """
    [queue]
    max_lifetime = "2d"
    min_backoff = "1m"
    max_backoff = "2h"
    delay_warning = "4h"

    [delivery]
    relayhost = "[smtp.isp.example]:587"
    max_deliveries = 10
    destination_concurrency = 2
    destination_rate_delay = "1s"
    max_recipients = 10
    max_addresses = 3
    ip_versions = ["ipv4"]
    connect_timeout = "10s"

    [bounce]
    double_bounce_recipient = "Postmaster@Example.org"
    """

    assert {:ok, config} = Config.parse(toml)

    assert Map.delete(config.queue, :directory) == %{
             max_lifetime: 2 * 86_400_000,
             min_backoff: 60_000,
             max_backoff: 7_200_000,
             delay_warning: 4 * 3_600_000
           }

    assert config.delivery.relayhost == %{host: "smtp.isp.example", port: 587, mx: false}
    assert config.delivery.destination_rate_delay == 1000
    assert config.delivery.ip_versions == [:ipv4]
    assert config.bounce.double_bounce_recipient == "postmaster@example.org"
  end

  test "parses relay hosts in Postfix syntax" do
    for {value, expected} <- [
          {"isp.example", %{host: "isp.example", port: 25, mx: true}},
          {"ISP.example:2525", %{host: "isp.example", port: 2525, mx: true}},
          {"[smtp.isp.example]", %{host: "smtp.isp.example", port: 25, mx: false}},
          {"[192.0.2.1]:587", %{host: "[192.0.2.1]", port: 587, mx: false}},
          {"[2001:db8::1]", %{host: "[IPv6:2001:db8::1]", port: 25, mx: false}},
          {"[IPv6:2001:db8::1]:465", %{host: "[IPv6:2001:db8::1]", port: 465, mx: false}}
        ] do
      assert {:ok, config} = Config.parse(~s([delivery]\nrelayhost = "#{value}"))
      assert config.delivery.relayhost == expected, value
    end

    for bad <- [
          "",
          "isp.example:0",
          "isp.example:x",
          "[isp.example",
          "192.0.2.1",
          "a:b:c",
          "-bad.example"
        ] do
      assert {:error, [error]} = Config.parse(~s([delivery]\nrelayhost = "#{bad}"))

      assert Exception.message(error) =~
               "delivery.relayhost: #{inspect(bad)} is not a valid relay host"
    end
  end

  test "checks settings that depend on each other" do
    toml = """
    [queue]
    min_backoff = "2h"
    max_backoff = "1h"

    [delivery]
    ip_versions = ["ipv4", "ipv4"]
    """

    assert {:error, errors} = Config.parse(toml)

    assert Enum.map(errors, &Exception.message/1) == [
             "queue.max_backoff: must not be less than queue.min_backoff",
             "delivery.ip_versions: must not repeat a version"
           ]

    assert {:error, [error]} = Config.parse("[delivery]\nip_versions = []")
    assert Exception.message(error) == "delivery.ip_versions: must not be empty"
  end

  test "names array elements in errors" do
    toml = """
    [[listener]]
    port = 70000

    [smtp]
    trusted_networks = ["192.0.2.1/24", "nope"]
    command_timeout = "5 minutes"

    [domains]
    local = "example.com"
    local_recipients = ["not an address"]
    """

    assert {:error, errors} = Config.parse(toml)

    assert Enum.map(errors, &Exception.message/1) == [
             "listener[0].port: expected an integer from 0 to 65535, got 70000",
             ~s(smtp.command_timeout: expected a duration like "30s", "5m", or "1h", got "5 minutes"),
             ~s(smtp.trusted_networks[0]: "192.0.2.1/24" has bits set after the prefix length),
             ~s(smtp.trusted_networks[1]: "nope" is not a valid network, expected an address or CIDR),
             ~s(domains.local: expected an array, got "example.com"),
             ~s(domains.local_recipients[0]: "not an address" is not a valid email address)
           ]
  end

  test "reports every problem with its key path" do
    toml = """
    typo = 1

    [server]
    hostname = "not a hostname"

    [queue]
    directory = "relative/path"
    extra = true

    [log]
    level = "loud"
    format = 1
    directory = "logs"
    file_name = "sovite.log"
    date_format = "%J"
    max_size = "1T"
    rotation = "yearly"
    symlink = "a/b"
    """

    assert {:error, errors} = Config.parse(toml)

    assert Enum.map(errors, &Exception.message/1) == [
             "typo: unknown key",
             ~s(server.hostname: "not a hostname" is not a valid hostname),
             "queue.extra: unknown key",
             ~s(queue.directory: "relative/path" is not an absolute path),
             ~s(log.level: expected one of "debug", "info", "notice", "warning", "error", got "loud"),
             ~s(log.format: expected one of "text", "json", got 1),
             ~s(log.directory: "logs" is not an absolute path),
             ~s(log.file_name: "sovite.log" must contain {n} exactly once),
             ~s(log.date_format: "%J" is not a valid strftime format),
             ~s(log.max_size: expected a size like "512M" or "1G", got "1T"),
             ~s(log.rotation: expected one of "never", "hourly", "daily", "weekly", "monthly", got "yearly"),
             ~s(log.symlink: "a/b" is not a valid file name)
           ]
  end

  test "rejects a section given as a plain value" do
    assert {:error, [error]} = Config.parse(~s(log = "debug"))
    assert Exception.message(error) == "log: expected a table"
  end

  test "reports TOML syntax errors" do
    assert {:error, [error]} = Config.parse("[server\n")
    assert Exception.message(error) =~ "invalid TOML"
  end

  test "does not create atoms from unknown keys" do
    key = "sovite_config_test_#{System.unique_integer([:positive])}"
    assert {:error, _} = Config.parse("#{key} = 1")
    assert_raise ArgumentError, fn -> String.to_existing_atom(key) end
  end

  test "load/1 reads a file", %{tmp_dir: dir} do
    path = Path.join(dir, "sovite.toml")
    File.write!(path, ~s([server]\nhostname = "mx.example.org"\n))

    assert {:ok, %Config{server: %{hostname: "mx.example.org"}}} = Config.load(path)
  end

  test "load/1 reports a missing file", %{tmp_dir: dir} do
    path = Path.join(dir, "missing.toml")
    assert {:error, [error]} = Config.load(path)
    assert Exception.message(error) == "cannot read #{path}: no such file or directory"
  end

  test "the shipped example config is valid" do
    assert {:ok, _} = Config.load("rel/overlays/etc/sovite.toml.example")
  end

  describe "Phase 3 settings" do
    @tls """
    [[tls.certificate]]
    cert_file = "/etc/sovite/mx.crt"
    key_file = "/etc/sovite/mx.key"
    """

    defp errors(toml) do
      {:error, errors} = Config.parse(toml)
      Enum.map(errors, &Exception.message/1)
    end

    test "defaults: SQLite, no TLS, database auth, opportunistic outbound TLS" do
      {:ok, config} = Config.parse("")

      assert config.database == %{
               adapter: :sqlite,
               path: "/var/lib/sovite/sovite.db",
               url: nil,
               pool_size: 5,
               ssl: false
             }

      assert config.tls.certificate == []
      assert config.tls.min_version == :"tlsv1.2"
      refute Config.tls_enabled?(config)
      refute Config.auth_enabled?(config)
      assert config.auth.backend == :database
      assert Config.auth_mechanisms(config) == ["SCRAM-SHA-256", "PLAIN", "LOGIN"]
      assert config.submission.strip_headers == ["Return-Path"]
    end

    test "submission listeners default to their port, TLS, and auth" do
      {:ok, config} =
        Config.parse(
          @tls <>
            """
            [[listener]]
            mode = "submission"
            [[listener]]
            mode = "submissions"
            [[listener]]
            mode = "smtp"
            port = 2525
            auth = true
            tls_min_version = "1.3"
            tls_ciphers = ["TLS_AES_256_GCM_SHA384"]
            """
        )

      assert [sub, subs, smtp] = config.listener
      assert %{port: 587, auth: true, require_tls: true, require_auth: true} = sub
      assert %{port: 465, auth: true, require_auth: true} = subs

      assert %{
               port: 2525,
               auth: true,
               require_tls: false,
               require_auth: false,
               tls_min_version: :"tlsv1.3"
             } = smtp

      assert Config.auth_enabled?(config)
    end

    test "refuses submission without certificates, and weak ciphers" do
      assert errors(~s([[listener]]\nmode = "submissions"))
             |> Enum.any?(&(&1 =~ ~s(listener[0].mode: "submissions" needs a certificate)))

      assert errors(~s([[listener]]\nmode = "submission"))
             |> Enum.any?(&(&1 =~ "listener[0].auth: needs a certificate"))

      # Allowed, if the admin explicitly accepts passwords in the clear.
      assert {:ok, _} =
               Config.parse(
                 ~s([[listener]]\nmode = "submission"\nrequire_tls = false\n[auth]\nplaintext = true\n)
               )

      assert errors(@tls <> ~s([tls]\nmin_version = "1.1"\n)) != []

      assert errors(~s([tls]\nciphers = ["AES128-SHA"])) == [
               ~s(tls.ciphers: "AES128-SHA" is not allowed: only ECDHE with AES-GCM or ChaCha20-Poly1305, and TLS 1.3 suites)
             ]

      assert errors(~s([[listener]]\nrequire_auth = true)) == [
               "listener[0].require_auth: needs auth = true"
             ]
    end

    test "checks auth backends" do
      sub = @tls <> ~s([[listener]]\nmode = "submission"\n)
      assert {:ok, _} = Config.parse(sub)

      assert errors(sub <> ~s([auth]\nbackend = "file")) == [
               ~s(auth.file.path: is required with backend = "file")
             ]

      assert errors(sub <> ~s([auth]\nbackend = "ldap")) == [
               ~s(auth.ldap.servers: is required with backend = "ldap"),
               "auth.ldap.base: is required unless auth.ldap.dn_template is set"
             ]

      assert errors(sub <> ~s([auth]\nbackend = "dovecot")) == [
               ~s(auth.dovecot.socket: is required with backend = "dovecot")
             ]

      assert errors(sub <> ~s([auth]\nmechanisms = ["OAUTHBEARER"])) == [
               "auth.mechanisms: OAUTHBEARER needs auth.oauth.introspection_url"
             ]

      {:ok, config} =
        Config.parse(
          sub <> ~s([auth.oauth]\nintrospection_url = "https://idp.example/introspect")
        )

      assert Config.auth_mechanisms(config) == ["SCRAM-SHA-256", "PLAIN", "LOGIN", "OAUTHBEARER"]

      {:ok, config} =
        Config.parse(
          sub <>
            ~s|[auth]\nbackend = "ldap"\n[auth.ldap]\nservers = ["ldap.example"]\nbase = "dc=example"\nfilter = "(uid=%n)"|
        )

      assert Config.auth_mechanisms(config) == ["PLAIN", "LOGIN"]

      assert errors(
               sub <>
                 ~s([auth]\nbackend = "ldap"\n[auth.ldap]\nservers = ["l"]\nbase = "x"\nfilter = "uid=%n")
             ) ==
               [~s(auth.ldap.filter: "uid=%n" is not a valid LDAP filter)]
    end

    test "parses sender maps and TLS policies" do
      {:ok, config} =
        Config.parse("""
        [auth.senders]
        "alice@example.com" = ["Alice@Example.com", "@example.org"]
        bob = ["*"]

        [delivery]
        tls = "dane"
        tls_policy = { "Bank.example" = "verify", "[192.0.2.1]" = "encrypt", "[IPv6:2001:db8::1]" = "none" }
        """)

      assert config.auth.senders == %{
               "alice@example.com" => ["alice@example.com", "@example.org"],
               "bob" => ["*"]
             }

      assert config.delivery.tls == :dane

      assert config.delivery.tls_policy == %{
               "bank.example" => :verify,
               "[192.0.2.1]" => :encrypt,
               "[IPv6:2001:db8::1]" => :none
             }

      assert errors(~s([auth.senders]\nbob = ["not an address"])) == [
               ~s(auth.senders.bob[0]: "not an address" is not an address, "@domain", or "*")
             ]

      assert errors(~s([delivery]\ntls_policy = { "a b" = "verify" })) == [
               ~s(delivery.tls_policy.a b: "a b" is not a domain or address literal)
             ]

      assert errors(~s([delivery]\ntls_policy = { "x.example" = "maybe" })) |> hd() =~
               "delivery.tls_policy.x.example: expected one of"
    end

    test "checks the database and ACME settings" do
      assert errors(~s([database]\nadapter = "postgres")) == [
               "database.url: is required for postgres"
             ]

      assert {:ok, %{database: %{adapter: :postgres}}} =
               Config.parse(
                 ~s([database]\nadapter = "postgres"\nurl = "postgres://u:p@db/sovite")
               )

      assert errors(~s([database]\nadapter = "mysql"\nurl = "ftp://x/y")) == [
               ~s(database.url: "ftp://x/y" must use postgres:// or postgresql:// or ecto:// or mysql://)
             ]

      assert errors(~s([tls.acme]\nenabled = true)) == [
               "tls.acme.domains: is required when ACME is enabled",
               "tls.acme.email: is required when ACME is enabled",
               "tls.acme.accept_terms: must be true: you must agree to the CA's terms of service to use ACME"
             ]

      {:ok, config} =
        Config.parse(
          ~s([tls.acme]\nenabled = true\ndomains = ["mx.example.com"]\nemail = "a@example.com"\naccept_terms = true\n[[listener]]\nmode = "submissions")
        )

      assert Config.tls_enabled?(config)
    end

    test "relayhost credentials need a relay host" do
      assert errors(~s([delivery]\nrelayhost_username = "u")) == [
               "delivery.relayhost_username: needs delivery.relayhost"
             ]
    end
  end

  describe "Phase 6 settings" do
    defp phase6_errors(toml) do
      {:error, errors} = Config.parse(toml)
      Enum.map(errors, &Exception.message/1)
    end

    test "defaults: verify everything, sign with keys, enforce nothing" do
      {:ok, config} = Config.parse(~s([server]\nhostname = "mx.example.com"))
      assert config.server.authserv_id == "mx.example.com"
      assert config.spf == %{verify: true, helo: true, reject_fail: false, timeout: 20_000}
      assert %{verify: true, sign: true, key: [], headers: nil} = config.dkim
      assert %{verify: true, seal: false, trusted_sealers: []} = config.arc

      assert config.dmarc == %{
               verify: true,
               policy: :report,
               reports: false,
               report_interval: 86_400_000,
               report_org: "mx.example.com",
               report_from: "postmaster@mx.example.com"
             }

      assert config.srs == %{enabled: false, domain: "mx.example.com", secrets: [], max_age: 21}
    end

    test "loads DKIM keys", %{tmp_dir: dir} do
      file = Path.join(dir, "key.pem")
      File.write!(file, SigningKey.generate(:ed25519))

      {:ok, config} =
        Config.parse("""
        [dkim]
        headers = ["From", "Subject"]
        expiration = "7d"
        [[dkim.key]]
        domain = "Example.COM"
        selector = "s2026"
        file = "#{file}"
        [arc]
        seal = true
        domain = "example.com"
        selector = "s2026"
        """)

      assert config.dkim.headers == ["from", "subject"]
      assert [%{domain: "example.com", sign: true, signing_key: key}] = config.dkim.key
      assert key.algorithm == :ed25519_sha256
    end

    test "rejects broken keys and settings", %{tmp_dir: dir} do
      file = Path.join(dir, "key.pem")
      File.write!(file, "not a key")

      assert phase6_errors("""
             [[dkim.key]]
             domain = "example.com"
             selector = "a_b"
             file = "#{file}"
             [[dkim.key]]
             domain = "example.com"
             selector = "s1"
             file = "#{file}"
             [[dkim.key]]
             domain = "example.com"
             selector = "s1"
             file = "#{dir}/missing.pem"
             [arc]
             seal = true
             [srs]
             enabled = true
             secrets = ["short"]
             """) == [
               ~s(dkim.key[0].selector: "a_b" is not a valid selector: use DNS labels)
             ]

      assert phase6_errors("""
             [[dkim.key]]
             domain = "example.com"
             selector = "s1"
             file = "#{file}"
             [[dkim.key]]
             domain = "example.com"
             selector = "s1"
             file = "#{dir}/missing.pem"
             [arc]
             seal = true
             [srs]
             enabled = true
             secrets = ["short"]
             """) == [
               "dkim.key[0].file: no private key found",
               "dkim.key[1].file: cannot read #{dir}/missing.pem: no such file or directory",
               "dkim.key[1]: selector s1 of example.com is already defined",
               "arc.seal: needs arc.domain and arc.selector to name a [[dkim.key]]",
               "srs.secrets[0]: must be at least 16 characters"
             ]

      assert phase6_errors("[srs]\nenabled = true") ==
               ["srs.secrets: is required when SRS is enabled"]

      assert phase6_errors(~s([dmarc]\npolicy = "strict")) ==
               [~s(dmarc.policy: expected one of "report", "enforce", got "strict")]
    end
  end

  describe "Phase 5 settings" do
    defp phase5_errors(toml) do
      {:error, errors} = Config.parse(toml)
      Enum.map(errors, &Exception.message/1)
    end

    test "defaults: no Maildir, no pipes, 50 hops" do
      {:ok, config} = Config.parse("")
      assert config.maildir == %{local: nil, mailbox: nil}
      assert config.pipe == %{}
      assert config.smtp.max_hops == 50
    end

    test "Maildir templates and pipes" do
      {:ok, config} =
        Config.parse("""
        [routing]
        local_transport = "pipe:procmail"
        [maildir]
        mailbox = "/var/vmail/{domain}/{user}/"
        [pipe.procmail]
        command = ["/usr/bin/procmail", "-a", "{extension}"]
        sandbox = ["/usr/bin/systemd-run", "--pipe", "--wait"]
        timeout = "1m"
        env = { LANG = "C" }
        """)

      assert config.maildir.mailbox == "/var/vmail/{domain}/{user}/"
      assert config.routing.local_transport == %{transport: :pipe, nexthop: "procmail"}

      assert config.pipe["procmail"] == %{
               command: ["/usr/bin/procmail", "-a", "{extension}"],
               sandbox: ["/usr/bin/systemd-run", "--pipe", "--wait"],
               timeout: 60_000,
               directory: "/",
               env: %{"LANG" => "C"},
               trace_headers: true
             }
    end

    test "rejects bad Maildir templates, pipes, and pipe transports" do
      assert phase5_errors("""
             [routing]
             mailbox_transport = "pipe:missing"
             [maildir]
             local = "mail/{user}"
             mailbox = "/mail/{folder}"
             [pipe."bad name"]
             command = ["/bin/true"]
             [pipe.relative]
             command = ["true"]
             [pipe.empty]
             command = []
             [pipe.noenv]
             command = ["/bin/true"]
             env = { "1X" = "y" }
             [pipe.nocommand]
             timeout = "1m"
             """) == [
               ~s(maildir.local: "mail/{user}" is not an absolute path),
               "maildir.mailbox: unknown placeholder {folder}; use {user}, {domain}, or {address}",
               ~s(pipe.bad name: "bad name" is not a valid name: use letters, digits, "_", and "-"),
               ~s(pipe.empty.command: expected a command: an array with a program's absolute path and its arguments, got []),
               "pipe.nocommand.command: is required",
               ~s(pipe.noenv.env.1X: "1X" is not a valid environment variable name),
               ~s(pipe.relative.command: "true" is not an absolute path)
             ]

      assert phase5_errors("""
             [routing]
             mailbox_transport = "pipe:missing"
             """) == ["routing.mailbox_transport: there is no [pipe.missing] section"]
    end

    test "LMTP listeners default to port 24 and must not use port 25" do
      {:ok, config} = Config.parse("[[listener]]\nmode = \"lmtp\"")
      assert [%{mode: :lmtp, port: 24, auth: false}] = config.listener

      assert phase5_errors("[[listener]]\nmode = \"lmtp\"\nport = 25") ==
               ["listener[0].port: LMTP must not use port 25"]
    end
  end
end
