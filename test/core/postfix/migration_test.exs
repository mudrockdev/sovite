defmodule Sovite.Core.Postfix.MigrationTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Config
  alias Sovite.Core.Postfix.Migration

  # Migrates main.cf text (and master.cf, and the files it names), and
  # checks that the config is valid.
  defp migrate(main, master \\ nil, files \\ %{}) do
    read = fn path ->
      case Map.fetch(files, path) do
        {:ok, contents} -> {:ok, contents}
        :error -> {:error, :enoent}
      end
    end

    result =
      Migration.migrate(main, master,
        read: read,
        defaults: %{"myhostname" => "mx.example.com", "inet_protocols" => "ipv4"},
        source: "/etc/postfix",
        date: ~D[2026-01-02]
      )

    assert result.errors == []
    assert {:ok, config} = Config.parse(result.config)
    Map.put(result, :parsed, config)
  end

  defp entry(result, setting, level \\ nil) do
    Enum.find(result.entries, &(&1.setting == setting and (level == nil or &1.level == level)))
  end

  defp message(result, setting, level \\ nil) do
    case entry(result, setting, level) do
      nil -> flunk("no report line for #{setting}: #{inspect(result.entries, pretty: true)}")
      entry -> entry.message
    end
  end

  @smtpd "smtp inet n - y - - smtpd\n"

  describe "host name, origin, and domains" do
    test "an explicit host name and an origin file" do
      result =
        migrate("myhostname = MX.example.net\nmyorigin = /etc/mailname\n", nil, %{
          "/etc/mailname" => "example.net\n"
        })

      assert result.parsed.server.hostname == "mx.example.net"
      assert result.parsed.sendmail.origin == "example.net"
      assert message(result, "myorigin") =~ "from /etc/mailname"
      assert result.report =~ "From /etc/postfix, on 2026-01-02"
      assert result.config =~ "/etc/postfix on 2026-01-02"
    end

    test "the system's host name, and problems with it" do
      result = migrate("")
      assert result.parsed.server.hostname == "mx.example.com"
      assert result.config =~ "# check: the system's host name"
      assert entry(result, "myorigin") == nil

      result = migrate("myhostname = localhost\nmyorigin = /etc/mailname\n")
      assert message(result, "myhostname", :attention) =~ "not a fully qualified host name"
      assert message(result, "myorigin", :attention) =~ "is not a domain (from /etc/mailname)"
    end

    test "myorigin like myhostname is the default" do
      result = migrate("myorigin = $myhostname\n")
      assert result.parsed.sendmail.origin == nil
      assert entry(result, "myorigin", :ignored)
    end

    test "domain classes, in lists, files, and tables" do
      result =
        migrate(
          """
          mydestination = $myhostname, localhost, /etc/postfix/local, hash:/etc/postfix/more, bad_domain!
          virtual_mailbox_domains = example.com, mx.example.com
          virtual_alias_domains = alias.example.com
          relay_domains = relay.example.com, mysql:/etc/postfix/relay.cf
          """,
          nil,
          %{
            "/etc/postfix/local" => "one.example.com two.example.com\n# comment\n",
            "/etc/postfix/more" => "three.example.com OK\nuser@four.example.com x\n"
          }
        )

      assert result.parsed.domains.local == ["mx.example.com", "localhost"]
      assert result.parsed.domains.hosted == ["example.com"]
      assert result.parsed.domains.aliased == ["alias.example.com"]
      assert result.parsed.domains.relay == ["relay.example.com"]

      assert ["domain", "add", "one.example.com", "local"] in result.commands
      assert ["domain", "add", "three.example.com", "local"] in result.commands
      refute Enum.any?(result.commands, &("four.example.com" in &1))

      assert message(result, "mydestination", :attention) =~ "bad_domain! is not a domain"

      assert message(result, "virtual_mailbox_domains", :attention) =~
               "mx.example.com is already a local domain"

      assert message(result, "relay_domains", :attention) =~ "mysql: tables cannot be read"
    end

    test "domains declared in the virtual maps" do
      result =
        migrate(
          "virtual_alias_maps = hash:/etc/postfix/virtual\nvirtual_mailbox_maps = hash:/etc/postfix/vmailbox\n",
          nil,
          %{
            "/etc/postfix/virtual" =>
              "aliases.example anything\nx@aliases.example y@example.org\n",
            "/etc/postfix/vmailbox" =>
              "boxes.example whatever\nme@boxes.example boxes.example/me/\n"
          }
        )

      assert ["domain", "add", "aliases.example", "aliased"] in result.commands
      assert ["domain", "add", "boxes.example", "hosted"] in result.commands
      assert ["alias", "add", "x@aliases.example", "y@example.org"] in result.commands
      assert ["mailbox", "add", "me@boxes.example"] in result.commands
    end

    test "an empty mydestination" do
      result = migrate("mydestination =\n")
      assert result.parsed.domains.local == []
      assert entry(result, "local delivery") == nil
    end

    test "unreadable domain files" do
      result = migrate("relay_domains = /etc/postfix/relay\n")
      assert message(result, "relay_domains", :attention) =~ "cannot read /etc/postfix/relay"
    end
  end

  describe "trusted networks" do
    test "mynetworks" do
      result = migrate("mynetworks = 127.0.0.0/8 [::1]/128 !10.0.0.1\n")
      assert length(result.parsed.smtp.trusted_networks) == 2
      assert message(result, "mynetworks", :attention) =~ "exclusions"
    end

    test "mynetworks_style" do
      result = migrate("")

      assert result.parsed.smtp.trusted_networks == [
               {{127, 0, 0, 0}, 8},
               {{0, 0, 0, 0, 0, 0, 0, 1}, 128}
             ]

      assert entry(result, "mynetworks_style", :migrated)

      result = migrate("mynetworks_style = subnet\n")
      assert message(result, "mynetworks_style", :attention) =~ "subnet networks"
      assert result.config =~ "# check: Postfix trusted the subnet networks"
    end
  end

  describe "TLS" do
    @tls """
    smtpd_tls_cert_file = /etc/ssl/mx.pem
    smtpd_tls_key_file = /etc/ssl/mx.key
    smtpd_tls_eccert_file = /etc/ssl/ec.pem
    smtpd_tls_dcert_file = /etc/ssl/dsa.pem
    """

    test "certificates and protocols" do
      result =
        migrate(
          @tls <>
            "smtpd_tls_protocols = >=TLSv1.3\nsmtpd_tls_ciphers = high\nsmtpd_tls_ask_ccert = yes\nsmtpd_tls_CAfile = /x\nsmtpd_tls_mandatory_protocols = >=TLSv1.2\n"
        )

      assert result.parsed.tls.certificate == [
               %{cert_file: "/etc/ssl/mx.pem", key_file: "/etc/ssl/mx.key"},
               %{cert_file: "/etc/ssl/ec.pem", key_file: "/etc/ssl/ec.pem"}
             ]

      assert result.parsed.tls.min_version == :"tlsv1.3"
      assert message(result, "smtpd_tls_dcert_file", :attention) =~ "DSA"
      assert message(result, "smtpd_tls_ciphers", :ignored) =~ "BCP 195"
      assert message(result, "smtpd_tls_ask_ccert", :attention) =~ "Client certificates"
      assert entry(result, "smtpd_tls_CAfile", :ignored)
      assert entry(result, "smtpd_tls_mandatory_protocols", :migrated)
      assert entry(result, "TLS keys", :attention)
    end

    test "relative paths, bad protocol lists, and old TLS versions" do
      result =
        migrate(
          "smtpd_tls_cert_file = mx.pem\nsmtpd_tls_protocols = !TLSv1 !TLSv1.1 !TLSv1.2 !TLSv1.3\n"
        )

      assert result.parsed.tls.certificate == []
      assert message(result, "smtpd_tls_cert_file", :attention) =~ "absolute paths"
      assert entry(result, "smtpd_tls_protocols", :attention)

      result = migrate("smtpd_tls_protocols = !SSLv2\n")
      assert message(result, "smtpd_tls_protocols", :ignored) =~ "TLS 1.2 and 1.3"
    end

    test "chain files" do
      files = %{
        "/tls/both.pem" => "-----BEGIN PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\n",
        "/tls/key.pem" => "-----BEGIN EC PRIVATE KEY-----\n",
        "/tls/cert.pem" => "-----BEGIN CERTIFICATE-----\n",
        "/tls/lonely.key" => "-----BEGIN PRIVATE KEY-----\n"
      }

      result =
        migrate(
          "smtpd_tls_chain_files = /tls/both.pem, /tls/key.pem, /tls/cert.pem, /tls/missing.pem, /tls/lonely.key\n",
          nil,
          files
        )

      assert result.parsed.tls.certificate == [
               %{cert_file: "/tls/both.pem", key_file: "/tls/both.pem"},
               %{cert_file: "/tls/cert.pem", key_file: "/tls/key.pem"}
             ]

      messages =
        for %{setting: "smtpd_tls_chain_files", level: :attention, message: m} <- result.entries,
            do: m

      assert Enum.any?(messages, &(&1 =~ "/tls/missing.pem: cannot tell"))
      assert Enum.any?(messages, &(&1 =~ "/tls/lonely.key: a key without a certificate"))
    end

    test "security levels and AUTH without TLS" do
      result = migrate(@tls <> "smtpd_tls_security_level = none\nsmtpd_tls_auth_only = no\n")
      assert message(result, "smtpd_tls_security_level", :attention) =~ "did not offer STARTTLS"
      assert message(result, "smtpd_tls_auth_only", :attention) =~ "auth.plaintext"

      result = migrate("smtpd_enforce_tls = yes\nsmtpd_tls_auth_only = yes\n")
      assert entry(result, "smtpd_tls_security_level", :migrated)
      assert entry(result, "smtpd_tls_auth_only", :ignored)

      result = migrate("smtpd_use_tls = yes\n")
      assert entry(result, "smtpd_tls_security_level", :ignored)
    end

    test "outbound TLS" do
      for {level, expected} <- [
            {"none", :none},
            {"encrypt", :encrypt},
            {"secure", :verify},
            {"verify", :verify}
          ] do
        assert migrate("smtp_tls_security_level = #{level}\n").parsed.delivery.tls == expected
      end

      assert migrate("smtp_tls_security_level = may\n").parsed.delivery.tls == :dane
      assert migrate("smtp_use_tls = yes\n").parsed.delivery.tls == :dane
      assert migrate("smtp_enforce_tls = yes\n").parsed.delivery.tls == :encrypt

      result = migrate("smtp_tls_security_level = dane-only\n")
      assert result.parsed.delivery.tls == :dane
      assert entry(result, "smtp_tls_security_level", :attention)

      result = migrate("smtp_tls_security_level = fingerprint\n")
      assert message(result, "smtp_tls_security_level", :attention) =~ "no such level"

      assert entry(migrate(""), "smtp_tls_security_level", :ignored)
    end

    test "outbound TLS policies and CAs" do
      result =
        migrate(
          """
          smtp_tls_policy_maps = hash:/etc/postfix/tls_policy, mysql:/x
          smtp_tls_CAfile = /etc/ssl/ca.pem
          smtp_tls_CApath = /etc/ssl/mine
          """,
          nil,
          %{
            "/etc/postfix/tls_policy" =>
              "[relay.example]:587 secure\n[192.0.2.1] encrypt\nbad_key! may\nok.example rubbish\n"
          }
        )

      assert result.parsed.delivery.tls_policy == %{
               "relay.example" => :verify,
               "[192.0.2.1]" => :encrypt
             }

      assert result.parsed.delivery.tls_ca_file == "/etc/ssl/ca.pem"
      message = message(result, "smtp_tls_policy_maps", :attention)
      assert message =~ "bad_key!: not a domain or [host]"
      assert message =~ "ok.example: rubbish is not a level"
      assert message =~ "mysql"
      assert entry(result, "smtp_tls_CApath", :attention)

      result =
        migrate("smtp_tls_policy_maps = hash:/p\nsmtp_tls_CAfile = ca.pem\n", nil, %{
          "/p" => "a.example may\n"
        })

      assert entry(result, "smtp_tls_policy_maps", :migrated)
      assert entry(result, "smtp_tls_CAfile", :attention)
    end
  end

  describe "SASL" do
    test "Dovecot over a socket in the queue directory, or inet" do
      master = @smtpd <> "submission inet n - y - - smtpd\n"

      result = migrate("smtpd_sasl_type = dovecot\nsmtpd_sasl_path = private/auth\n", master)
      assert result.parsed.auth.backend == :dovecot
      assert result.parsed.auth.dovecot.socket == "/var/spool/postfix/private/auth"
      assert message(result, "smtpd_sasl_path", :attention) =~ "/run/dovecot/auth-client"
      assert result.config =~ "# check: inside Postfix's queue directory"

      result =
        migrate("smtpd_sasl_type = dovecot\nsmtpd_sasl_path = inet:127.0.0.1:12345\n", master)

      assert result.parsed.auth.dovecot.socket == "127.0.0.1:12345"
      assert entry(result, "smtpd_sasl_path", :migrated)
    end

    test "Cyrus, and SASL nothing uses" do
      result = migrate("smtpd_sasl_auth_enable = yes\n", @smtpd)
      assert message(result, "smtpd_sasl_type", :attention) =~ "Cyrus SASL is not supported"

      result = migrate("smtpd_sasl_type = dovecot\nsmtpd_sasl_path = private/auth\n", @smtpd)
      assert result.parsed.auth.backend == :database
      assert entry(result, "smtpd_sasl_type", :ignored)
    end
  end

  describe "listeners" do
    test "smtpd services, interfaces, and modes" do
      result =
        migrate(
          "inet_interfaces = 192.0.2.1, [2001:db8::1], localhost, host.example\ninet_protocols = ipv4, ipv6\nsmtpd_tls_cert_file = /c.pem\n",
          """
          smtp inet n - y - - smtpd
          127.0.0.1:2525 inet n - y - - smtpd
          [::1]:2526 inet n - y - - smtpd
          localhost:2527 inet n - y - - smtpd
          host.example:2528 inet n - y - - smtpd
          weird inet n - y - - smtpd
          smtps inet n - y - - smtpd
          10465 inet n - y - - smtpd -o smtpd_tls_wrappermode=yes
          qmqp inet n - n - - qmqpd
          custom unix - - n - - mydaemon
          """
        )

      listeners =
        for l <- result.parsed.listener,
            do: {:inet.ntoa(l.address) |> to_string(), l.port, l.mode}

      assert {"192.0.2.1", 25, :smtp} in listeners
      assert {"2001:db8::1", 25, :smtp} in listeners
      assert {"127.0.0.1", 25, :smtp} in listeners
      assert {"::1", 25, :smtp} in listeners
      assert {"127.0.0.1", 2525, :smtp} in listeners
      assert {"::1", 2526, :smtp} in listeners
      assert {"127.0.0.1", 2527, :smtp} in listeners
      assert {"192.0.2.1", 465, :submissions} in listeners
      assert {"192.0.2.1", 10_465, :submissions} in listeners
      refute Enum.any?(listeners, &(elem(&1, 1) == 2528))

      assert message(result, "master.cf: host.example:2528", :attention) =~ "IP address"
      assert message(result, "master.cf: weird", :attention) =~ "Unknown service name or port"
      assert message(result, "master.cf: qmqp", :attention) =~ "qmqpd(8)"
      assert message(result, "master.cf: custom", :attention) =~ "Unknown service"
      assert entry(result, "inet_protocols") == nil
    end

    test "no master.cf, or no services" do
      result = migrate("")
      assert message(result, "master.cf", :attention) =~ "no master.cf"
      assert [%{port: 25}] = result.parsed.listener

      result = migrate("", "pickup unix n - y 60 1 pickup\n")
      assert result.parsed.listener == []
      assert result.config =~ "\nlistener = []\n"
      assert entry(result, "sendmail", :attention)
    end

    test "submission without a certificate, and AUTH without TLS" do
      result =
        migrate(
          "smtpd_sasl_auth_enable = yes\nsmtpd_tls_security_level = encrypt\n",
          @smtpd <> "submission inet n - y - - smtpd\n"
        )

      assert [%{port: 25, auth: false, require_tls: false}] = result.parsed.listener
      assert Enum.any?(result.entries, &(&1.message =~ "needs a TLS certificate"))
      assert Enum.any?(result.entries, &(&1.message =~ "auth was left off"))
      assert Enum.any?(result.entries, &(&1.message =~ "require_tls was left off"))
    end

    test "per-service options" do
      result =
        migrate(
          "smtpd_tls_cert_file = /c.pem\nsmtpd_milters = inet:127.0.0.1:11332\nsmtpd_upstream_proxy_protocol = haproxy\nsmtpd_tls_protocols = >=TLSv1.2\n",
          """
          smtp inet n - y - - smtpd
            -o smtpd_tls_security_level=encrypt
            -o smtpd_milters=
            -o smtpd_helo_restrictions=permit_sasl_authenticated,reject
            -o smtpd_recipient_restrictions=reject_unknown_sender_domain
            -o smtpd_sasl_auth_enable=yes
          2525 inet n - y - - smtpd
            -o smtpd_upstream_proxy_protocol=nginx
            -o smtpd_tls_protocols=>=TLSv1.3
            -o smtpd_milters=inet:127.0.0.1:11332,unix:/run/opendkim.sock
            -o myhostname=other.example
          submission inet n - y - - smtpd
            -o smtpd_tls_mandatory_protocols=>=TLSv1.3
          """
        )

      [port25, port2525, submission] = result.parsed.listener
      assert port25.require_tls
      assert port25.auth
      assert port25.require_auth
      assert port25.milters == []
      assert port25.proxy_protocol
      refute port2525.proxy_protocol
      assert port2525.tls_min_version == :"tlsv1.3"
      assert port2525.milters == ["inet:127.0.0.1:11332", "unix:/run/opendkim.sock"]
      assert submission.tls_min_version == :"tlsv1.3"
      assert submission.milters == ["inet:127.0.0.1:11332"]
      assert submission.proxy_protocol

      notes = for %{setting: "master.cf: " <> _, message: m} <- result.entries, do: m
      assert Enum.any?(notes, &(&1 =~ "nginx is not supported"))
      assert Enum.any?(notes, &(&1 =~ "-o myhostname=other.example: per-service"))

      assert Enum.any?(
               notes,
               &(&1 =~ "-o smtpd_recipient_restrictions=reject_unknown_sender_domain")
             )

      assert Enum.any?(notes, &(&1 =~ "not recommended on port 25")) or
               result.config =~ "not recommended on port 25"

      assert entry(result, "smtpd_upstream_proxy_protocol", :migrated)
    end

    test "submission notes" do
      result =
        migrate(
          "smtpd_tls_cert_file = /c.pem\n",
          "submission inet n - y - - smtpd\n  -o smtpd_sasl_auth_enable=no\n"
        )

      assert [%{mode: :submission}] = result.parsed.listener
      notes = for %{setting: "master.cf: submission", message: m} <- result.entries, do: m
      assert Enum.any?(notes, &(&1 =~ "did not offer AUTH"))
      assert Enum.any?(notes, &(&1 =~ "without AUTH"))
    end

    test "postscreen and the screen" do
      result =
        migrate(
          """
          postscreen_dnsbl_sites = zen.spamhaus.org=127.0.0.[2;3;4]*2, list.dnswl.org*-3, bad_zone!, x.example*9999, y.example=999.1.1.1
          postscreen_dnsbl_threshold = 2
          postscreen_dnsbl_allowlist_threshold = -2
          postscreen_greet_action = drop
          postscreen_greet_wait = 3s
          postscreen_upstream_proxy_protocol = haproxy
          postscreen_access_list = permit_mynetworks, cidr:/etc/postfix/access.cidr
          postscreen_bare_newline_enable = yes
          postscreen_cache_map = btree:/x
          postscreen_unknown_thing = 1
          """,
          "smtp inet n - y - 1 postscreen\nsmtpd pass - - y - - smtpd\n"
        )

      screen = result.parsed.screen
      assert screen.threshold == 2
      assert screen.allow_threshold == -2
      assert screen.greet_delay == 3000

      assert [%{zone: "zen.spamhaus.org", weight: 2}, %{zone: "list.dnswl.org", weight: -3}] =
               screen.dnsbl

      assert [%{proxy_protocol: true, screen: true}] = result.parsed.listener

      message = message(result, "postscreen_dnsbl_sites", :attention)
      assert message =~ "bad_zone! is not a DNS zone"
      assert message =~ "the weight must be"
      assert message =~ "999.1.1.1 is not a reply code"
      assert message(result, "postscreen_access_list", :attention) =~ "cidr:"
      assert entry(result, "postscreen_bare_newline_enable", :ignored)
      assert entry(result, "postscreen_cache_map", :ignored)
      assert entry(result, "postscreen_unknown_thing", :attention)
    end

    test "postscreen settings without postscreen, and odd values" do
      result =
        migrate(
          "postscreen_dnsbl_threshold = 0\npostscreen_greet_action = ignore\npostscreen_dnsbl_whitelist_threshold = 0\n",
          @smtpd
        )

      assert entry(result, "postscreen_dnsbl_threshold", :attention)
      assert entry(result, "postscreen_greet_action", :ignored)
      assert entry(result, "postscreen_dnsbl_whitelist_threshold", :ignored)

      result =
        migrate(
          "postscreen_dnsbl_threshold = 1\npostscreen_dnsbl_sites = zen.spamhaus.org\npostscreen_dnsbl_allowlist_threshold = 5\npostscreen_greet_action = enforce\npostscreen_greet_wait = forever\npostscreen_access_list = permit_mynetworks\n",
          "smtp inet n - y - 1 postscreen\n"
        )

      assert message(result, "postscreen_dnsbl_sites", :attention) =~
               "postscreen_dnsbl_action is ignore"

      assert entry(result, "postscreen_dnsbl_allowlist_threshold", :attention)
      assert entry(result, "postscreen_greet_wait", :attention)
      assert entry(result, "postscreen_access_list", :ignored)

      result =
        migrate("postscreen_dnsbl_allowlist_threshold = x\n", "smtp inet n - y - 1 postscreen\n")

      assert message(result, "postscreen_dnsbl_allowlist_threshold", :attention) =~ "Not a number"
    end
  end

  describe "restrictions" do
    test "translated checks, and the ones Sovite has no equivalent for" do
      result =
        migrate(
          """
          smtpd_restriction_classes = myclass
          smtpd_client_restrictions = permit_mynetworks, sleep 5, reject_unknown_client_hostname
          smtpd_helo_restrictions = permit_sasl_authenticated, reject_non_fqdn_helo_hostname, reject_invalid_helo_hostname, reject_unknown_helo_hostname
          smtpd_sender_restrictions = reject_unlisted_sender, reject_sender_login_mismatch, check_sender_mx_access hash:/x, permit_mx_backup
          smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, myclass, reject_plaintext_session, reject_unverified_sender, check_policy_service { inet:127.0.0.1:10023, timeout=10s, default_action=DUNNO, other=1 }, check_policy_service unix:/run/policy.sock, check_policy_service unix:private/postgrey, check_policy_service bogus:x, reject_rbl_client bad_zone!, permit_dnswl_client list.dnswl.org, reject_rhsbl_helo dbl.example, reject_unknown_recipient_domain, bogus_check
          smtpd_data_restrictions = reject_unauth_pipelining, reject_multi_recipient_bounce
          smtpd_end_of_data_restrictions = permit_mynetworks
          smtpd_relay_restrictions = permit_mynetworks, reject_rbl_client zen.spamhaus.org, permit
          """,
          @smtpd
        )

      r = result.parsed.restrictions
      assert r.connect == ["permit_trusted", "require_fcrdns"]
      assert r.mail == ["permit_authenticated", "require_fqdn_helo", "require_known_helo"]

      assert r.rcpt == [
               "permit_trusted",
               "permit_authenticated",
               "check_policy_service inet:127.0.0.1:10023",
               "check_policy_service unix:/run/policy.sock",
               "check_policy_service unix:/var/spool/postfix/private/postgrey",
               "require_known_recipient_domain"
             ]

      assert result.parsed.policy.timeout == 10_000
      assert result.parsed.policy.default_action == "DUNNO"

      assert [%{zone: "zen.spamhaus.org", weight: 1}, %{zone: "list.dnswl.org", weight: -1}] =
               result.parsed.screen.dnsbl

      assert [%{zone: "dbl.example", check: [:helo]}] = result.parsed.screen.rhsbl

      problems =
        for %{level: :attention, setting: "smtpd_" <> _, value: v, message: m} <- result.entries,
            do: {v, m}

      text = inspect(problems)

      for expected <- [
            "sleep 5",
            "Restriction classes",
            "reject_unlisted_sender",
            "permit_mx_backup",
            "Use require_tls",
            "Address verification",
            "other=1",
            "bogus:x",
            "bad_zone!",
            "bogus_check",
            "reject_multi_recipient_bounce",
            "check_sender_mx_access"
          ] do
        assert text =~ expected
      end

      assert Enum.any?(
               result.entries,
               &(&1.message =~ "Sovite runs connect and helo checks before AUTH")
             )

      assert Enum.any?(result.entries, &(&1.message =~ "/var/spool/postfix/private/postgrey"))
      assert entry(result, "reject_unauth_destination", :ignored)
      assert entry(result, "reject_sender_login_mismatch", :ignored)
    end

    test "checks that cannot run at a stage are dropped" do
      result =
        migrate(
          "smtpd_client_restrictions = reject_non_fqdn_sender\nsmtpd_delay_reject = no\n",
          @smtpd
        )

      assert result.parsed.restrictions.connect == []

      assert message(result, "smtpd_client_restrictions", :attention) =~
               "cannot run at Sovite's connect stage"
    end

    test "access tables" do
      result =
        migrate(
          """
          smtpd_client_restrictions = check_client_access hash:/c, check_client_access hash:/c2
          smtpd_helo_restrictions = check_helo_access hash:/h
          smtpd_recipient_restrictions = check_recipient_access hash:/r, check_sender_access mysql:/x
          """,
          @smtpd,
          %{
            "/c" => "192.0.2.1 OK\n2001:db8::1 REJECT go away\n10.0 DEFER\n300.1 OK\n",
            "/c2" => "192.0.2.1 REJECT\n",
            "/h" => "localhost REJECT\n[192.0.2.1] HOLD\n.example.com WARN look\nbad_helo! OK\n",
            "/r" =>
              "abuse@ OK\nuser@example.com 450 later\nexample.org DISCARD\n.example.net FILTER smtp:x\n"
          }
        )

      commands = result.commands
      assert ["access", "set", "client", "192.0.2.1", "ACCEPT"] in commands
      assert ["access", "set", "client", "2001:db8::1", "REJECT", "go away"] in commands
      assert ["access", "set", "client", "10.0", "DEFER"] in commands
      assert ["access", "set", "helo", "[192.0.2.1]", "HOLD"] in commands
      assert ["access", "set", "helo", ".example.com", "WARN", "look"] in commands
      assert ["access", "set", "recipient", "abuse@", "ACCEPT"] in commands
      assert ["access", "set", "recipient", "user@example.com", "450", "later"] in commands
      assert ["access", "set", "recipient", "example.org", "DISCARD"] in commands

      text = inspect(result.entries)
      assert text =~ "300.1"
      assert text =~ "an earlier table has this key already"
      assert text =~ "bad_helo!"
      assert text =~ "FILTER is not an action Sovite has"
      assert text =~ "add the rules with sovitectl access set"
      assert result.parsed.restrictions.rcpt == ["recipient_access", "sender_access"]
    end
  end

  describe "milters, policy servers, and content filters" do
    test "milters with their settings" do
      result =
        migrate(
          """
          smtpd_milters = inet:localhost:11332, { unix:/run/opendkim.sock, connect_timeout=10s, default_action=reject }, local:opendkim/opendkim.sock, { inet:127.0.0.1:8891, command_timeout=1m, content_timeout=bad, default_action=quarantine }, bogus
          milter_default_action = accept
          milter_content_timeout = 120s
          non_smtpd_milters = inet:other:1
          milter_protocol = 2
          milter_connect_macros = j
          milter_header_checks = pcre:/x
          """,
          @smtpd
        )

      [rspamd, dkim, local, other] = result.parsed.milter
      assert rspamd.name == "inet:localhost:11332"
      assert rspamd.default_action == :accept
      assert rspamd.content_timeout == 120_000
      assert dkim.default_action == :reject
      assert dkim.connect_timeout == 10_000
      assert local.name == "unix:/var/spool/postfix/opendkim/opendkim.sock"
      assert other.command_timeout == 60_000
      assert other.default_action == :tempfail

      assert entry(result, "non_smtpd_milters", :attention)
      assert entry(result, "milter_protocol", :ignored)
      assert entry(result, "milter_connect_macros", :ignored)
      assert entry(result, "milter_header_checks", :attention)
      assert entry(result, "milter_default_action", :attention)
      assert entry(result, "milter_content_timeout", :attention)

      assert message(result, "smtpd_milters", :attention) =~ "bogus is not a milter address" or
               Enum.any?(result.entries, &(&1.message =~ "inside Postfix's queue directory"))
    end

    test "policy server defaults" do
      result =
        migrate(
          "smtpd_policy_service_timeout = 30\nsmtpd_policy_service_default_action = DUNNO\nsmtpd_policy_service_max_idle = 300s\n"
        )

      assert result.parsed.policy.timeout == 30_000
      assert result.parsed.policy.default_action == "DUNNO"
      assert entry(result, "smtpd_policy_service_max_idle", :ignored)

      result = migrate("smtpd_policy_service_default_action = MAYBE\n")
      assert entry(result, "smtpd_policy_service_default_action", :attention)
    end

    test "a policy server spawned by master.cf" do
      result =
        migrate(
          "smtpd_recipient_restrictions = check_policy_service unix:private/policy\n",
          @smtpd <> "policy unix - n n - 0 spawn user=nobody argv=/usr/bin/policy { --opt x }\n"
        )

      assert result.parsed.restrictions.rcpt == [
               "check_policy_service spawn:/usr/bin/policy --opt x"
             ]

      assert Enum.any?(result.entries, &(&1.message =~ "An argument contains whitespace"))
    end

    test "content filters, XFORWARD, and XCLIENT" do
      result =
        migrate(
          """
          content_filter = amavis:[127.0.0.1]:10024
          smtpd_authorized_xclient_hosts = 192.0.2.5, hostname.example
          receive_override_options = no_address_mappings
          """,
          """
          smtp inet n - y - - smtpd
          amavis unix - - n - 2 lmtp
            -o lmtp_data_done_timeout=1200
            -o lmtp_send_xforward_command=yes
            -o max_use=20
            -o lmtp_connect_timeout=5s
          127.0.0.1:10025 inet n - n - - smtpd
            -o content_filter=
            -o smtpd_authorized_xforward_hosts=127.0.0.0/8
          """
        )

      assert result.parsed.smtp.content_filter == "lmtp:[127.0.0.1]:10024"
      assert result.parsed.smtp.xforward_networks == [{{127, 0, 0, 0}, 8}]
      assert result.parsed.smtp.xclient_networks == [{{192, 0, 2, 5}, 32}]
      assert message(result, "smtpd_authorized_xclient_hosts", :attention) =~ "host names"
      assert message(result, "master.cf: amavis", :attention) =~ "lmtp_connect_timeout"
      assert entry(result, "receive_override_options", :attention)

      [mx, reinjection] = result.parsed.listener
      assert mx.content_filter == "lmtp:[127.0.0.1]:10024"
      assert reinjection.reinjection
      assert reinjection.content_filter == nil
    end

    test "content filters Sovite cannot use" do
      result = migrate("content_filter = local:\n", @smtpd)
      assert message(result, "content_filter", :attention) =~ "SMTP or LMTP servers"

      result =
        migrate(
          "content_filter = scanner:x\n",
          @smtpd <> "smtp2 inet n - n - - smtpd -o content_filter=\n"
        )

      assert message(result, "content_filter", :attention) =~ "is not a transport Sovite knows"
    end
  end

  describe "routing" do
    test "transports for mailboxes, local users, relays, and the rest" do
      result =
        migrate(
          """
          virtual_transport = lmtp:inet:127.0.0.1:24
          mailbox_transport = lmtp:unix:/run/dovecot/lmtp
          relay_transport = relay:[relay.example]
          default_transport = smtp
          """,
          @smtpd
        )

      routing = result.parsed.routing
      assert routing.mailbox_transport.nexthop == %{host: "[127.0.0.1]", port: 24, mx: false}
      assert routing.local_transport.nexthop == {:unix, "/run/dovecot/lmtp"}
      assert routing.relay_transport.nexthop == %{host: "relay.example", port: 25, mx: false}
      assert entry(result, "default_transport", :ignored)
    end

    test "Postfix's virtual(8) delivery" do
      result = migrate("virtual_transport = virtual\nvirtual_mailbox_base = /var/vmail\n")
      assert result.parsed.maildir.mailbox == "/var/vmail/{domain}/{user}/"
      assert entry(result, "virtual_mailbox_base", :attention)

      result = migrate("virtual_mailbox_maps = hash:/x\n")
      assert message(result, "virtual_transport", :attention) =~ "virtual_mailbox_base is not set"
    end

    test "local delivery" do
      result = migrate("mailbox_command = /usr/bin/procmail\n")
      assert message(result, "mailbox_command", :attention) =~ "[pipe.NAME]"

      result = migrate("home_mailbox = Maildir/\n")
      assert result.parsed.maildir.local == "/home/{user}/Maildir/"

      result = migrate("home_mailbox = Mailbox\n")
      assert message(result, "home_mailbox", :attention) =~ "mbox"

      result = migrate("local_transport = error:5.1.1 no local mail\n")
      assert result.parsed.routing.local_transport.transport == :error

      result = migrate("local_transport = nowhere\nmailbox_transport = elsewhere\n")
      assert entry(result, "local_transport", :attention)

      result = migrate("mailbox_transport = elsewhere\n")
      assert entry(result, "mailbox_transport", :attention)
    end

    test "pipe services" do
      result =
        migrate(
          "mailbox_transport = maildrop\nvirtual_transport = relative\nrelay_transport = bad.name\n",
          """
          maildrop unix - n n - - pipe flags=DRXhu user=vmail size=1000 argv=/usr/bin/maildrop -d ${recipient} ${client_address}
          relative unix - n n - - pipe argv=maildrop
          bad.name unix - n n - - pipe argv=/bin/true
          """
        )

      assert result.parsed.routing.local_transport.nexthop == "maildrop"

      assert result.parsed.pipe["maildrop"].command == [
               "/usr/bin/maildrop",
               "-d",
               "{recipient}",
               "${client_address}"
             ]

      assert result.parsed.pipe["maildrop"].trace_headers
      message = message(result, "master.cf: maildrop", :attention)
      assert message =~ "user=vmail"
      assert message =~ "X were dropped"
      assert message =~ "${client_address}"
      assert message =~ "size= is not supported"
      assert message(result, "virtual_transport", :attention) =~ "not an absolute path"
      assert message(result, "relay_transport", :attention) =~ "not a valid Sovite pipe name"
    end

    test "delimiter, masquerading, and always_bcc" do
      result =
        migrate("""
        myorigin = example.com
        recipient_delimiter = +-
        masquerade_domains = example.com, !mx.example.com, bad_domain!
        masquerade_exceptions = root, mailer-daemon
        masquerade_classes = envelope_sender
        always_bcc = archive
        """)

      assert result.parsed.routing.extension_delimiter == "+-"
      assert result.parsed.routing.hide_subdomains == ["example.com", "!mx.example.com"]
      assert result.parsed.routing.hide_subdomains_exceptions == ["root", "mailer-daemon"]
      assert result.parsed.routing.always_bcc == "archive@example.com"
      assert entry(result, "masquerade_domains", :attention)
      assert entry(result, "masquerade_classes", :attention)

      result = migrate("recipient_delimiter = a\nalways_bcc = not an address\n")
      assert entry(result, "recipient_delimiter", :attention)
      assert entry(result, "always_bcc", :attention)
      assert entry(migrate("always_bcc =\n"), "always_bcc") == nil
    end
  end

  describe "relay host" do
    @passwords %{
      "/etc/postfix/sasl_passwd" => "smtp.isp.example user:secret\n@example.com sender:pw\n"
    }

    test "with a login by host name" do
      result =
        migrate(
          "relayhost = [smtp.isp.example]:587, backup.example\nsmtp_sasl_auth_enable = yes\nsmtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd\nsmtp_sender_dependent_authentication = yes\n",
          nil,
          @passwords
        )

      assert result.parsed.delivery.relayhost == %{host: "smtp.isp.example", port: 587, mx: false}
      assert result.parsed.delivery.relayhost_username == "user"
      assert result.parsed.delivery.relayhost_password == "secret"
      assert message(result, "relayhost", :attention) =~ "backup.example were left out"

      assert {:stdin, "pw", ["sender-relay", "set", "@example.com", "login", "sender"]} in result.commands
    end

    test "without a login, or with an unusable host" do
      result =
        migrate(
          "relayhost = [other.example]\nsmtp_sasl_auth_enable = yes\nsmtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd\n",
          nil,
          @passwords
        )

      assert result.parsed.delivery.relayhost_username == nil

      assert message(result, "smtp_sasl_auth_enable", :attention) =~
               "No login for [other.example]"

      assert message(result, "smtp_sasl_password_maps", :attention) =~ "smtp.isp.example"

      result = migrate("relayhost = [bad\n")
      assert entry(result, "relayhost", :attention)
    end
  end

  describe "limits and timers" do
    test "are converted with Postfix's units" do
      result =
        migrate("""
        maximal_queue_lifetime = 2
        minimal_backoff_time = 300
        maximal_backoff_time = 2h
        delay_warning_time = 0h
        message_size_limit = 1048576
        smtpd_client_connection_rate_limit = 30
        anvil_rate_time_unit = 2m
        disable_vrfy_command = no
        default_destination_concurrency_limit = 5
        smtp_destination_concurrency_limit = 7
        default_process_limit = 50
        smtp_connect_timeout = 10
        default_destination_rate_delay = 1s
        smtpd_policy_service_timeout = 1m
        smtp_bind_address = 192.0.2.10
        smtp_bind_address6 = not-an-ip
        inet_protocols = ipv4, ipv6
        smtp_address_preference = ipv4
        """)

      assert result.parsed.queue.max_lifetime == 2 * 86_400_000
      assert result.parsed.queue.min_backoff == 300_000
      assert result.parsed.queue.max_backoff == 7_200_000
      assert result.parsed.queue.delay_warning == nil
      assert result.parsed.smtp.max_message_size == 1_048_576
      assert result.parsed.rate_limit.client_connections == {30, 120_000}
      assert result.parsed.smtp.vrfy
      assert result.parsed.delivery.destination_concurrency == 7
      assert result.parsed.delivery.max_deliveries == 50
      assert result.parsed.delivery.connect_timeout == 10_000
      assert result.parsed.delivery.destination_rate_delay == 1000
      assert result.parsed.delivery.source_address == [{192, 0, 2, 10}]
      assert result.parsed.delivery.ip_versions == [:ipv4, :ipv6]
      assert entry(result, "delay_warning_time", :ignored)
      assert entry(result, "smtp_bind_address6", :attention)
      assert message(result, "default_process_limit", :migrated) =~ "deliveries in progress"
    end

    test "zero and bad values" do
      result =
        migrate("""
        message_size_limit = 0
        smtpd_recipient_limit = 0
        smtpd_error_sleep_time = 0
        smtpd_client_message_rate_limit = 0
        smtpd_hard_error_limit = lots
        disable_vrfy_command = maybe
        inet_protocols = ipv6
        """)

      assert entry(result, "message_size_limit", :attention)
      assert entry(result, "smtpd_recipient_limit", :attention)
      assert entry(result, "smtpd_error_sleep_time", :attention)
      assert entry(result, "smtpd_client_message_rate_limit", :ignored)
      assert entry(result, "smtpd_hard_error_limit", :attention)
      assert entry(result, "disable_vrfy_command", :attention)
      assert result.parsed.delivery.ip_versions == [:ipv6]

      result = migrate("inet_protocols = none\n")
      assert entry(result, "inet_protocols", :attention)
    end
  end

  describe "lookup tables" do
    test "aliases, rewrites, BCC rules, moved users, and transports" do
      result =
        migrate(
          """
          myorigin = example.com
          alias_maps = hash:/etc/aliases, mysql:/x, hash:/etc/missing
          canonical_maps = hash:/canonical
          recipient_canonical_maps = hash:/rc
          recipient_bcc_maps = hash:/bcc
          relocated_maps = hash:/relocated
          transport_maps = hash:/transport
          """,
          "smtp inet n - y - - smtpd\nkeep unix - - n - - smtp\n",
          %{
            "/etc/aliases" =>
              "root: \\root, admin, :include:/etc/list, /var/log/mail, x@y.example\nbad key: a\nempty:\nnone: |cmd\n",
            "/canonical" => "a@example.com b@example.com\nbad! x\nok@example.com not valid!\n",
            "/rc" => "@old.example @new.example\n",
            "/bcc" =>
              "a@example.com copy@example.com\nb@example.com not-an-address\nbad! x@y.z\n",
            "/relocated" => "gone@example.com new@example.org\nbad! x\nempty@example.com\n",
            "/transport" =>
              "* keep:[relay.example]\nexample.org error:5.1.1 nope\nbad! smtp\nexample.net unknownthing:\nexample.info lmtp:unix:private/lmtp\n"
          }
        )

      commands = result.commands

      assert ["alias", "add", "root", "root@example.com", "admin@example.com", "x@y.example"] in commands

      assert ["rewrite", "set", "both", "a@example.com", "b@example.com"] in commands
      assert ["rewrite", "set", "recipient", "@old.example", "@new.example"] in commands
      assert ["bcc", "add", "recipient", "a@example.com", "copy@example.com"] in commands
      assert ["moved", "set", "gone@example.com", "new@example.org"] in commands
      assert ["transport", "set", "*", "smtp:[relay.example]"] in commands
      assert ["transport", "set", "example.org", "error:5.1.1 nope"] in commands

      assert ["transport", "set", "example.info", "lmtp:unix:/var/spool/postfix/private/lmtp"] in commands

      text = inspect(result.entries)

      for expected <- [
            ":include: files",
            "delivery to files",
            "Some destinations were left out",
            "not a local part or address",
            "no destinations",
            "commands are not supported",
            "mysql",
            "not an address, @domain, or local part",
            "not valid!: not an address",
            "not-an-address: not an address",
            "no new location",
            "unknownthing is not a transport",
            "not an address, domain, .domain, or *",
            "inside Postfix's queue directory"
          ] do
        assert text =~ expected, expected
      end

      assert text =~ "cannot read /etc/missing"
    end

    test "sender login maps" do
      result =
        migrate(
          "smtpd_sender_login_maps = hash:/logins, ldap:/x\n",
          nil,
          %{"/logins" => "@example.com alice, bob\nbob@example.org bob\nbad! carol\n"}
        )

      assert result.parsed.auth.senders == %{
               "alice" => ["@example.com"],
               "bob" => ["@example.com", "bob@example.org"]
             }

      assert message(result, "smtpd_sender_login_maps", :attention) =~ "bad!" or
               Enum.any?(result.entries, &(&1.message =~ "ldap"))
    end

    test "sender-dependent relays" do
      result =
        migrate(
          """
          sender_dependent_relayhost_maps = hash:/relays
          smtp_sasl_password_maps = hash:/passwords
          """,
          nil,
          %{
            "/relays" =>
              "@example.com [relay.example]:587\nfine@example.org DUNNO\nbad! [x]\nx@example.net not a host!\n",
            "/passwords" => "[relay.example]:587 user:pass\n"
          }
        )

      assert ["sender-relay", "set", "@example.com", "relayhost", "[relay.example]:587"] in result.commands

      assert {:stdin, "pass", ["sender-relay", "set", "@example.com", "login", "user"]} in result.commands

      assert entry(result, "smtp_sasl_password_maps", :migrated)
      assert message(result, "sender_dependent_relayhost_maps", :attention) =~ "not a relay host"
    end

    test "the script quotes every argument and pipes passwords" do
      result =
        migrate(
          "alias_maps = hash:/a\nsender_dependent_relayhost_maps = hash:/r\nsmtp_sasl_password_maps = hash:/p\n",
          nil,
          %{
            "/a" => "o'brien: x@example.com\n",
            "/r" => "@example.com [relay.example]\n",
            "/p" => "[relay.example] u:it's $secret\n"
          }
        )

      assert result.script =~
               ~S("$sovitectl" 'alias' 'add' 'o'\''brien' 'x@example.com' || status=1)

      assert result.script =~
               ~S(printf '%s\n' 'it'\''s $secret' | "$sovitectl" 'sender-relay' 'set' '@example.com' 'login' 'u' || status=1)

      assert String.starts_with?(result.script, "#!/bin/sh\n")
      assert result.script =~ ~s(exit "$status"\n)

      assert migrate("").script =~ "# Nothing to import"
    end
  end

  describe "left over" do
    test "parameters are reported, ignored, or silent" do
      result =
        migrate(
          """
          readme_directory = no
          smtpd_banner = hi
          header_checks = regexp:/x
          my-filter_destination_recipient_limit = 1
          smtp_helo_name = custom.example
          some_unknown_parameter = 1
          """,
          "my-filter unix - - n - - smtp\n"
        )

      assert entry(result, "readme_directory") == nil
      assert entry(result, "smtpd_banner", :ignored)
      assert entry(result, "header_checks", :attention)
      assert message(result, "my-filter_destination_recipient_limit", :ignored) =~ "my-filter"
      assert entry(result, "smtp_helo_name", :attention)
      assert entry(result, "some_unknown_parameter", :attention)
    end

    test "an invalid result is reported" do
      # Two classes for one domain cannot happen, so make the config invalid
      # with a restriction stage it cannot have: an unreadable inline milter.
      result =
        Migration.migrate("smtpd_milters = inet:[::1:1\n", nil,
          read: fn _ -> {:error, :enoent} end
        )

      assert is_list(result.errors)
    end
  end
end
