defmodule Sovite.Core.ConfigTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Config

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
             server: %{hostname: "mail.example.com"},
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
    assert config.listener == [%{address: {0, 0, 0, 0}, port: 25}]
    assert config.smtp.trusted_networks == []
    assert config.smtp.max_message_size == 25 * 1024 * 1024
    assert config.smtp.command_timeout == 300_000
    assert config.domains == %{local: ["mx.example.org"], relay: [], local_recipients: nil}
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

    assert config.listener == [
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
             local_recipients: ["alice@example.com"]
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
             connect_timeout: 30_000
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
end
