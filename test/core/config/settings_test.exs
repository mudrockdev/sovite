defmodule Sovite.Core.Config.SettingsTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Config
  alias Sovite.Core.Config.Settings

  test "a loaded config keeps its file for the settings" do
    {:ok, config} = Config.parse("[smtp]\nmax_recipients = 10")
    assert {"smtp.max_recipients", "10", false} in Settings.list(config.raw)
  end

  # The settings of a file, valid or not: they are read from the TOML.
  defp settings(toml), do: toml |> Toml.decode!() |> Settings.list()

  defp setting(settings, key), do: List.keyfind(settings, key, 0)

  test "lists every key with its value or default" do
    settings =
      settings("""
      [server]
      hostname = "mx.example.org"
      [smtp]
      max_recipients = 10
      [[listener]]
      port = 2525
      [[listener]]
      mode = "submission"
      [pipe.spam]
      command = ["/usr/bin/spamc"]
      [delivery.tls_policy]
      "example.com" = "verify"
      """)

    assert setting(settings, "server.hostname") ==
             {"server.hostname", ~s("mx.example.org"), false}

    assert setting(settings, "smtp.max_recipients") == {"smtp.max_recipients", "10", false}

    assert setting(settings, "smtp.max_message_size") ==
             {"smtp.max_message_size", ~s("25M"), true}

    assert setting(settings, "listener[0].port") == {"listener[0].port", "2525", false}
    assert setting(settings, "listener[1].mode") == {"listener[1].mode", ~s("submission"), false}
    # Mode defaults are not schema defaults.
    assert setting(settings, "listener[1].port") == nil

    assert setting(settings, "pipe.spam.command") ==
             {"pipe.spam.command", ~s(["/usr/bin/spamc"]), false}

    assert setting(settings, "pipe.spam.timeout") == {"pipe.spam.timeout", ~s("10m"), true}

    assert setting(settings, "delivery.tls_policy") ==
             {"delivery.tls_policy", ~s({ "example.com" = "verify" }), false}

    assert setting(settings, "delivery.ip_versions") ==
             {"delivery.ip_versions", ~s(["ipv6", "ipv4"]), true}

    assert setting(settings, "tracing.sample_ratio") == {"tracing.sample_ratio", "1.0", true}
    # Unset, without a default.
    assert setting(settings, "delivery.relayhost") == nil
  end

  test "the default listener is listed as a default" do
    settings = settings("")
    assert {"listener[0].address", ~s("0.0.0.0"), true} = setting(settings, "listener[0].address")
  end

  test "hides secrets" do
    settings =
      settings("""
      [database]
      adapter = "postgres"
      url = "postgres://sovite:hunter2@db.example.com/sovite"
      [delivery]
      relayhost_username = "user"
      relayhost_password = "hunter2"
      [srs]
      secrets = ["s3cret"]
      [tracing]
      headers = { authorization = "Bearer hunter2" }
      """)

    assert {_, url, false} = setting(settings, "database.url")
    assert url == ~s("postgres://sovite:********@db.example.com/sovite")
    assert setting(settings, "delivery.relayhost_password") |> elem(1) == ~s("********")
    assert setting(settings, "delivery.relayhost_username") |> elem(1) == ~s("user")
    assert setting(settings, "srs.secrets") |> elem(1) == ~s("********")
    assert setting(settings, "tracing.headers") |> elem(1) == ~s({ authorization = "********" })
    refute Settings.format(settings) =~ "hunter2"
  end

  test "diff and format" do
    old = settings("[smtp]\nmax_recipients = 10\n[delivery]\nrelayhost = \"[relay.example]\"")
    new = settings("[smtp]\nmax_recipients = 20\n[dkim]\nexpiration = \"7d\"")

    assert Settings.diff(old, new) == [
             {"delivery.relayhost", ~s("[relay.example]"), nil},
             {"dkim.expiration", nil, ~s("7d")},
             {"smtp.max_recipients", "10", "20"}
           ]

    assert Settings.diff(old, old) == []
    assert Settings.format([{"a.b", "1", true}, {"c", ~s("x"), false}]) == ~s(a.b = 1\nc = "x"\n)
  end
end
