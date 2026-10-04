defmodule Sovite.Core.ConfigTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Config

  @moduletag :tmp_dir

  test "fills in defaults for an empty file" do
    assert {:ok, config} = Config.parse("")
    assert config.queue.directory == "/var/spool/sovite"
    assert config.log == %{level: :info, format: :text}
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
    """

    assert {:ok, config} = Config.parse(toml)

    assert config == %Config{
             server: %{hostname: "mail.example.com"},
             queue: %{directory: "/srv/sovite/queue"},
             log: %{level: :debug, format: :json}
           }
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
    """

    assert {:error, errors} = Config.parse(toml)

    assert Enum.map(errors, &Exception.message/1) == [
             "typo: unknown key",
             ~s(server.hostname: "not a hostname" is not a valid hostname),
             "queue.extra: unknown key",
             ~s(queue.directory: "relative/path" is not an absolute path),
             ~s(log.level: expected one of "debug", "info", "notice", "warning", "error", got "loud"),
             ~s(log.format: expected one of "text", "json", got 1)
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
