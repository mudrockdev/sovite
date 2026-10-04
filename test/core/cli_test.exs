defmodule Sovite.Core.CLITest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias Sovite.Core.CLI
  alias Sovite.SASL.Password

  @moduletag :tmp_dir

  test "config check succeeds for a valid file", %{tmp_dir: dir} do
    path = Path.join(dir, "ok.toml")
    File.write!(path, ~s([server]\nhostname = "mx.example.org"\n))

    assert capture_io(fn -> assert CLI.run(["config", "check", path]) == 0 end) == "#{path}: OK\n"
  end

  test "config check prints each error and fails", %{tmp_dir: dir} do
    path = Path.join(dir, "bad.toml")
    File.write!(path, ~s([log]\nlevel = "loud"\nfoo = 1\n))

    stderr = capture_io(:stderr, fn -> assert CLI.run(["config", "check", path]) == 1 end)

    assert stderr =~ "#{path}: log.foo: unknown key"
    assert stderr =~ "#{path}: log.level: expected one of"
  end

  test "unknown commands print usage and exit 64" do
    stderr = capture_io(:stderr, fn -> assert CLI.run(["frobnicate"]) == 64 end)
    assert stderr =~ "Usage: sovitectl"
  end

  test "version prints the version" do
    assert capture_io(fn -> assert CLI.run(["version"]) == 0 end) =~ ~r/^sovite \d+\.\d+\.\d+/
  end

  test "help prints usage" do
    assert capture_io(fn -> assert CLI.run(["help"]) == 0 end) =~ "config check [PATH]"
  end

  describe "users" do
    setup %{tmp_dir: dir} do
      path = Path.join(dir, "sovite.toml")
      File.write!(path, ~s([database]\npath = "#{Path.join(dir, "sovite.db")}"\n))
      %{config: path}
    end

    defp cli(config, args, input \\ "") do
      ref = make_ref()
      parent = self()

      stdout =
        capture_io(input, fn ->
          stderr =
            capture_io(:stderr, fn ->
              send(parent, {ref, CLI.run(["--config", config | args])})
            end)

          send(parent, {ref, :stderr, stderr})
        end)

      assert_received {^ref, status}
      assert_received {^ref, :stderr, stderr}
      {status, stdout, stderr}
    end

    test "manages users and sender addresses", %{config: config} do
      assert {0, "created alice@example.com\n", _} =
               cli(config, ["user", "add", "Alice@Example.com"], "secret\n")

      assert {1, "", stderr} = cli(config, ["user", "add", "alice@example.com"], "x\n")
      assert stderr =~ "error: username has already been taken"

      assert {0, _, _} =
               cli(config, ["user", "sender", "add", "alice@example.com", "@example.org"])

      assert {1, _, stderr} =
               cli(config, ["user", "sender", "add", "alice@example.com", "nonsense"])

      assert stderr =~ "address must be"

      assert {0, "alice@example.com  enabled  senders: @example.org\n", _} =
               cli(config, ["user", "list"])

      assert {0, _, _} = cli(config, ["user", "disable", "alice@example.com"])

      assert {0, "alice@example.com  disabled  senders: @example.org\n", _} =
               cli(config, ["user", "list"])

      assert {0, _, _} = cli(config, ["user", "enable", "alice@example.com"])
      assert {0, _, _} = cli(config, ["user", "passwd", "alice@example.com"], "new\n")

      assert {0, _, _} =
               cli(config, ["user", "sender", "remove", "alice@example.com", "@example.org"])

      assert {0, _, _} = cli(config, ["user", "delete", "alice@example.com"])

      assert {1, _, "error: no such user\n"} =
               cli(config, ["user", "delete", "alice@example.com"])

      assert {0, "", _} = cli(config, ["user", "list"])
    end

    test "refuses an empty password", %{config: config} do
      assert {1, _, stderr} = cli(config, ["user", "add", "bob@example.com"], "\n")
      assert stderr =~ "error: empty password"
      assert {1, _, _} = cli(config, ["user", "add", "bob@example.com"])
    end

    test "reports config errors", %{tmp_dir: dir} do
      bad = Path.join(dir, "bad.toml")
      File.write!(bad, "[database]\nadapter = \"oracle\"\n")
      assert {1, _, stderr} = cli(bad, ["user", "list"])
      assert stderr =~ "database.adapter"
    end
  end

  test "hash-password prints a hash usable in a users file" do
    output =
      capture_io("pw\n", fn ->
        capture_io(:stderr, fn -> assert CLI.run(["hash-password"]) == 0 end)
      end)

    assert "{SCRAM-SHA-256}" <> _ = hash = String.trim(output)
    assert Password.verify(hash, "pw") == :ok

    output =
      capture_io("pw\n", fn ->
        capture_io(:stderr, fn -> CLI.run(["hash-password", "sha512-crypt"]) end)
      end)

    assert "$6$" <> _ = String.trim(output)

    assert capture_io(:stderr, fn -> assert CLI.run(["hash-password", "md5"]) == 64 end) =~
             "Usage"
  end
end
