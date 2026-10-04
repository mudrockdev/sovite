defmodule Sovite.Core.CLITest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias Sovite.Core.CLI

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
end
