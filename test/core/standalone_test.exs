defmodule Sovite.Core.StandaloneTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias Sovite.Core.Standalone

  test "outside the single binary, nothing changes" do
    assert Standalone.command() == nil
  end

  test "no arguments run the server; commands run and return their status" do
    assert Standalone.command([]) == :server

    assert {:run, version} = Standalone.command(["version"])
    assert capture_io(fn -> assert version.() == 0 end) =~ ~r/\Asovite \d+\.\d+\.\d+/

    for help <- ["help", "--help", "-h"] do
      assert {:run, run} = Standalone.command([help])
      assert capture_io(fn -> assert run.() == 0 end) =~ "Usage: sovite"
    end

    assert {:run, run} = Standalone.command(["nope"])
    assert capture_io(:stderr, fn -> assert run.() == 64 end) =~ "Usage: sovite"

    assert {:run, run} = Standalone.command(["ctl", "version"])
    assert capture_io(fn -> assert run.() == 0 end) =~ "sovite "

    assert {:run, run} = Standalone.command(["newaliases"])
    assert capture_io(:stderr, fn -> assert run.() == 0 end) =~ "sovitectl alias"

    for command <- [["sendmail", "-bv"], ["mailq"]] do
      assert {:run, run} = Standalone.command(command)
      assert is_function(run, 0)
    end
  end

  @tag :tmp_dir
  test "reads the parent process", %{tmp_dir: dir} do
    assert {:ok, ppid} = Standalone.parent_pid()
    assert ppid > 0

    path = Path.join(dir, "stat")
    File.write!(path, "4242 (odd) name) S 77 4242 4242 0 -1\n")
    assert Standalone.parent_pid(path) == {:ok, 77}
    File.write!(path, "garbage")
    assert Standalone.parent_pid(path) == :error
    assert Standalone.parent_pid(Path.join(dir, "missing")) == :error
  end
end
