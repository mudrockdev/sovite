defmodule Sovite.PipeTest do
  use ExUnit.Case, async: true

  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    input = Path.join(dir, "input")
    File.write!(input, "line one\nline two\n")
    %{input: input}
  end

  defp script(dir, body) do
    path = Path.join(dir, "script-#{System.unique_integer([:positive])}")
    File.write!(path, "#!/bin/sh\n" <> body)
    File.chmod!(path, 0o755)
    path
  end

  test "feeds the file to the command and collects its output", %{tmp_dir: dir, input: input} do
    assert {:ok, 0, "line one\nline two\n"} =
             Sovite.Pipe.run([System.find_executable("cat")], input)

    # Arguments reach the command as they are, without a shell.
    echo = script(dir, ~S(printf '%s|' "$@"))
    assert {:ok, 0, "a b|$HOME|;x|"} = Sovite.Pipe.run([echo, "a b", "$HOME", ";x"], input)
  end

  test "runs in a clean environment", %{tmp_dir: dir, input: input} do
    env = script(dir, "env | sort\n")
    System.put_env("SOVITE_PIPE_SECRET", "leak")
    assert {:ok, 0, output} = Sovite.Pipe.run([env], input, env: %{"SENDER" => "a@example.com"})
    assert output =~ "SENDER=a@example.com\n"
    assert output =~ "PATH=/usr/local/bin:/usr/bin:/bin\n"
    refute output =~ "SOVITE_PIPE_SECRET"
  after
    System.delete_env("SOVITE_PIPE_SECRET")
  end

  test "uses the working directory", %{tmp_dir: dir, input: input} do
    assert {:ok, 0, output} = Sovite.Pipe.run([script(dir, "pwd\n")], input, directory: dir)
    assert String.trim(output) == dir
  end

  test "reports exit statuses and limits the output", %{tmp_dir: dir, input: input} do
    fail = script(dir, "echo 'no such user' >&2; exit 67\n")
    assert {:ok, 67, "no such user\n"} = Sovite.Pipe.run([fail], input)

    noisy = script(dir, "head -c 10000 /dev/zero; exit 0\n")
    assert {:ok, 0, output} = Sovite.Pipe.run([noisy], input, max_output: 100)
    assert byte_size(output) == 100
  end

  test "kills a command that runs too long", %{tmp_dir: dir, input: input} do
    slow = script(dir, "echo started; exec sleep 10\n")
    assert {:error, :timeout, "started\n"} = Sovite.Pipe.run([slow], input, timeout: 300)
  end

  test "refuses what it cannot run", %{tmp_dir: dir, input: input} do
    assert {:error, :enoent} = Sovite.Pipe.run(["relative/cmd"], input)
    assert {:error, :enoent} = Sovite.Pipe.run([Path.join(dir, "missing")], input)
    assert {:error, :eacces} = Sovite.Pipe.run([input], input)
    assert {:error, :eacces} = Sovite.Pipe.run([dir], input)
  end
end
