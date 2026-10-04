defmodule Sovite.MaildirTest do
  use ExUnit.Case, async: true

  @moduletag :tmp_dir

  test "writes a message into new/", %{tmp_dir: dir} do
    maildir = Path.join([dir, "example.com", "alice"])

    assert {:ok, path} = Sovite.Maildir.deliver(maildir, ["Subject: hi\r\n", "\r\nbody\r\n"])
    assert Path.dirname(path) == Path.join(maildir, "new")
    assert File.read!(path) == "Subject: hi\r\n\r\nbody\r\n"
    assert Path.basename(path) =~ ~r/\A\d+\.M\d+P\d+Q\d+\..+,S=21\z/

    for sub <- ~w(cur new tmp) do
      assert %File.Stat{type: :directory, mode: mode} = File.stat!(Path.join(maildir, sub))
      assert Bitwise.band(mode, 0o777) == 0o700
    end

    assert Bitwise.band(File.stat!(path).mode, 0o777) == 0o600
    assert File.ls!(Path.join(maildir, "tmp")) == []
  end

  test "file names are unique and safe", %{tmp_dir: dir} do
    paths =
      for _ <- 1..20 do
        {:ok, path} = Sovite.Maildir.deliver(dir, ["x"], hostname: "a/b:c")
        path
      end

    assert length(Enum.uniq(paths)) == 20
    assert Enum.all?(paths, &(Path.basename(&1) =~ ~r/\.a\\057b\\072c,S=1\z/))
  end

  test "a failing read leaves nothing behind", %{tmp_dir: dir} do
    data = Stream.map([1], fn _ -> raise File.Error, reason: :eio, action: "read", path: "q" end)
    assert {:error, {:read, %File.Error{}}} = Sovite.Maildir.deliver(dir, data)
    assert File.ls!(Path.join(dir, "tmp")) == []
    assert File.ls!(Path.join(dir, "new")) == []
  end

  test "reports file errors", %{tmp_dir: dir} do
    File.write!(Path.join(dir, "file"), "")
    assert {:error, :enotdir} = Sovite.Maildir.deliver(Path.join([dir, "file", "box"]), ["x"])
  end
end
