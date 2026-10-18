defmodule Sovite.Core.Cluster.SharedConfigTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Cluster.SharedConfig

  @moduletag :tmp_dir

  test "writes and reads versions", %{tmp_dir: dir} do
    path = Path.join([dir, "sub", "cluster.toml"])
    assert SharedConfig.read(path) == nil
    assert SharedConfig.read(nil) == nil

    shared = %{version: 3, origin: "mx1@10.0.0.1", content: "[smtp]\nmax_errors = 7\n"}
    assert SharedConfig.write(path, shared) == :ok
    assert SharedConfig.read(path) == shared

    assert File.read!(path) =~
             ~r/\A# sovite shared config: version 3, from mx1@10.0.0.1, \S+Z\n\[smtp\]/

    assert Bitwise.band(File.stat!(path).mode, 0o777) == 0o640

    # Written by hand: version 0.
    File.write!(path, "[smtp]\n")
    assert SharedConfig.read(path) == %{version: 0, origin: "", content: "[smtp]\n"}
  end

  test "newer versions, then the origin that sorts last" do
    a = %{version: 2, origin: "a"}
    assert SharedConfig.newer?(a, nil)
    assert SharedConfig.newer?(a, %{version: 1, origin: "z"})
    assert SharedConfig.newer?(%{version: 2, origin: "b"}, a)
    refute SharedConfig.newer?(a, a)
    refute SharedConfig.newer?(%{version: 1, origin: "z"}, a)
  end

  test "checks a version with the node's own file", %{tmp_dir: dir} do
    local = Path.join(dir, "sovite.toml")
    File.write!(local, "[cluster]\nshared_config = \"#{dir}/cluster.toml\"\n")

    assert SharedConfig.check(local, "[smtp]\nmax_errors = 3") == :ok
    assert {:error, [error]} = SharedConfig.check(local, "[smtp]\nmax_errors = 0")
    assert error =~ "smtp.max_errors"
    assert {:error, [error]} = SharedConfig.check(local, "[cluster]\nenabled = true")
    assert error =~ "cannot have a [cluster] table"

    assert SharedConfig.check(nil, "") ==
             {:error, ["the server was started without a config file"]}
  end
end
