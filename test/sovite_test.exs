defmodule SoviteTest do
  use ExUnit.Case
  doctest Sovite

  test "greets the world" do
    assert Sovite.hello() == :world
  end
end
