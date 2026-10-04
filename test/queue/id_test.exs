defmodule Sovite.Queue.IDTest do
  use ExUnit.Case, async: true

  alias Sovite.Queue.ID

  test "generates 14 alphanumeric characters" do
    for _ <- 1..1000 do
      id = ID.generate()
      assert id =~ ~r/\A[0-9A-Za-z]{14}\z/
      assert ID.valid?(id)
    end
  end

  test "generated IDs are unique" do
    ids = for _ <- 1..10_000, do: ID.generate()
    assert ids |> Enum.uniq() |> length() == 10_000
  end

  test "IDs generated in sequence sort by creation time" do
    ids =
      for _ <- 1..20 do
        id = ID.generate()
        Process.sleep(1)
        id
      end

    assert Enum.sort(ids) == ids
  end

  test "valid?/1" do
    assert ID.valid?("0Q7c3XbK2mA9fZ")
    assert ID.valid?("00000000000000")
    refute ID.valid?("0Q7c3XbK2mA9f")
    refute ID.valid?("0Q7c3XbK2mA9fZZ")
    refute ID.valid?("0Q7c3XbK2mA9f-")
    refute ID.valid?("0Q7c3XbK2mA9f/")
    refute ID.valid?("../../etc/pass")
    refute ID.valid?("0Q7c3XbK2mA9f\n")
    refute ID.valid?("0Q7c3XbK2mA9é")
    refute ID.valid?("")
    refute ID.valid?(nil)
    refute ID.valid?(~c"0Q7c3XbK2mA9fZ")
  end
end
