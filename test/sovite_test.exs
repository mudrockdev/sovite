defmodule SoviteTest do
  use ExUnit.Case, async: true

  test "the application does not start the MTA unless enabled" do
    refute Application.get_env(:sovite, :start_mta, false)
    assert Supervisor.which_children(Sovite.Supervisor) == []
  end
end
