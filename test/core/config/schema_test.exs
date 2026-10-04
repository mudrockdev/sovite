defmodule Sovite.Core.Config.SchemaTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Config.Schema

  @schema [
    {:name, :string, required: true},
    {:enabled, :boolean, default: false},
    {:port, {:integer, 1, 65_535}, default: 25},
    {:mode, {:enum, [:fast, :safe]}, default: :bogus},
    {:optional, :string, []},
    {:nested, {:section, [{:path, :absolute_path, default: "/tmp"}]}, []}
  ]

  defp messages({:error, errors}), do: Enum.map(errors, &Exception.message/1)

  test "casts values and applies defaults" do
    input = %{"name" => "x", "enabled" => true, "port" => 587, "mode" => "safe"}

    assert Schema.validate(input, @schema) ==
             {:ok,
              %{
                name: "x",
                enabled: true,
                port: 587,
                mode: :safe,
                optional: nil,
                nested: %{path: "/tmp"}
              }}
  end

  test "reports missing required keys, type errors, and invalid defaults" do
    input = %{"enabled" => "yes", "port" => 0, "optional" => 5, "nested" => %{"path" => 1}}

    assert input |> Schema.validate(@schema) |> messages() == [
             "name: is required",
             ~s(enabled: expected true or false, got "yes"),
             "port: expected an integer from 1 to 65535, got 0",
             ~s(mode: expected one of "fast", "safe", got :bogus (default value\)),
             "optional: expected a string, got 5",
             "nested.path: expected an absolute path, got 1"
           ]
  end

  test "rejects non-string values for string-like types" do
    schema = [{:host, :hostname, []}, {:mode, {:enum, [:a]}, []}]

    assert %{"host" => 1, "mode" => 2} |> Schema.validate(schema) |> messages() == [
             "host: expected a hostname string, got 1",
             ~s(mode: expected one of "a", got 2)
           ]
  end
end
