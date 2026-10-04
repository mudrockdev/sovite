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

  test "parses byte sizes" do
    schema = [{:size, :byte_size, []}]

    for {input, bytes} <- [
          {4096, 4096},
          {"4096", 4096},
          {"10k", 10 * 1024},
          {"512M", 512 * 1024 * 1024},
          {"512 MB", 512 * 1024 * 1024},
          {"1G", 1024 * 1024 * 1024}
        ] do
      assert Schema.validate(%{"size" => input}, schema) == {:ok, %{size: bytes}}
    end

    for input <- ["0M", 0, -1, "1T", "M", "1.5G", 1.5] do
      assert [~s(size: expected a size like "512M" or "1G", got ) <> _] =
               %{"size" => input} |> Schema.validate(schema) |> messages()
    end
  end

  test "checks file names, file name patterns, and strftime formats" do
    schema = [
      {:name, :file_name, []},
      {:pattern, :file_name_pattern, []},
      {:date, :strftime, []}
    ]

    assert Schema.validate(
             %{"name" => "current.log", "pattern" => "a.{date}.{n}.log", "date" => "%Y-%m"},
             schema
           ) == {:ok, %{name: "current.log", pattern: "a.{date}.{n}.log", date: "%Y-%m"}}

    assert %{"name" => "..", "pattern" => "x/{n}", "date" => "%Y/%m"}
           |> Schema.validate(schema)
           |> messages() == [
             ~s(name: ".." is not a valid file name),
             ~s(pattern: "x/{n}" is not a valid file name),
             ~s(date: "%Y/%m" must not produce a "/")
           ]

    assert %{"pattern" => "{n}.{n}"} |> Schema.validate(schema) |> messages() ==
             [~s(pattern: "{n}.{n}" must contain {n} exactly once)]

    assert %{"pattern" => "{day}.{n}"} |> Schema.validate(schema) |> messages() ==
             [~s(pattern: "{day}.{n}" has unknown placeholder {day}, expected {date} or {n})]
  end

  test "rejects non-string values for string-like types" do
    schema = [{:host, :hostname, []}, {:mode, {:enum, [:a]}, []}]

    assert %{"host" => 1, "mode" => 2} |> Schema.validate(schema) |> messages() == [
             "host: expected a hostname string, got 1",
             ~s(mode: expected one of "a", got 2)
           ]
  end
end
