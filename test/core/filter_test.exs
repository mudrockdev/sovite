defmodule Sovite.Core.FilterTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Sovite.Core.{Config, Filter}
  alias Sovite.Core.Filter.Server

  @moduletag :tmp_dir

  @message "From: a@example.com\r\nSubject: CHEAP PILLS\r\n\r\nSee http://spam.example/x\r\n"

  defp start(dir, opts \\ []) do
    instance = make_ref()

    opts =
      Keyword.merge(
        [
          instance: instance,
          rules: [dir],
          flags: Filter.flags(),
          reload_interval: 60_000,
          timeout: 5000
        ],
        opts
      )

    pid = start_supervised!({Server, opts})
    {instance, pid}
  end

  # A check, done once the server has taken it.
  defp check(pid) do
    send(pid, :check)
    :sys.get_state(pid)
  end

  defp names(instance) do
    {:ok, result} = Filter.scan(instance, @message)
    Enum.map(result.symbols, & &1.name)
  end

  test "rule files are read in name order, and their errors are config errors", %{tmp_dir: dir} do
    File.write!(Path.join(dir, "10-base.toml"), """
    [[symbol]]
    name = "CAPS"
    score = 1.0
    match = "subject"
    regex = "CHEAP"
    """)

    File.write!(Path.join(dir, "20-local.toml"), """
    [[symbol]]
    name = "CAPS"
    regex = "("
    """)

    File.write!(Path.join(dir, "notes.txt"), "not rules")

    assert {:error, [error]} = Config.parse(~s([filter]\nrules = ["#{dir}"]))
    assert error.path == ["filter", "rules"]
    assert error.reason =~ "20-local.toml: symbol[0].regex: missing closing parenthesis"

    File.write!(Path.join(dir, "20-local.toml"), "[[symbol]]\nname = \"CAPS\"\nscore = 2.0\n")
    assert {:ok, config} = Config.parse(~s([filter]\nrules = ["#{dir}"]))
    assert config.filter.rules == [dir]

    # Not read when this node does not run the filter.
    File.write!(Path.join(dir, "30-broken.toml"), "not = [toml")
    assert {:error, [error]} = Config.parse(~s([filter]\nrules = ["#{dir}"]))
    assert error.reason =~ "30-broken.toml: invalid TOML"
    assert {:ok, _} = Config.parse(~s([stack]\nfilter = false\n[filter]\nrules = ["#{dir}"]))

    assert {:error, [error]} = Config.parse(~s([filter]\nrules = ["#{dir}/missing"]))
    assert error.reason =~ "cannot read #{dir}/missing"
  end

  test "rules and maps are loaded, and reloaded when their files change", %{tmp_dir: dir} do
    map = Path.join(dir, "domains.txt")
    File.write!(map, "other.example\n")

    File.write!(Path.join(dir, "rules.toml"), """
    [[map]]
    name = "bad"
    type = "domain"
    file = "#{map}"

    [[symbol]]
    name = "BAD_URL"
    score = 5.0
    match = "url_host"
    map = "bad"
    """)

    {instance, pid} = start(dir)
    assert names(instance) == []

    File.write!(map, "spam.example\nbad!domain\n")

    log = capture_log(fn -> check(pid) end)
    assert log =~ "map bad: entries left out"
    assert log =~ "domains.txt:2"
    assert names(instance) == ["BAD_URL"]

    # A rule set with errors is not taken.
    File.write!(Path.join(dir, "rules.toml"), "[[symbol]]\nname = \"X\"\nregex = \"x\"\n")
    assert capture_log(fn -> check(pid) end) =~ "rules not reloaded"
    assert names(instance) == ["BAD_URL"]

    File.write!(Path.join(dir, "rules.toml"), """
    [[symbol]]
    name = "CAPS"
    score = 1.0
    match = "subject"
    regex = "PILLS"
    """)

    assert capture_log(fn -> check(pid) end) =~ "rules reloaded, 1 symbols"
    assert names(instance) == ["CAPS"]

    # Also when the configuration is reloaded.
    File.write!(Path.join(dir, "rules.toml"), "")
    :telemetry.execute([:sovite, :config, :reloaded], %{}, %{path: nil, changed: []})
    capture_log(fn -> :sys.get_state(pid) end)
    assert names(instance) == []

    stop_supervised!(Server)
    assert Filter.scan(instance, @message) == {:error, :not_running}
  end

  test "the part starts only when this node runs it", %{tmp_dir: dir} do
    {:ok, config} = Config.parse(~s([filter]\nrules = ["#{dir}"]))
    assert [%{id: Server}] = Filter.child_specs(config, make_ref())

    {:ok, config} = Config.parse("[stack]\nfilter = false")
    assert Filter.child_specs(config, make_ref()) == []
  end
end
