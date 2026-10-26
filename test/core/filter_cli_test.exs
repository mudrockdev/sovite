defmodule Sovite.Core.FilterCLITest do
  # sovitectl writes errors to standard error, which capture_io captures
  # for every process: not async, so other tests' errors are not mixed in.
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Sovite.Core.CLI
  alias Sovite.Test.FakeNameserver

  @moduletag :tmp_dir

  describe "sovitectl filter" do
    setup %{tmp_dir: dir} do
      path = Path.join(dir, "sovite.toml")
      rules = Path.join(dir, "rules.toml")

      File.write!(rules, """
      [[symbol]]
      name = "CAPS"
      score = 7.0
      match = "subject"
      regex = "CHEAP"
      """)

      File.write!(path, """
      [database]
      path = "#{Path.join(dir, "sovite.db")}"

      [filter]
      rules = ["#{rules}"]
      """)

      %{config: path, rules: rules}
    end

    defp cli(config, args, input \\ "") do
      parent = self()

      stdout =
        capture_io(input, fn ->
          stderr =
            capture_io(:stderr, fn ->
              send(parent, {:status, CLI.run(["--config", config | args])})
            end)

          send(parent, {:stderr, stderr})
        end)

      assert_received {:status, status}
      assert_received {:stderr, stderr}
      {status, stdout, stderr}
    end

    test "manages thresholds", %{config: config} do
      assert {0, "bob@example.com: reject from 20.0\n", _} =
               cli(config, ~w(filter threshold set bob@example.com reject 20))

      assert {0, "@example.com: greylist off\n", _} =
               cli(config, ~w(filter threshold set @example.com greylist off))

      assert {1, _, stderr} = cli(config, ~w(filter threshold set @example.com bounce 1))
      assert stderr =~ "error: unknown action \"bounce\""

      assert {1, _, stderr} = cli(config, ~w(filter threshold set @example.com reject lots))
      assert stderr =~ "error: \"lots\" is not a score: use a number, or off\n"

      assert {0, "@example.com  greylist  off\nbob@example.com  reject  from 20.0\n", _} =
               cli(config, ~w(filter threshold list))

      assert {0, stdout, _} = cli(config, ~w(filter threshold show bob@example.com))
      assert stdout =~ "reject  from 20.0\n"
      assert stdout =~ "add_header  from 6.0\n"
      assert stdout =~ "greylist  off\n"

      assert {0, "deleted bob@example.com\n", _} =
               cli(config, ~w(filter threshold delete bob@example.com reject))

      assert {1, _, stderr} = cli(config, ~w(filter threshold delete bob@example.com))
      assert stderr =~ "error: no such threshold\n"
    end

    test "scans a message with Sovite's checks", %{config: config, tmp_dir: dir} do
      {:ok, ns} =
        FakeNameserver.start_link(%{
          {"example.com", :txt} => [[~c"v=spf1 ip4:192.0.2.1 -all"]],
          {"9.2.0.192.in-addr.arpa", :ptr} => [~c"client.example"]
        })

      {_, port} = FakeNameserver.address(ns)

      File.write!(
        config,
        File.read!(config) <> "[dns]\nnameservers = [\"127.0.0.1\"]\nport = #{port}\n"
      )

      file = Path.join(dir, "message.eml")
      File.write!(file, "From: a@example.com\r\nSubject: CHEAP\r\n\r\nhi\r\n")

      args = ~w(filter scan --ip 192.0.2.9 --helo client.example --from a@example.com) ++ [file]
      assert {0, stdout, _} = cli(config, args)
      assert stdout =~ "  R_SPF_FAIL  1.0 [example.com, -all]\n"
      assert stdout =~ "  R_DKIM_NA  0.0\n"
      assert stdout =~ "  RDNS_UNCONFIRMED  1.0 [client.example]\n"
      assert stdout =~ "  CAPS  7.0 [CHEAP]\n"
      assert stdout =~ "score: 9.0\naction: add_header\n"

      assert {64, _, _} = cli(config, ~w(filter scan --bogus))
    end

    test "scans a message", %{config: config, rules: rules, tmp_dir: dir} do
      file = Path.join(dir, "message.eml")
      File.write!(file, "Subject: CHEAP stuff\r\n\r\nhi\r\n")

      assert {0, "score: 7.0\naction: add_header\n  CAPS  7.0 [CHEAP]\n", _} =
               cli(config, ["filter", "scan", file])

      File.write!(file, "Subject: fine\r\n\r\nhi\r\n")
      assert {0, "score: 0.0\naction: no_action\n", _} = cli(config, ["filter", "scan", file])
      assert {1, _, stderr} = cli(config, ["filter", "scan", file <> ".x"])
      assert stderr =~ "error: cannot read"

      File.write!(rules, "[[symbol]]\nname = \"X\"\nregex = \"x\"\n")
      assert {1, _, stderr} = cli(config, ["filter", "scan", file])
      assert stderr =~ "#{rules}: symbol[0].match: is required with regex or map"
    end
  end
end
