defmodule Sovite.Core.FilterActionsTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias Sovite.Core.{CLI, Config}
  alias Sovite.Core.Filter.Actions
  alias Sovite.Core.Repo.Tables.FilterThresholds
  alias Sovite.Rules.Actions, as: RuleActions
  alias Sovite.Test.Database

  doctest Actions
  doctest RuleActions

  @moduletag :tmp_dir

  @config """
  [filter.actions]
  rewrite_subject = 8

  [[tenant]]
  name = "acme"
  domains = ["acme.example"]

  [tenant.filter_actions]
  reject = 20
  greylist = false
  """

  test "actions by score, most severe first" do
    thresholds = %{reject: 15.0, soft_reject: false, add_header: 6.0, greylist: nil}
    assert RuleActions.decide(15, thresholds) == :reject
    assert RuleActions.decide(14.9, thresholds) == :add_header
    assert RuleActions.decide(-3, %{}) == :no_action
    assert RuleActions.least_severe([]) == :no_action
    assert RuleActions.more_severe?(:quarantine, :rewrite_subject)
    refute RuleActions.more_severe?(:no_action, :greylist)
    assert RuleActions.parse("soft_reject") == {:ok, :soft_reject}
    assert RuleActions.parse("Reject") == :error
  end

  test "thresholds of the config, the tenant, the domain, and the address", %{tmp_dir: dir} do
    {:ok, config} = Config.parse(@config)
    repo = Database.start!(dir)

    assert Actions.thresholds(config, nil, "bob@other.example") ==
             {:ok,
              %{
                reject: 15.0,
                soft_reject: false,
                quarantine: false,
                rewrite_subject: 8.0,
                add_header: 6.0,
                greylist: 4.0
              }}

    assert {:ok, %{reject: 20.0, greylist: false, add_header: 6.0}} =
             Actions.thresholds(config, repo, "bob@Acme.example")

    # The tenant of outgoing mail is that of its sender's session.
    assert {:ok, %{reject: 20.0}} =
             Actions.thresholds(config, repo, "x@other.example", tenant: "acme")

    assert {:ok, %{reject: 15.0}} =
             Actions.thresholds(config, repo, "bob@acme.example", tenant: nil)

    {:ok, _} = FilterThresholds.set(repo, "@acme.example", :reject, 30.0)
    {:ok, _} = FilterThresholds.set(repo, "@acme.example", :quarantine, 10.0)
    {:ok, _} = FilterThresholds.set(repo, "Bob@acme.example", :reject, nil)
    {:ok, _} = FilterThresholds.set(repo, "bob@acme.example", :greylist, 2.0)

    assert {:ok, %{reject: false, quarantine: 10.0, greylist: 2.0}} =
             Actions.thresholds(config, repo, "bob@acme.example")

    assert {:ok, %{reject: 30.0, greylist: false}} =
             Actions.thresholds(config, repo, "ann@acme.example")

    # One copy for several recipients gets the least severe action.
    assert {:ok, :add_header, actions} =
             Actions.decide(config, repo, 7.0, [
               "bob@acme.example",
               "x@other.example",
               "ann@acme.example"
             ])

    assert actions == %{
             "bob@acme.example" => :add_header,
             "x@other.example" => :add_header,
             "ann@acme.example" => :add_header
           }

    assert {:ok, :quarantine, %{"bob@acme.example" => :quarantine}} =
             Actions.decide(config, repo, 25.0, ["bob@acme.example"])

    assert {:ok, :no_action, %{}} = Actions.decide(config, repo, 25.0, [])

    assert {:error, %Ecto.Changeset{}} =
             FilterThresholds.set(repo, "not an address", :reject, 1.0)

    assert FilterThresholds.delete(repo, "@acme.example", nil) == :ok
    assert FilterThresholds.delete(repo, "@acme.example", nil) == {:error, :not_found}
  end

  test "a database that fails is an error" do
    {:ok, config} = Config.parse("")
    gone = spawn(fn -> :ok end)
    repo = {Sovite.Core.Repo.SQLite, gone}

    assert {:error, {:database, _}} = Actions.thresholds(config, repo, "a@example.com")
  end

  test "the tenant's actions are checked" do
    assert {:error, [error]} =
             Config.parse(~s([[tenant]]\nname = "a"\n[tenant.filter_actions]\nreject = "high"\n))

    assert Exception.message(error) =~
             "tenant[0].filter_actions.reject: expected a score, or false"
  end

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

      assert {1, _, "error: unknown action \"bounce\"" <> _} =
               cli(config, ~w(filter threshold set @example.com bounce 1))

      assert {1, _, "error: \"lots\" is not a score: use a number, or off\n"} =
               cli(config, ~w(filter threshold set @example.com reject lots))

      assert {0, "@example.com  greylist  off\nbob@example.com  reject  from 20.0\n", _} =
               cli(config, ~w(filter threshold list))

      assert {0, stdout, _} = cli(config, ~w(filter threshold show bob@example.com))
      assert stdout =~ "reject  from 20.0\n"
      assert stdout =~ "add_header  from 6.0\n"
      assert stdout =~ "greylist  off\n"

      assert {0, "deleted bob@example.com\n", _} =
               cli(config, ~w(filter threshold delete bob@example.com reject))

      assert {1, _, "error: no such threshold\n"} =
               cli(config, ~w(filter threshold delete bob@example.com))
    end

    test "scans a message", %{config: config, rules: rules, tmp_dir: dir} do
      file = Path.join(dir, "message.eml")
      File.write!(file, "Subject: CHEAP stuff\r\n\r\nhi\r\n")

      assert {0, "score: 7.0\naction: add_header\n  CAPS  7.0 [CHEAP]\n", _} =
               cli(config, ["filter", "scan", file])

      File.write!(file, "Subject: fine\r\n\r\nhi\r\n")
      assert {0, "score: 0.0\naction: no_action\n", _} = cli(config, ["filter", "scan", file])
      assert {1, _, "error: cannot read" <> _} = cli(config, ["filter", "scan", file <> ".x"])

      File.write!(rules, "[[symbol]]\nname = \"X\"\nregex = \"x\"\n")
      assert {1, _, stderr} = cli(config, ["filter", "scan", file])
      assert stderr =~ "#{rules}: symbol[0].match: is required with regex or map"
    end
  end
end
