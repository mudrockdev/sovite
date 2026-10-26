defmodule Sovite.Core.FilterActionsTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Config
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
end
