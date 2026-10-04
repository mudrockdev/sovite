defmodule Sovite.Core.UsersTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.{Repo, Users}
  alias Sovite.Test.Database

  @moduletag :tmp_dir

  setup %{tmp_dir: dir}, do: %{repo: Database.start!(dir)}

  test "creates users with SCRAM hashes and checks their passwords", %{repo: repo} do
    assert {:ok, user} = Users.create(repo, " Alice@Example.com ", "secret")
    assert user.username == "alice@example.com"
    assert "{SCRAM-SHA-256}" <> _ = user.password_hash

    opts = [repo: repo]

    assert Users.verify_password("ALICE@example.com", "secret", opts) ==
             {:ok, "alice@example.com"}

    assert Users.verify_password("alice@example.com", "wrong", opts) == {:error, :invalid}
    assert Users.verify_password("bob@example.com", "x", opts) == {:error, :unknown_user}

    assert {:ok, %{iterations: 4096}, "alice@example.com"} =
             Users.scram_credentials("alice@example.com", opts)
  end

  test "refuses duplicates and invalid names", %{repo: repo} do
    {:ok, _} = Users.create(repo, "alice@example.com", "a")
    assert {:error, changeset} = Users.create(repo, "ALICE@example.com", "b")
    assert {"has already been taken", _} = changeset.errors[:username]

    assert {:error, changeset} = Users.create(repo, "bad name", "x")
    assert changeset.errors[:username]
    assert {:error, _} = Users.create(repo, "a:b", "x")
  end

  test "changes passwords, disables, and deletes", %{repo: repo} do
    {:ok, _} = Users.create(repo, "alice@example.com", "old")
    opts = [repo: repo]

    assert {:ok, _} = Users.set_password(repo, "alice@example.com", "new")
    assert {:error, :invalid} = Users.verify_password("alice@example.com", "old", opts)
    assert {:ok, _} = Users.verify_password("alice@example.com", "new", opts)

    assert {:ok, %{enabled: false}} = Users.set_enabled(repo, "alice@example.com", false)
    assert {:error, :unknown_user} = Users.verify_password("alice@example.com", "new", opts)
    assert {:error, :unknown_user} = Users.scram_credentials("alice@example.com", opts)

    assert Users.delete(repo, "Alice@example.com") == :ok
    assert Users.delete(repo, "alice@example.com") == {:error, :not_found}
    assert Users.set_password(repo, "alice@example.com", "x") == {:error, :not_found}
  end

  test "keeps sender addresses per user", %{repo: repo} do
    {:ok, _} = Users.create(repo, "alice@example.com", "x")
    assert {:ok, _} = Users.add_sender(repo, "alice@example.com", "Sales@Example.com")
    assert {:ok, _} = Users.add_sender(repo, "alice@example.com", "@example.org")
    assert {:error, changeset} = Users.add_sender(repo, "alice@example.com", "sales@example.com")
    assert changeset.errors != []
    assert {:error, _} = Users.add_sender(repo, "alice@example.com", "not an address")
    assert Users.add_sender(repo, "bob@example.com", "x@example.com") == {:error, :not_found}

    assert Users.senders(repo, "alice@example.com") == ["@example.org", "sales@example.com"]
    assert [%{username: "alice@example.com", sender_logins: [_, _]}] = Users.list(repo)

    assert Users.remove_sender(repo, "alice@example.com", "SALES@example.com") == :ok

    assert Users.remove_sender(repo, "alice@example.com", "sales@example.com") ==
             {:error, :not_found}

    assert Users.delete(repo, "alice@example.com") == :ok
    assert Users.senders(repo, "alice@example.com") == []
  end

  test "a database failure is a temporary error", %{tmp_dir: dir} do
    {module, pid} = repo = Database.start!(Path.join(dir, "other"))
    Supervisor.stop(pid)
    _ = module
    assert {:error, {:temporary, _}} = Users.verify_password("a", "b", repo: repo)
  end

  test "migrating twice is harmless", %{repo: repo} do
    assert Repo.migrate(repo) == :ok
  end
end
