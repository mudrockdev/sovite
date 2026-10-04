defmodule Sovite.Core.DatabaseAdaptersTest do
  # Runs the users schema on real PostgreSQL and MySQL servers. Excluded
  # by default; run with a server URL, for example:
  #
  #   SOVITE_TEST_POSTGRES_URL=postgres://postgres:pw@localhost:5432/sovite_test \
  #     mix test --only postgres
  #
  #   SOVITE_TEST_MYSQL_URL=mysql://root:pw@localhost:3306/sovite_test \
  #     mix test --only mysql
  use ExUnit.Case, async: false

  alias Sovite.Core.{Repo, Users}

  for {adapter, env} <- [postgres: "SOVITE_TEST_POSTGRES_URL", mysql: "SOVITE_TEST_MYSQL_URL"] do
    @tag adapter
    test "users and sender logins work on #{adapter}" do
      url = System.get_env(unquote(env)) || flunk("set #{unquote(env)}")
      config = %{adapter: unquote(adapter), url: url, pool_size: 2, ssl: false}
      module = Repo.module(unquote(adapter))

      pid =
        start_supervised!(%{
          id: :repo,
          start: {Repo, :start_link, [config, nil]},
          type: :supervisor
        })

      repo = {module, pid}

      # Start from a clean table each run.
      Repo.run(repo, fn m -> m.delete_all(Users.User) end)

      assert {:ok, _} = Users.create(repo, "Alice@Example.com", "secret")

      assert {:ok, "alice@example.com"} =
               Users.verify_password("alice@example.com", "secret", repo: repo)

      assert {:error, _} = Users.create(repo, "alice@example.com", "again")
      assert {:ok, _} = Users.add_sender(repo, "alice@example.com", "@example.org")
      assert Users.senders(repo, "alice@example.com") == ["@example.org"]
      assert Users.remove_sender(repo, "alice@example.com", "@example.org") == :ok
      assert Users.delete(repo, "alice@example.com") == :ok
      assert Repo.migrate(repo) == :ok
    end
  end
end
