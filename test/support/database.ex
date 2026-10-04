defmodule Sovite.Test.Database do
  @moduledoc """
  Starts a migrated SQLite database for one test, in its `tmp_dir`.

      repo = Sovite.Test.Database.start!(context.tmp_dir)
      Sovite.Core.Repo.Tables.Users.create(repo, "alice@example.com", "secret")
  """

  import ExUnit.Callbacks, only: [start_supervised!: 1]

  alias Sovite.Core.Repo

  def config(dir), do: %{adapter: :sqlite, path: Path.join(dir, "sovite.db"), pool_size: 2}

  def start!(dir) do
    config = config(dir)

    pid =
      start_supervised!(%{
        id: make_ref(),
        start: {Repo, :start_link, [config, nil]},
        type: :supervisor
      })

    {Repo.module(:sqlite), pid}
  end
end
