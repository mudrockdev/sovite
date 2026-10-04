defmodule Sovite.Core.Repo.SQLite do
  @moduledoc false
  use Ecto.Repo, otp_app: :sovite, adapter: Ecto.Adapters.SQLite3
end

# The Postgres and MySQL drivers are optional dependencies: Sovite's own
# release always has them, a project using Sovite as a library may not.
if Code.ensure_loaded?(Postgrex) do
  defmodule Sovite.Core.Repo.Postgres do
    @moduledoc false
    use Ecto.Repo, otp_app: :sovite, adapter: Ecto.Adapters.Postgres
  end
end

if Code.ensure_loaded?(MyXQL) do
  defmodule Sovite.Core.Repo.MySQL do
    @moduledoc false
    use Ecto.Repo, otp_app: :sovite, adapter: Ecto.Adapters.MyXQL
  end
end
