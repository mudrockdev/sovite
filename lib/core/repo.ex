defmodule Sovite.Core.Repo do
  @moduledoc """
  Sovite's database, through Ecto.

  The adapter comes from the `[database]` config section: SQLite (the
  default, a single file), PostgreSQL, or MySQL. Each adapter has its own
  repo module, since Ecto fixes the adapter at compile time; this module
  picks the one the config asks for.

  The database is migrated at startup, so a new Sovite version updates
  the schema by itself. Migrations are compiled modules, listed in
  `migrations/0`, not `.exs` files, so they work in releases.

  Functions take a repo reference, `{module, name}`, so several databases
  can be open in one VM (tests use one per test).
  """

  alias Sovite.Core.Repo.Migrations

  @typedoc "A running repo: the repo module and its process name or pid."
  @type t :: {module(), GenServer.server()}

  @type adapter :: :sqlite | :postgres | :mysql

  @migrations [
    {20_261_004_000_001, Migrations.CreateUsers},
    {20_261_004_000_003, Migrations.CreateDomains},
    {20_261_004_000_004, Migrations.CreateAliases},
    {20_261_004_000_005, Migrations.CreateMailboxes},
    {20_261_004_000_006, Migrations.CreateRelocatedUsers},
    {20_261_004_000_007, Migrations.CreateTransports},
    {20_261_004_000_008, Migrations.CreateSenderRelays},
    {20_261_004_000_009, Migrations.CreateAccessRules},
    {20_261_004_000_010, Migrations.CreateAddressRewrites},
    {20_261_004_000_011, Migrations.CreateBccRules},
    {20_261_010_000_001, Migrations.CreateDMARCReportEntries},
    {20_261_010_000_002, Migrations.CreateMTASTSPolicies},
    {20_261_010_000_003, Migrations.CreateTLSReportEntries},
    {20_261_011_000_001, Migrations.CreateGreylistEntries}
  ]

  @doc "The migrations, in order, as `{version, module}`."
  @spec migrations() :: [{pos_integer(), module()}]
  def migrations, do: @migrations

  @doc "Returns the repo module for `adapter`, or `nil` if its driver is missing."
  @spec module(adapter()) :: module() | nil
  def module(:sqlite), do: Sovite.Core.Repo.SQLite
  def module(:postgres), do: loaded(Sovite.Core.Repo.Postgres)
  def module(:mysql), do: loaded(Sovite.Core.Repo.MySQL)

  defp loaded(module), do: if(Code.ensure_loaded?(module), do: module)

  @doc "The driver an adapter needs, for error messages."
  @spec driver(adapter()) :: atom()
  def driver(:sqlite), do: :ecto_sqlite3
  def driver(:postgres), do: :postgrex
  def driver(:mysql), do: :myxql

  @doc """
  Returns the reference for the repo started from `config` (the
  `[database]` section) under `name`. `name` defaults to the repo module.
  """
  @spec ref(map(), atom() | nil) :: t()
  def ref(config, name \\ nil) do
    module = module(config.adapter)
    {module, name || module}
  end

  @doc false
  def child_spec({config, name}) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [config, name]}, type: :supervisor}
  end

  @doc """
  Starts the repo for `config` and migrates the database. With `name:
  nil` the repo is unnamed: use the returned pid in the reference.
  """
  @spec start_link(map(), atom() | nil) :: {:ok, pid()} | {:error, term()}
  def start_link(config, name \\ nil) do
    module = module(config.adapter)

    with :ok <- prepare(config),
         # Query logs would carry user names and password hashes.
         {:ok, pid} <- module.start_link([name: name, log: false] ++ options(config)) do
      case migrate({module, pid}) do
        :ok ->
          {:ok, pid}

        {:error, reason} ->
          Supervisor.stop(pid)
          {:error, {:migration_failed, reason}}
      end
    end
  end

  @doc "Runs the pending migrations."
  @spec migrate(t()) :: :ok | {:error, term()}
  def migrate({module, name}) do
    Ecto.Migrator.run(module, @migrations, :up,
      all: true,
      dynamic_repo: name,
      log: false,
      log_migrations_sql: false,
      log_migrator_sql: false
    )

    :ok
  rescue
    error -> {:error, Exception.message(error)}
  end

  @doc """
  Runs `fun` with the repo module, inside the process that calls it,
  using the repo named in `ref`.
  """
  @spec run(t(), (module() -> result)) :: result when result: term()
  def run({module, name}, fun) do
    previous = module.put_dynamic_repo(name)

    try do
      fun.(module)
    after
      module.put_dynamic_repo(previous)
    end
  end

  # SQLite needs its directory; the others need nothing.
  defp prepare(%{adapter: :sqlite, path: path}) do
    case File.mkdir_p(Path.dirname(path)) do
      :ok -> init_sqlite(path)
      {:error, reason} -> {:error, {:database_directory, reason}}
    end
  end

  defp prepare(_config), do: :ok

  # Switching a database to WAL needs an exclusive lock. With several
  # pool connections doing it at once on a new file, all but one fail
  # with "database is locked", so do it once, alone, first.
  defp init_sqlite(path) do
    with {:ok, db} <- Exqlite.Sqlite3.open(path) do
      result = Exqlite.Sqlite3.execute(db, "PRAGMA journal_mode = WAL")
      Exqlite.Sqlite3.close(db)
      File.chmod(path, 0o600)
      result
    end
  end

  defp options(%{adapter: :sqlite} = config) do
    [database: config.path, pool_size: config.pool_size, journal_mode: :wal, busy_timeout: 5_000]
  end

  defp options(config) do
    [url: config.url, pool_size: config.pool_size] ++ ssl(config)
  end

  defp ssl(%{ssl: true, url: url}) do
    host = URI.parse(url).host

    [
      ssl: [
        verify: :verify_peer,
        cacerts: :public_key.cacerts_get(),
        server_name_indication: String.to_charlist(host),
        customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
      ]
    ]
  end

  defp ssl(_config), do: []
end
