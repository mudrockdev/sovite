defmodule Sovite.Abuse.Cache do
  @moduledoc """
  A small in-memory cache with per-entry expiry, for example to remember
  clients that passed anti-abuse checks.

      children = [
        {Sovite.Abuse.Cache, name: MyApp.PassedClients, max_entries: 50_000}
      ]

      Cache.put(MyApp.PassedClients, ip, :passed, 86_400_000)
      Cache.get(MyApp.PassedClients, ip)

  Callers read and write an ETS table directly and never wait on the
  process, which only owns the table and purges expired entries. Once
  the cache holds `:max_entries` entries, new keys are refused until
  some expire, so whoever fills it cannot exhaust memory. Expired
  entries count until the next purge. State is in memory: a restart
  empties the cache.

  ## Options

    * `:name` - an atom, also used as the ETS table name. Required.
    * `:max_entries` - defaults to 100_000.
    * `:cleanup_interval` - milliseconds between purges of expired
      entries. Defaults to one minute.
  """

  use GenServer

  @doc false
  def child_spec(opts),
    do: %{id: {__MODULE__, Keyword.fetch!(opts, :name)}, start: {__MODULE__, :start_link, [opts]}}

  @doc "Starts the cache."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    opts = Keyword.validate!(opts, [:name, max_entries: 100_000, cleanup_interval: 60_000])
    GenServer.start_link(__MODULE__, opts, name: Keyword.fetch!(opts, :name))
  end

  @doc """
  Stores `value` under `key` for `ttl` milliseconds. Returns `:full`, and
  stores nothing, if `key` is new and the cache is full.
  """
  @spec put(atom(), term(), term(), non_neg_integer()) :: :ok | :full
  def put(name, key, value, ttl) when is_integer(ttl) and ttl >= 0 do
    [{:max_entries, max_entries}] = :ets.lookup(name, :max_entries)

    if size(name) < max_entries or :ets.member(name, {:entry, key}) do
      :ets.insert(name, {{:entry, key}, value, now() + ttl})
      :ok
    else
      :full
    end
  end

  @doc "Returns the value stored under `key`, unless it has expired."
  @spec get(atom(), term()) :: {:ok, term()} | :error
  def get(name, key) do
    case :ets.lookup(name, {:entry, key}) do
      [{_key, value, expires_at}] -> if expires_at > now(), do: {:ok, value}, else: :error
      [] -> :error
    end
  end

  @doc "Removes `key`."
  @spec delete(atom(), term()) :: :ok
  def delete(name, key) do
    :ets.delete(name, {:entry, key})
    :ok
  end

  @doc "Returns the number of entries, including expired ones not yet purged."
  @spec size(atom()) :: non_neg_integer()
  def size(name), do: :ets.info(name, :size) - 1

  @impl true
  def init(opts) do
    name = Keyword.fetch!(opts, :name)

    table =
      :ets.new(name, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])

    :ets.insert(table, {:max_entries, Keyword.fetch!(opts, :max_entries)})
    state = %{table: table, cleanup_interval: Keyword.fetch!(opts, :cleanup_interval)}
    schedule(state)
    {:ok, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    :ets.select_delete(state.table, [{{{:entry, :_}, :_, :"$1"}, [{:"=<", :"$1", now()}], [true]}])

    schedule(state)
    {:noreply, state}
  end

  defp schedule(state), do: Process.send_after(self(), :cleanup, state.cleanup_interval)

  # Milliseconds since the VM started: monotonic and never negative.
  defp now do
    System.monotonic_time(:millisecond) -
      System.convert_time_unit(:erlang.system_info(:start_time), :native, :millisecond)
  end
end
