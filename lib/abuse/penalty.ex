defmodule Sovite.Abuse.Penalty do
  @moduledoc """
  Counts failures per key (for example failed logins per client address)
  and bans a key for a while after too many of them.

      children = [
        {Sovite.Abuse.Penalty, name: MyApp.AuthPenalty, max_failures: 5, window: 600_000, ban_time: 3_600_000}
      ]

      Penalty.banned?(MyApp.AuthPenalty, ip)
      Penalty.failure(MyApp.AuthPenalty, ip)

  A key with `:max_failures` failures within `:window` milliseconds is
  banned for `:ban_time` milliseconds. Successes do not reset the count,
  so an attacker who owns one account cannot use it to keep guessing
  others.

  `banned?/2` reads an ETS table and never waits on the process, so it
  is cheap to call on every connection. State is in memory: a restart
  forgets all bans.

  ## Options

    * `:name` - an atom, also used as the ETS table name. Required.
    * `:max_failures` - required.
    * `:window` - milliseconds. Required.
    * `:ban_time` - milliseconds. Required.
    * `:cleanup_interval` - milliseconds between purges of old entries.
      Defaults to one minute.

  ## Telemetry

    * `[:sovite, :abuse, :penalty, :banned]` - `%{failures}`, `%{penalty,
      key, ban_time}`, when a key gets banned.
  """

  use GenServer

  @doc false
  def child_spec(opts),
    do: %{id: {__MODULE__, Keyword.fetch!(opts, :name)}, start: {__MODULE__, :start_link, [opts]}}

  @doc "Starts the counter."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    opts =
      Keyword.validate!(opts, [:name, :max_failures, :window, :ban_time, cleanup_interval: 60_000])

    GenServer.start_link(__MODULE__, opts, name: Keyword.fetch!(opts, :name))
  end

  @doc "Returns whether `key` is banned now."
  @spec banned?(atom(), term()) :: boolean()
  def banned?(name, key) do
    case :ets.lookup(name, key) do
      [{^key, _count, _since, banned_until}] -> banned_until > now()
      [] -> false
    end
  end

  @doc "Records a failure for `key`. Returns `:banned` if `key` is banned now."
  @spec failure(atom(), term()) :: :ok | :banned
  def failure(name, key), do: GenServer.call(name, {:failure, key})

  @doc "Forgets `key`, lifting any ban."
  @spec reset(atom(), term()) :: :ok
  def reset(name, key), do: GenServer.call(name, {:reset, key})

  @impl true
  def init(opts) do
    name = Keyword.fetch!(opts, :name)
    table = :ets.new(name, [:named_table, :protected, :set, read_concurrency: true])
    state = Map.new(opts) |> Map.put(:table, table)
    schedule(state)
    {:ok, state}
  end

  @impl true
  def handle_call({:failure, key}, _from, state) do
    now = now()

    {count, since, banned_until} =
      case :ets.lookup(state.table, key) do
        [{^key, count, since, banned_until}] when now - since < state.window ->
          {count, since, banned_until}

        [{^key, _count, _since, banned_until}] ->
          {0, now, banned_until}

        [] ->
          {0, now, 0}
      end

    count = count + 1
    newly_banned = count >= state.max_failures and banned_until <= now
    banned_until = if newly_banned, do: now + state.ban_time, else: banned_until
    :ets.insert(state.table, {key, count, since, banned_until})

    if newly_banned do
      :telemetry.execute([:sovite, :abuse, :penalty, :banned], %{failures: count}, %{
        penalty: state.name,
        key: key,
        ban_time: state.ban_time
      })
    end

    {:reply, if(banned_until > now, do: :banned, else: :ok), state}
  end

  def handle_call({:reset, key}, _from, state) do
    :ets.delete(state.table, key)
    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    now = now()
    window = state.window

    :ets.select_delete(state.table, [
      {{:_, :_, :"$1", :"$2"}, [{:andalso, {:<, :"$2", now}, {:>=, {:-, now, :"$1"}, window}}],
       [true]}
    ])

    schedule(state)
    {:noreply, state}
  end

  defp schedule(state), do: Process.send_after(self(), :cleanup, state.cleanup_interval)

  # Milliseconds since the VM started: monotonic and never negative, so 0
  # can mean "never banned".
  defp now do
    System.monotonic_time(:millisecond) -
      System.convert_time_unit(:erlang.system_info(:start_time), :native, :millisecond)
  end
end
