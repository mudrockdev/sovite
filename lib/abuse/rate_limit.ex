defmodule Sovite.Abuse.RateLimit do
  @moduledoc """
  Counts events per key over sliding windows, for limits such as "100
  messages per hour per client address".

      children = [
        {Sovite.Abuse.RateLimit, name: MyApp.RateLimit}
      ]

      case RateLimit.hit(MyApp.RateLimit, ip, 100, 3_600_000) do
        :ok -> accept()
        :limited -> defer()
      end

  Each window is split into fixed buckets of its own length, and the
  count is estimated from the current bucket plus the share of the
  previous one that still falls inside the window. This needs two
  counters per key and window, and is accurate enough for abuse limits.
  One table can hold limits with different windows for the same key.

  Callers update an ETS table directly and never wait on the process,
  which only owns the table and purges old buckets. Concurrent hits can
  refuse a little more than strictly needed, never less. State is in
  memory: a restart forgets all counts.

  ## Options

    * `:name` - an atom, also used as the ETS table name. Required.
    * `:cleanup_interval` - milliseconds between purges of old buckets.
      Defaults to one minute.
    * `:clock` - a zero-arity function returning the current time in
      milliseconds. For tests.

  ## Telemetry

    * `[:sovite, :abuse, :rate_limit, :exceeded]` - `%{limit, window}`,
      `%{rate_limit, key}`, on the first refused hit of a key and window
      in each bucket.
  """

  use GenServer

  @doc false
  def child_spec(opts),
    do: %{id: {__MODULE__, Keyword.fetch!(opts, :name)}, start: {__MODULE__, :start_link, [opts]}}

  @doc "Starts the rate limiter."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    opts = Keyword.validate!(opts, [:name, :clock, cleanup_interval: 60_000])
    GenServer.start_link(__MODULE__, opts, name: Keyword.fetch!(opts, :name))
  end

  @doc """
  Counts `count` events for `key` unless that would take it over `limit`
  events in the last `window` milliseconds. A refused hit is not counted.
  """
  @spec hit(atom(), term(), non_neg_integer(), pos_integer(), pos_integer()) :: :ok | :limited
  def hit(name, key, limit, window, count \\ 1)
      when is_integer(limit) and limit >= 0 and is_integer(window) and window > 0 and
             is_integer(count) and count > 0 do
    now = now(name)
    bucket = div(now, window)
    row = {key, window, bucket}
    current = :ets.update_counter(name, row, {2, count}, {row, 0, 0})
    previous = previous(name, key, window, bucket)

    if scaled_estimate(previous, current, now, window) > limit * window do
      [_count, refusals] = :ets.update_counter(name, row, [{2, -count}, {3, 1}])

      if refusals == 1 do
        :telemetry.execute(
          [:sovite, :abuse, :rate_limit, :exceeded],
          %{limit: limit, window: window},
          %{rate_limit: name, key: key}
        )
      end

      :limited
    else
      :ok
    end
  end

  @doc """
  Counts `count` events for `key` without a limit. Returns the number of
  events in the last `window` milliseconds, rounded down.
  """
  @spec add(atom(), term(), pos_integer(), pos_integer()) :: non_neg_integer()
  def add(name, key, window, count \\ 1)
      when is_integer(window) and window > 0 and is_integer(count) and count > 0 do
    now = now(name)
    bucket = div(now, window)
    row = {key, window, bucket}
    current = :ets.update_counter(name, row, {2, count}, {row, 0, 0})
    div(scaled_estimate(previous(name, key, window, bucket), current, now, window), window)
  end

  @doc "Returns the number of events for `key` in the last `window` milliseconds, rounded down."
  @spec count(atom(), term(), pos_integer()) :: non_neg_integer()
  def count(name, key, window) when is_integer(window) and window > 0 do
    now = now(name)
    bucket = div(now, window)

    current =
      case :ets.lookup(name, {key, window, bucket}) do
        [{_row, count, _refusals}] -> count
        [] -> 0
      end

    div(scaled_estimate(previous(name, key, window, bucket), current, now, window), window)
  end

  @doc "Forgets every window of `key`."
  @spec reset(atom(), term()) :: :ok
  def reset(name, key) do
    :ets.select_delete(name, [
      {{{:"$1", :_, :_}, :_, :_}, [{:"=:=", :"$1", {:const, key}}], [true]}
    ])

    :ok
  end

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

    clock = Keyword.get(opts, :clock)
    if clock, do: :ets.insert(table, {:clock, clock})

    state = %{
      table: table,
      clock: clock,
      cleanup_interval: Keyword.fetch!(opts, :cleanup_interval)
    }

    schedule(state)
    {:ok, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    now = if state.clock, do: state.clock.(), else: now()

    :ets.select_delete(state.table, [
      {{{:_, :"$1", :"$2"}, :_, :_}, [{:<, :"$2", {:-, {:div, now, :"$1"}, 1}}], [true]}
    ])

    schedule(state)
    {:noreply, state}
  end

  defp schedule(state), do: Process.send_after(self(), :cleanup, state.cleanup_interval)

  defp previous(name, key, window, bucket) do
    case :ets.lookup(name, {key, window, bucket - 1}) do
      [{_row, count, _refusals}] -> count
      [] -> 0
    end
  end

  # The estimate multiplied by `window`, to stay in integers.
  defp scaled_estimate(previous, current, now, window),
    do: previous * (window - rem(now, window)) + current * window

  defp now(name) do
    case :ets.lookup(name, :clock) do
      [{:clock, clock}] -> clock.()
      [] -> now()
    end
  end

  # Milliseconds since the VM started: monotonic and never negative.
  defp now do
    System.monotonic_time(:millisecond) -
      System.convert_time_unit(:erlang.system_info(:start_time), :native, :millisecond)
  end
end
