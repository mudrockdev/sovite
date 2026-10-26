defmodule Sovite.Core.MTA.IPPools do
  @moduledoc """
  Outbound IP pools (`[[ip_pool]]`): the source addresses mail goes out
  from, with warm-up schedules and daily limits.

      [delivery]
      ip_pool = "shared"

      [[ip_pool]]
      name = "shared"

      [[ip_pool.address]]
      address = "192.0.2.10"
      helo = "mta1.example.com"

      [[ip_pool.address]]
      address = "192.0.2.11"
      helo = "mta2.example.com"
      warmup_start = 2026-10-01
      warmup = [50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000]
      daily_limit = 100000

  SMTP deliveries use the pool of their message's tenant
  (`Sovite.Core.Tenants`), else `delivery.ip_pool`. A source address the
  sender relays table gives for the sender comes first; a pool comes
  before `delivery.source_address`.

  ## Picking an address

  Each connection picks one IPv4 and one IPv6 address of the pool, for
  whichever family the next hop has, among those with room left today.
  The address with the most room left, as a share of its limit, goes
  first, so new addresses grow into their share as their warm-up goes
  on. A connection says `helo` in `EHLO` when its address has one
  (which should be the name the address's reverse DNS gives), else
  `server.hostname`.

  An address's limit for a day (UTC) is the `warmup` entry for that day,
  counting `warmup_start` as the first; after the schedule, it is
  `daily_limit`, or none. An address is not used before its
  `warmup_start`. Every message sent from an address counts, once per
  connection that delivered it.

  When no address of a pool has room left, the pool's `overflow` pool
  is used, if it has one, else the delivery is deferred until the next
  day starts, with `4.7.0`. Counts are kept in the `ip_address_counts`
  table, so they survive restarts.

  ## Clusters

  In a cluster, an address can be on another node (`node`): only that
  node uses it. When a pool has no address on this node, its mail is
  handed to a node that has some (see `Sovite.Core.MTA.Cluster.Queue`).

  ## Telemetry

    * `[:sovite, :ip_pool, :exhausted]` - `%{}`, `%{pool}`, when a
      delivery finds no address with room left in a pool or its
      overflow pools.
  """

  use GenServer

  require Logger

  alias Sovite.Core.Repo.Tables.IPAddressCounts

  @flush_interval 10_000

  @typedoc "Addresses to connect from, by family, and their `EHLO` names."
  @type source :: %{
          source: %{optional(:ipv4 | :ipv6) => :inet.ip_address()},
          helo: %{optional(:ipv4 | :ipv6) => String.t()}
        }

  @doc false
  def child_spec(opts),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, shutdown: 10_000}

  @doc """
  The child spec options from the config, or `nil` without pools.
  `node` is this node's name in a cluster, or `nil`.
  """
  @spec opts(Sovite.Core.Config.t(), atom(), Sovite.Core.Repo.t() | nil) :: keyword() | nil
  def opts(%{ip_pool: []}, _name, _repo), do: nil

  def opts(config, name, repo) do
    node = if config.cluster.enabled, do: config.cluster.node_name

    pools =
      Map.new(config.ip_pool, fn pool ->
        addresses =
          for address <- pool.address do
            %{
              ip: address.address,
              text: address.address |> :inet.ntoa() |> to_string(),
              family: if(tuple_size(address.address) == 4, do: :ipv4, else: :ipv6),
              helo: address.helo,
              node: address.node,
              local: address.node in [nil, node],
              warmup_start: address.warmup_start,
              warmup: address.warmup,
              daily_limit: address.daily_limit
            }
          end

        {pool.name, %{overflow: pool.overflow, addresses: addresses}}
      end)

    [name: name, repo: repo, pools: pools]
  end

  @doc "Starts the pool counters."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.fetch!(opts, :name))

  @doc """
  The addresses to connect from for pool `pool`, or `{:error, text}`
  when none has room left today.
  """
  @spec source(atom(), String.t()) :: {:ok, source()} | {:error, String.t()}
  def source(name, pool), do: source(name, pool, today(), [])

  defp source(name, pool, day, seen) do
    pools = pools(name)

    case Map.fetch(pools, pool) do
      {:ok, config} ->
        picked =
          for family <- [:ipv4, :ipv6],
              address = pick(name, config.addresses, family, day),
              address != nil,
              do: address

        cond do
          picked != [] ->
            {:ok,
             %{
               source: Map.new(picked, &{&1.family, &1.ip}),
               helo:
                 for(%{helo: helo} = a <- picked, helo != nil, into: %{}, do: {a.family, helo})
             }}

          config.overflow != nil and config.overflow not in seen ->
            source(name, config.overflow, day, [pool | seen])

          true ->
            :telemetry.execute([:sovite, :ip_pool, :exhausted], %{}, %{pool: pool})
            {:error, "IP pool #{pool} has reached its daily limit"}
        end

      :error ->
        {:error, "there is no IP pool #{pool}"}
    end
  end

  defp pick(name, addresses, family, day) do
    addresses
    |> Enum.filter(&(&1.local and &1.family == family))
    |> Enum.map(&{&1, room(&1, limit(&1, day), sent(name, &1.text, day))})
    |> Enum.filter(fn {_address, room} -> room > 0 end)
    |> Enum.max_by(fn {_address, room} -> room end, fn -> nil end)
    |> case do
      nil -> nil
      {address, _room} -> address
    end
  end

  # The share of the day's limit left, from 0 to 1; 2 without a limit.
  defp room(_address, :infinity, _count), do: 2
  defp room(_address, 0, _count), do: 0
  defp room(_address, limit, count), do: max(limit - count, 0) / limit

  @doc """
  The limit of an address (from `opts/3`) on `day`: messages, or
  `:infinity`.
  """
  @spec limit(map(), Date.t()) :: non_neg_integer() | :infinity
  def limit(%{warmup_start: nil} = address, _day), do: address.daily_limit || :infinity

  def limit(address, day) do
    case Date.diff(day, address.warmup_start) do
      days when days < 0 -> 0
      days when days < length(address.warmup) -> Enum.at(address.warmup, days)
      _days -> address.daily_limit || :infinity
    end
  end

  @doc """
  Whether address `ip` has room left today, for a connection from it
  that is reused.
  """
  @spec room?(atom(), :inet.ip_address()) :: boolean()
  def room?(name, ip) do
    text = ip |> :inet.ntoa() |> to_string()
    day = today()

    pools(name)
    |> Map.values()
    |> Enum.flat_map(& &1.addresses)
    |> Enum.filter(&(&1.text == text))
    |> Enum.any?(&(room(&1, limit(&1, day), sent(name, text, day)) > 0))
  end

  @doc """
  Whether pool `pool` can send from this node: `:local`, or `{:remote,
  nodes}` with the names of the nodes that have its addresses, when it
  has none here. Overflow pools count too.
  """
  @spec placement(atom(), String.t()) :: :local | {:remote, [String.t()]}
  def placement(name, pool) do
    case addresses(pools(name), pool, []) do
      [] ->
        :local

      addresses ->
        if Enum.any?(addresses, & &1.local),
          do: :local,
          else: {:remote, addresses |> Enum.map(& &1.node) |> Enum.uniq() |> Enum.sort()}
    end
  end

  defp addresses(pools, pool, seen) do
    case Map.fetch(pools, pool) do
      {:ok, config} ->
        overflow =
          if config.overflow && config.overflow not in seen,
            do: addresses(pools, config.overflow, [pool | seen]),
            else: []

        config.addresses ++ overflow

      :error ->
        []
    end
  end

  @doc "Counts `messages` sent from `ip` today."
  @spec count(atom(), :inet.ip_address(), pos_integer()) :: :ok
  def count(name, ip, messages) when messages > 0 do
    key = {:count, ip |> :inet.ntoa() |> to_string(), today()}
    :ets.update_counter(name, key, {2, messages}, {key, 0})
    pending = {:pending, elem(key, 1), elem(key, 2)}
    :ets.update_counter(name, pending, {2, messages}, {pending, 0})
    :ok
  end

  def count(_name, _ip, 0), do: :ok

  @doc """
  The pools with their addresses, and for each the messages sent today
  and today's limit, for status pages.
  """
  @spec status(atom()) :: [map()]
  def status(name) do
    day = today()

    for {pool, config} <- Enum.sort(pools(name)) do
      %{
        name: pool,
        overflow: config.overflow,
        addresses:
          for address <- config.addresses do
            %{
              address: address.text,
              node: address.node,
              helo: address.helo,
              sent_today: sent(name, address.text, day),
              limit_today:
                case limit(address, day) do
                  :infinity -> nil
                  limit -> limit
                end
            }
          end
      }
    end
  end

  defp pools(name) do
    case :ets.lookup(name, :pools) do
      [{:pools, pools}] -> pools
      [] -> %{}
    end
  end

  defp sent(name, text, day) do
    case :ets.lookup(name, {:count, text, day}) do
      [{_key, count}] -> count
      [] -> 0
    end
  end

  defp today, do: Date.utc_today()

  ## Server

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    name = Keyword.fetch!(opts, :name)
    table = :ets.new(name, [:named_table, :public, :set, read_concurrency: true])
    :ets.insert(table, {:pools, Keyword.fetch!(opts, :pools)})
    state = %{table: table, repo: Keyword.fetch!(opts, :repo), loaded: nil}
    Process.send_after(self(), :flush, @flush_interval)
    {:ok, load(state)}
  end

  @impl true
  def handle_info(:flush, state) do
    Process.send_after(self(), :flush, @flush_interval)
    {:noreply, state |> flush() |> load()}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state), do: flush(state)

  # Today's counts from the database, once a day, and those not stored
  # yet.
  defp load(%{loaded: day} = state) do
    today = today()

    if day == today or state.repo == nil do
      state
    else
      stored = IPAddressCounts.day(state.repo, today)
      :ets.match_delete(state.table, {{:count, :_, :_}, :_})

      for {text, messages} <- stored,
          messages > 0,
          do: :ets.insert(state.table, {{:count, text, today}, messages})

      for {{:pending, text, ^today}, messages} <-
            :ets.match_object(state.table, {{:pending, :_, :_}, :_}) do
        key = {:count, text, today}
        :ets.update_counter(state.table, key, {2, messages}, {key, 0})
      end

      _ = IPAddressCounts.delete_before(state.repo, Date.add(today, -30))
      %{state | loaded: today}
    end
  rescue
    error ->
      Logger.error("cannot read the IP pool counts: #{Exception.message(error)}")
      state
  end

  defp flush(%{repo: nil} = state), do: state

  defp flush(state) do
    for {{:pending, text, day} = key, messages} <-
          :ets.match_object(state.table, {{:pending, :_, :_}, :_}),
        messages > 0 do
      case IPAddressCounts.add(state.repo, text, day, messages) do
        {:ok, _count} -> :ets.update_counter(state.table, key, {2, -messages})
        {:error, _changeset} -> :ok
      end
    end

    :ets.match_delete(state.table, {{:pending, :_, :_}, 0})
    state
  rescue
    error ->
      Logger.error("cannot store the IP pool counts: #{Exception.message(error)}")
      state
  end
end
