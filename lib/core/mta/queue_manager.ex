defmodule Sovite.Core.MTA.QueueManager do
  @moduledoc """
  Schedules queued messages for delivery, like Postfix's `qmgr`.

  ## Lifecycle

  On startup, messages left in `active/` by a crash or `kill -9` go back
  to `incoming/` (`Sovite.Queue.Spool.recover/1`), and the retry times of
  `deferred/` messages are read from their records.

  A message is picked up from `incoming/` (right after it is queued, and
  by a periodic scan) or from `deferred/` (when its retry time comes) and
  moved to `active/`. Its pending recipients are routed
  (`Sovite.Core.MTA.Router`) and grouped into jobs: one per destination, with
  at most `delivery.max_recipients` recipients each. Jobs run in
  `Sovite.Core.MTA.Delivery` workers.

  A message with a content filter (`smtp.content_filter`, see
  `Sovite.Queue.Envelope`) goes to the filter instead, for all its
  recipients at once, with its original sender and without
  `REQUIRETLS`. When the filter offers `XFORWARD`, it is told the
  original client, `HELO` name, and queue ID. Its job is then done: the
  filter sends the message back as a new one.

  Each job's results are appended to the queue file and `fsync`ed before
  anything else happens, so a crash never loses a delivery result: at
  worst, the recipients of the jobs in flight are delivered again, which
  SMTP allows. When all jobs of a message are done:

    1. Failed recipients are reported to the sender (`Sovite.Core.MTA.Bounce`),
       and counted against the user who sent the message, if any
       (`Sovite.Core.MTA.Outbound`). Delivered recipients and expanded
       aliases are reported too, when the sender asked for it
       (`NOTIFY=SUCCESS`); a recipient with `NOTIFY=NEVER`, or without
       `FAILURE`, is never reported as failed.
    2. If no recipient is pending, the message is deleted.
    3. If the message is older than `queue.max_lifetime`, its pending
       recipients fail and are reported, and it is deleted.
    4. Otherwise it is deferred: a delay warning is sent if due
       (`queue.delay_warning`) for the recipients whose `NOTIFY` does not
       rule it out, and the next attempt is scheduled with exponential
       backoff (`Sovite.Queue.Backoff`).

  The DSN parameters of the message (RFC 3461) go with it to servers
  that support `DSN`.

  ## Priorities and deadlines

  Jobs for the same destination run in `MT-PRIORITY` order (RFC 6710),
  and of the destinations waiting, the one with the highest priority
  job goes first. A message on hold (`FUTURERELEASE`, RFC 4865) waits in
  `deferred/` until its release time, and its lifetime starts then. A
  message with a `DELIVERBY` deadline (RFC 2852) is retried by then at
  the latest; when it passes, the pending recipients fail with `5.4.7`
  (`R`), or the sender gets a delay warning (`N`).

  ## ETRN

  `flush/2` with a domain retries the deferred messages with recipients
  in that domain now, for `ETRN` (RFC 1985). The same domain is flushed
  at most once a minute.

  ## Administration

  `hold/2`, `release/2`, `delete/2`, `requeue/2`, and `retry/2` act on
  one message, like Postfix's `postsuper` and `postqueue -i`. A message
  being delivered is held or deleted once its running deliveries end;
  the deliveries that have not started are dropped. `reconfigure/2`
  takes new options from a reloaded configuration, for the messages
  picked up from then on. `drain/2` stops starting deliveries, for a
  graceful shutdown.

  ## Limits

    * `delivery.max_deliveries` workers run at once.
    * `delivery.destination_concurrency` of them per destination.
    * `delivery.destination_rate_delay` between two deliveries to the same
      destination.

  A worker that finishes a job may get the next job for the same
  destination and send it over the same connection. With
  `delivery.connection_cache`, a worker with no next job keeps its
  connection open for `delivery.connection_cache_time` (2 seconds), in
  case one comes, as Postfix's connection cache does; it still counts
  towards the limits meanwhile, but makes room when another destination
  is waiting for a free slot.
  """

  use GenServer

  require Logger

  alias Sovite.Core.Config
  alias Sovite.Core.MTA.{Bounce, Delivery, IPPools, Outbound, Recipients, Router, Routing}
  alias Sovite.Core.MTA.Cluster.Placement
  alias Sovite.Queue.{Backoff, Entry, Envelope, ID, Spool}
  alias Sovite.SMTP.Client

  # The shortest time between two ETRN flushes of the same domain.
  @flush_interval 60_000

  defstruct [
    :opts,
    :task_supervisor,
    :wake_timer,
    :rate_timer,
    messages: %{},
    deferred: :gb_sets.new(),
    deferred_due: %{},
    deferred_domains: %{},
    flushed: %{},
    seq: 0,
    ready: %{},
    running: %{},
    workers: %{},
    idle: %{},
    destination_running: %{},
    destination_last: %{},
    backlog: false,
    draining: false,
    drain_waiters: []
  ]

  ## API

  @doc """
  Queue manager options from the running configuration (`repo` is
  Sovite's database, for `database` tables). `start_link/1` takes these,
  plus:

    * `:name` - registered name, or `nil` for none. Defaults to this
      module.
    * `:resolver` - DNS resolver. Defaults to `Sovite.DNS.default_resolver/0`.
    * `:port` - SMTP port for MX and address-literal deliveries. Defaults
      to 25.
    * `:client` - extra `Sovite.SMTP.Client.connect/3` options.
    * `:scan_interval` - milliseconds between scans of `incoming/`.
      Defaults to one minute.
    * `:max_active` - messages in memory at once. Defaults to 10000.
    * `:outbound` - `Sovite.Core.MTA.Outbound` options, if failures are
      counted.
  """
  @spec opts(Sovite.Core.Config.t(), Sovite.Core.Repo.t() | nil) :: keyword()
  def opts(config, repo \\ nil) do
    [
      resolver: Config.resolver(config),
      tls_reports: if(config.tls_rpt.reports, do: repo),
      routing: Routing.new(config, repo),
      directory: config.queue.directory,
      hostname: config.server.hostname,
      local_domains: config.domains.local,
      max_lifetime: config.queue.max_lifetime,
      min_backoff: config.queue.min_backoff,
      max_backoff: config.queue.max_backoff,
      delay_warning: config.queue.delay_warning,
      double_bounce_recipient: config.bounce.double_bounce_recipient,
      bounce_size_limit: config.bounce.size_limit,
      maildir: config.maildir,
      pipes: config.pipe,
      delimiter: config.routing.extension_delimiter,
      ip_pools: if(config.ip_pool != [], do: IPPools),
      cluster: Placement.placement_opts(config),
      tenant_pools:
        for(%{ip_pool: pool} = t <- config.tenant, pool != nil, into: %{}, do: {t.name, pool})
    ] ++ Map.to_list(config.delivery)
  end

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, if(name, do: [name: name], else: []))
  end

  @doc "Tells the queue manager that message `queue_id` was queued in `incoming/`."
  @spec notify(GenServer.server(), String.t()) :: :ok
  def notify(server, queue_id), do: GenServer.cast(server, {:enqueued, queue_id})

  @doc "Retries every deferred message now, like `postqueue -f`."
  @spec flush(GenServer.server()) :: :ok
  def flush(server), do: GenServer.call(server, :flush)

  @doc """
  Retries the deferred messages with pending recipients in a domain now
  (`{:domain, domain}`), or in a domain and its subdomains
  (`{:subdomains, domain}`), as `ETRN` asks. Returns how many there
  were, or `{:error, :too_soon}` when the same was asked less than a
  minute ago.
  """
  @spec flush(GenServer.server(), {:domain | :subdomains, String.t()}) ::
          {:ok, non_neg_integer()} | {:error, :too_soon}
  def flush(server, {kind, domain} = node)
      when kind in [:domain, :subdomains] and is_binary(domain),
      do: GenServer.call(server, {:flush, node})

  @doc """
  Retries message `queue_id` now, if it is deferred or waiting in
  `incoming/`. A message on hold for `FUTURERELEASE` stays on hold.
  """
  @spec retry(GenServer.server(), String.t()) :: :ok | {:error, :not_found}
  def retry(server, queue_id), do: GenServer.call(server, {:retry, queue_id})

  @doc """
  Puts message `queue_id` on hold (in `hold/`): it is not delivered until
  `release/2` or `requeue/2`.
  """
  @spec hold(GenServer.server(), String.t()) :: :ok | {:error, :not_found}
  def hold(server, queue_id), do: GenServer.call(server, {:hold, queue_id})

  @doc """
  Releases a message from `hold/` to `deferred/`. It is retried when its
  next attempt is due, at once if that has passed.
  """
  @spec release(GenServer.server(), String.t()) :: :ok | {:error, :not_found}
  def release(server, queue_id), do: GenServer.call(server, {:release, queue_id})

  @doc """
  Deletes message `queue_id` from any queue, without notifying anyone.
  """
  @spec delete(GenServer.server(), String.t()) :: :ok | {:error, :not_found}
  def delete(server, queue_id), do: GenServer.call(server, {:delete, queue_id})

  @doc """
  Queues message `queue_id` again and retries it now, from `deferred/`,
  `hold/`, or `corrupt/` (where it goes back if it still fails
  verification). Its pending recipients are routed again, with the
  current aliases and routing tables.
  """
  @spec requeue(GenServer.server(), String.t()) :: :ok | {:error, :not_found}
  def requeue(server, queue_id), do: GenServer.call(server, {:requeue, queue_id})

  @doc """
  Replaces the options with `opts` (from `opts/2`, after a config
  reload). The queue directory cannot change. Deliveries already planned
  keep the options they were planned with.
  """
  @spec reconfigure(GenServer.server(), keyword()) :: :ok
  def reconfigure(server, opts), do: GenServer.call(server, {:reconfigure, opts})

  @doc """
  Stops starting deliveries, and waits up to `timeout` milliseconds for
  the running ones to end. Messages left in `active/` are picked up again
  at the next start. Returns `{:error, :timeout}` if deliveries were
  still running.
  """
  @spec drain(GenServer.server(), timeout()) :: :ok | {:error, :timeout}
  def drain(server, timeout) do
    GenServer.call(server, :drain, timeout)
  catch
    :exit, {:timeout, _} -> {:error, :timeout}
  end

  @doc "Counts of messages and deliveries, for status output and tests."
  @spec stats(GenServer.server()) :: %{
          active: non_neg_integer(),
          deferred: non_neg_integer(),
          deliveries: non_neg_integer(),
          ready: non_neg_integer(),
          draining: boolean()
        }
  def stats(server), do: GenServer.call(server, :stats)

  ## Server

  @impl true
  def init(opts) do
    {:ok, task_supervisor} = Task.Supervisor.start_link()
    state = %__MODULE__{opts: build_opts(opts), task_supervisor: task_supervisor}
    {:ok, state, {:continue, :recover}}
  end

  defp build_opts(opts) do
    hostname = Keyword.fetch!(opts, :hostname)

    families =
      Enum.map(Keyword.fetch!(opts, :ip_versions), fn
        :ipv6 -> :aaaa
        :ipv4 -> :a
      end)

    opts =
      opts
      |> Map.new()
      |> Map.put_new(:scan_interval, 60_000)
      |> Map.put_new(:max_active, 10_000)
      |> Map.put_new(:connection_cache, false)
      |> Map.put_new(:connection_cache_time, 2_000)
      |> Map.put_new_lazy(:routing, fn ->
        %Routing{
          hostname: hostname,
          local_domains: MapSet.new(Keyword.get(opts, :local_domains, [])),
          relayhost: Keyword.get(opts, :relayhost)
        }
      end)

    delivery = %{
      hostname: hostname,
      resolver: Map.get(opts, :resolver, Sovite.DNS.default_resolver()),
      port: Map.get(opts, :port, 25),
      families: families,
      max_addresses: opts.max_addresses,
      client:
        [helo: hostname, connect_timeout: opts.connect_timeout] ++ Map.get(opts, :client, []),
      tls: %{
        default: Map.get(opts, :tls) || :may,
        policy: Map.get(opts, :tls_policy) || %{},
        cacerts: Map.get(opts, :tls_cacerts)
      },
      maildir: Map.get(opts, :maildir) || %{},
      pipes: Map.get(opts, :pipes, %{}),
      delimiter: Map.get(opts, :delimiter, ""),
      mta_sts: Map.get(opts, :mta_sts),
      tls_reports: Map.get(opts, :tls_reports),
      ip_pools: Map.get(opts, :ip_pools),
      # The spool's private tmp/, emptied by Spool.init/1.
      tmp_dir: Path.join(opts.directory, "tmp")
    }

    Map.put(opts, :delivery, delivery)
  end

  @impl true
  def handle_continue(:recover, state) do
    case Spool.recover(state.opts.directory) do
      {:ok, 0} ->
        :ok

      {:ok, count} ->
        Logger.notice("recovered #{count} messages that were being delivered")

      {:error, reason} ->
        Logger.error("cannot recover active messages: #{:file.format_error(reason)}")
    end

    state = load_deferred(state)
    Process.send_after(self(), :scan, state.opts.scan_interval)
    {:noreply, state |> scan_incoming() |> schedule_wake() |> dispatch()}
  end

  @impl true
  def handle_cast({:enqueued, id}, state) do
    state =
      cond do
        Map.has_key?(state.messages, id) -> state
        capacity?(state) -> activate(state, id, :incoming)
        true -> %{state | backlog: true}
      end

    {:noreply, dispatch(state)}
  end

  @impl true
  def handle_call({:job_done, results, reusable}, {pid, _tag}, state) do
    ref = Map.fetch!(state.workers, pid)
    worker = Map.fetch!(state.running, ref)
    state = job_finished(state, worker.job, results)
    now = now_ms()

    case reusable && not state.draining && next_job(state, worker.destination, now) do
      {job, state} ->
        state = put_in(state.running[ref].job, job)
        state = put_in(state.destination_last[worker.destination], now)
        {:reply, {:next, job}, state}

      _ when reusable and not state.draining and state.opts.connection_cache ->
        state = put_in(state.running[ref].job, nil)
        {:reply, :wait, idle(state, ref, worker.destination)}

      _ ->
        {:reply, :stop, put_in(state.running[ref].job, nil)}
    end
  end

  def handle_call(:flush, _from, state) do
    deferred = :gb_sets.from_list(for {id, _due} <- state.deferred_due, do: {0, id})
    due = Map.new(state.deferred_due, fn {id, _due} -> {id, 0} end)
    state = %{state | deferred: deferred, deferred_due: due}
    {:reply, :ok, state |> activate_due() |> schedule_wake() |> dispatch()}
  end

  def handle_call({:flush, node}, _from, state) do
    now = now_ms()

    case Map.fetch(state.flushed, node) do
      {:ok, last} when now - last < @flush_interval ->
        {:reply, {:error, :too_soon}, state}

      _ ->
        ids =
          for {id, domains} <- state.deferred_domains,
              Enum.any?(domains, &in_node?(&1, node)),
              do: id

        state =
          Enum.reduce(ids, %{state | flushed: Map.put(state.flushed, node, now)}, fn id, state ->
            due = Map.fetch!(state.deferred_due, id)

            %{
              state
              | deferred: :gb_sets.add({0, id}, :gb_sets.delete({due, id}, state.deferred)),
                deferred_due: Map.put(state.deferred_due, id, 0)
            }
          end)

        {:reply, {:ok, length(ids)}, state |> activate_due() |> schedule_wake() |> dispatch()}
    end
  end

  def handle_call(:stats, _from, state) do
    stats = %{
      active: map_size(state.messages),
      deferred: map_size(state.deferred_due),
      deliveries: map_size(state.running),
      ready: state.ready |> Map.values() |> Enum.map(&:gb_sets.size/1) |> Enum.sum(),
      draining: state.draining
    }

    {:reply, stats, state}
  end

  def handle_call({:retry, id}, _from, state) do
    cond do
      Map.has_key?(state.deferred_due, id) ->
        state = reschedule(state, id, 0)
        {:reply, :ok, state |> activate_due() |> schedule_wake() |> dispatch()}

      Map.has_key?(state.messages, id) ->
        {:reply, :ok, state}

      File.exists?(Spool.path(state.opts.directory, :incoming, id)) ->
        {:reply, :ok, state |> activate(id, :incoming) |> dispatch()}

      true ->
        {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call({:hold, id}, _from, state) do
    case locate(state, id) do
      :active -> {:reply, :ok, finish_early(state, id, :hold)}
      :hold -> {:reply, :ok, state}
      :corrupt -> {:reply, {:error, :not_found}, state}
      nil -> {:reply, {:error, :not_found}, state}
      queue -> {:reply, move_out(state, id, queue, :hold, :held), unindex(state, id)}
    end
  end

  def handle_call({:release, id}, _from, state) do
    dir = state.opts.directory

    case Spool.move(dir, id, :hold, :deferred) do
      :ok ->
        admin_event(:released, id)
        state = index_deferred(state, id)
        {:reply, :ok, state |> activate_due() |> schedule_wake() |> dispatch()}

      {:error, _reason} ->
        {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call({:delete, id}, _from, state) do
    case locate(state, id) do
      :active ->
        {:reply, :ok, finish_early(state, id, :delete)}

      nil ->
        {:reply, {:error, :not_found}, state}

      queue ->
        result =
          case Spool.remove(state.opts.directory, queue, id, :deleted) do
            :ok -> :ok
            {:error, _reason} -> {:error, :not_found}
          end

        {:reply, result, unindex(state, id)}
    end
  end

  def handle_call({:requeue, id}, _from, state) do
    case locate(state, id) do
      :active ->
        admin_event(:requeued, id)
        {:reply, :ok, put_in(state.messages[id].after, :requeue)}

      :incoming ->
        admin_event(:requeued, id)
        {:reply, :ok, state |> activate(id, :incoming) |> dispatch()}

      nil ->
        {:reply, {:error, :not_found}, state}

      queue ->
        case move_out(state, id, queue, :incoming, :requeued) do
          :ok -> {:reply, :ok, state |> unindex(id) |> activate(id, :incoming) |> dispatch()}
          error -> {:reply, error, state}
        end
    end
  end

  def handle_call({:reconfigure, opts}, _from, state) do
    opts = build_opts(opts)
    {:reply, :ok, dispatch(%{state | opts: %{opts | directory: state.opts.directory}})}
  end

  def handle_call(:drain, from, state) do
    state = stop_idle(%{state | draining: true})

    if map_size(state.running) == 0,
      do: {:reply, :ok, state},
      else: {:noreply, %{state | drain_waiters: [from | state.drain_waiters]}}
  end

  @impl true
  def handle_info(:scan, state) do
    Process.send_after(self(), :scan, state.opts.scan_interval)
    {:noreply, state |> scan_incoming() |> dispatch()}
  end

  def handle_info(:wake, state) do
    state = %{state | wake_timer: nil}
    {:noreply, state |> activate_due() |> schedule_wake() |> dispatch()}
  end

  def handle_info(:dispatch, state), do: {:noreply, dispatch(%{state | rate_timer: nil})}

  # A worker kept its connection open long enough.
  def handle_info({:idle_expired, ref}, state), do: {:noreply, stop_idle(state, ref)}

  # A worker returned normally.
  def handle_info({ref, _result}, state) when is_map_key(state.running, ref) do
    Process.demonitor(ref, [:flush])
    {:noreply, state |> worker_exited(ref) |> refill() |> dispatch()}
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, state)
      when is_map_key(state.running, ref) do
    worker = state.running[ref]

    state =
      if worker.job do
        :telemetry.execute(
          [:sovite, :smtp, :client, :delivery, :exception],
          %{duration: 0},
          %{
            queue_id: worker.job.queue_id,
            relay: Router.name(worker.destination),
            kind: :exit,
            reason: reason
          }
        )

        details = details({"4.3.0", "internal error during delivery"})

        job_finished(
          state,
          worker.job,
          Enum.map(worker.job.recipients, &{&1, :deferred, details})
        )
      else
        state
      end

    {:noreply, state |> worker_exited(ref) |> refill() |> dispatch()}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @doc false
  # Runs in a worker task.
  def work(manager, job, opts, connection \\ nil) do
    {results, connection} = Delivery.run(job, connection, opts)

    manager
    |> GenServer.call({:job_done, results, connection != nil}, :infinity)
    |> next(manager, opts, connection)
  end

  defp next({:next, job}, manager, opts, connection), do: work(manager, job, opts, connection)

  # Idle, with the connection open: the manager says what comes next.
  defp next(:wait, manager, opts, connection) do
    receive do
      {__MODULE__, reply} -> next(reply, manager, opts, connection)
    end
  end

  defp next(:stop, _manager, _opts, connection) do
    if connection, do: connection |> elem(0) |> Client.quit()
    :ok
  end

  ## Administration

  # Which queue message `id` is in. Messages the manager has in memory
  # are active or deferred; the others are found by their file.
  defp locate(state, id) do
    cond do
      not ID.valid?(id) -> nil
      Map.has_key?(state.messages, id) -> :active
      Map.has_key?(state.deferred_due, id) -> :deferred
      true -> Enum.find([:incoming, :hold, :corrupt], &File.exists?(file(state, &1, id)))
    end
  end

  defp file(state, queue, id), do: Spool.path(state.opts.directory, queue, id)

  defp move_out(state, id, from, to, event) do
    case Spool.move(state.opts.directory, id, from, to) do
      :ok -> admin_event(event, id)
      {:error, _reason} -> {:error, :not_found}
    end
  end

  defp admin_event(event, id),
    do: :telemetry.execute([:sovite, :queue, :message, event], %{}, %{queue_id: id})

  defp unindex(state, id) do
    case Map.pop(state.deferred_due, id) do
      {nil, _} ->
        state

      {due, deferred_due} ->
        %{
          state
          | deferred: :gb_sets.delete({due, id}, state.deferred),
            deferred_due: deferred_due,
            deferred_domains: Map.delete(state.deferred_domains, id)
        }
    end
  end

  defp reschedule(state, id, due) do
    old = Map.fetch!(state.deferred_due, id)

    %{
      state
      | deferred: :gb_sets.add({due, id}, :gb_sets.delete({old, id}, state.deferred)),
        deferred_due: Map.put(state.deferred_due, id, due)
    }
  end

  # Holds or deletes an active message: its jobs that have not started
  # are dropped, and it is finished when the running ones end.
  defp finish_early(state, id, action) do
    {state, dropped} = drop_ready_jobs(state, id)
    message = %{state.messages[id] | after: action}
    message = %{message | jobs: message.jobs - dropped}

    if message.jobs == 0,
      do: finalize(state, id, message),
      else: put_in(state.messages[id], message)
  end

  defp drop_ready_jobs(state, id) do
    Enum.reduce(state.ready, {%{state | ready: %{}}, 0}, fn {destination, jobs}, {state, n} ->
      kept = :gb_sets.filter(fn {_priority, _seq, job} -> job.queue_id != id end, jobs)
      n = n + :gb_sets.size(jobs) - :gb_sets.size(kept)

      if :gb_sets.is_empty(kept),
        do: {state, n},
        else: {put_in(state.ready[destination], kept), n}
    end)
  end

  defp in_node?(domain, {:domain, node}), do: domain == node

  defp in_node?(domain, {:subdomains, node}),
    do: domain == node or String.ends_with?(domain, "." <> node)

  # The domains of a message's pending recipients, for ETRN.
  defp pending_domains(entry) do
    entry
    |> Entry.pending()
    |> Enum.flat_map(fn address ->
      case Sovite.Validators.split_mailbox(address, utf8: true) do
        {:ok, {_local, domain}} -> [String.downcase(domain, :ascii)]
        {:error, _} -> []
      end
    end)
    |> Enum.uniq()
  end

  ## Picking up messages

  defp capacity?(state), do: map_size(state.messages) < state.opts.max_active

  defp load_deferred(state) do
    state
    |> list_queue(:deferred)
    |> Enum.reduce(state, &index_deferred(&2, &1))
  end

  defp index_deferred(state, id) do
    case Spool.load(Spool.path(state.opts.directory, :deferred, id), verify: false) do
      {:ok, loaded} ->
        entry = Entry.new(loaded.envelope, loaded.records)

        due =
          if entry.next_attempt, do: DateTime.to_unix(entry.next_attempt, :millisecond), else: 0

        add_deferred(state, id, due, pending_domains(entry))

      {:error, reason} ->
        corrupt(state, id, :deferred, reason)
    end
  end

  defp list_queue(state, queue) do
    case Spool.list(state.opts.directory, queue) do
      {:ok, ids} ->
        ids

      {:error, reason} ->
        Logger.error("cannot list #{queue} messages: #{:file.format_error(reason)}")
        []
    end
  end

  defp refill(%{backlog: true} = state),
    do: state |> scan_incoming() |> activate_due() |> schedule_wake()

  defp refill(state), do: state

  defp scan_incoming(state) do
    state
    |> list_queue(:incoming)
    |> Enum.reduce_while(%{state | backlog: false}, &pick_up/2)
  end

  defp pick_up(id, state) do
    cond do
      Map.has_key?(state.messages, id) -> {:cont, state}
      capacity?(state) -> {:cont, activate(state, id, :incoming)}
      true -> {:halt, %{state | backlog: true}}
    end
  end

  defp add_deferred(state, id, due, domains) do
    %{
      state
      | deferred: :gb_sets.add({due, id}, state.deferred),
        deferred_due: Map.put(state.deferred_due, id, due),
        deferred_domains: Map.put(state.deferred_domains, id, domains)
    }
  end

  defp activate_due(state) do
    now = System.os_time(:millisecond)

    cond do
      :gb_sets.is_empty(state.deferred) ->
        state

      not capacity?(state) ->
        %{state | backlog: true}

      true ->
        case :gb_sets.smallest(state.deferred) do
          {due, id} when due <= now ->
            state = %{
              state
              | deferred: :gb_sets.delete({due, id}, state.deferred),
                deferred_due: Map.delete(state.deferred_due, id),
                deferred_domains: Map.delete(state.deferred_domains, id)
            }

            state |> activate(id, :deferred) |> activate_due()

          _ ->
            state
        end
    end
  end

  defp schedule_wake(state) do
    if state.wake_timer, do: Process.cancel_timer(state.wake_timer)

    cond do
      :gb_sets.is_empty(state.deferred) ->
        %{state | wake_timer: nil}

      not capacity?(state) ->
        %{state | wake_timer: nil, backlog: true}

      true ->
        {due, _id} = :gb_sets.smallest(state.deferred)
        # Re-check at least every minute, in case the wall clock jumps.
        delay = due |> Kernel.-(System.os_time(:millisecond)) |> max(0) |> min(60_000)
        %{state | wake_timer: Process.send_after(self(), :wake, delay)}
    end
  end

  defp activate(state, id, from) do
    dir = state.opts.directory

    case Spool.move(dir, id, from, :active) do
      :ok ->
        path = Spool.path(dir, :active, id)

        case Spool.load(path) do
          {:ok, loaded} -> loaded(state, id, path, loaded)
          {:error, reason} -> corrupt(state, id, :active, reason)
        end

      # Picked up already, or removed by the administrator.
      {:error, :enoent} ->
        state

      {:error, reason} ->
        Logger.error("cannot activate message: #{:file.format_error(reason)}", queue_id: id)
        state
    end
  end

  defp loaded(state, id, path, loaded) do
    message = %{
      entry: Entry.new(loaded.envelope, loaded.records),
      path: path,
      message_offset: loaded.message_offset,
      message_size: loaded.message_size,
      prefix: loaded.prefix,
      end_offset: loaded.end_offset,
      jobs: 0,
      expired: false,
      # :hold, :delete, or :requeue, asked for while it was active.
      after: nil
    }

    release = Envelope.release_time(loaded.envelope)

    if release && DateTime.after?(release, DateTime.utc_now()),
      do: hold(state, id, message, release),
      else: plan(state, id, message)
  end

  # FUTURERELEASE: back to deferred/ until the release time.
  defp hold(state, id, message, release) do
    case Spool.move(state.opts.directory, id, :active, :deferred) do
      :ok ->
        state
        |> add_deferred(
          id,
          DateTime.to_unix(release, :millisecond),
          pending_domains(message.entry)
        )
        |> schedule_wake()

      {:error, reason} ->
        Logger.error("cannot hold message: #{:file.format_error(reason)}", queue_id: id)
        state
    end
  end

  defp corrupt(state, id, queue, reason) do
    _ = Spool.move(state.opts.directory, id, queue, :corrupt)

    :telemetry.execute([:sovite, :queue, :message, :corrupt], %{}, %{queue_id: id, reason: reason})

    state
  end

  ## Planning deliveries

  defp plan(state, id, message) do
    envelope = message.entry.envelope

    # DELIVERBY with R: too late to try again.
    message =
      if deadline_passed?(envelope, :return),
        do: fail_pending(message, "5.4.7", "delivery time expired (DELIVERBY)"),
        else: message

    route =
      case envelope.content_filter do
        nil -> &Router.route(state.opts.routing, envelope.sender, &1)
        filter -> fn _rcpt -> Router.filter(filter) end
      end

    pool = pool(state, envelope)

    {remote, immediate} =
      message.entry
      |> Entry.pending()
      |> Enum.map(&{&1, &1 |> route.() |> with_pool(pool, state) |> placed(state, envelope)})
      |> Enum.split_with(&match?({_rcpt, {:deliver, _}}, &1))

    message = record_results(message, Enum.map(immediate, &immediate_result/1))

    groups =
      Enum.group_by(
        remote,
        fn {rcpt, route} -> {route, job_sender(state, envelope, rcpt, route)} end,
        &elem(&1, 0)
      )

    jobs =
      for {{{:deliver, destination}, sender}, recipients} <- groups,
          chunk <- Enum.chunk_every(recipients, state.opts.max_recipients),
          do: job(state, id, message, destination, sender, chunk)

    if jobs == [] do
      finalize(state, id, message)
    else
      state = put_in(state.messages[id], %{message | jobs: length(jobs)})
      Enum.reduce(jobs, state, &add_job(&2, &1))
    end
  end

  # The IP pool of the message's tenant, else the default one.
  defp pool(%{opts: %{ip_pools: pools} = opts}, envelope) when pools != nil,
    do: Map.get(opts.tenant_pools, envelope.tenant) || Map.get(opts, :ip_pool)

  defp pool(_state, _envelope), do: nil

  # A pool replaces delivery.source_address, not a sender's own source
  # address from the sender relays table.
  defp with_pool({:deliver, %{transport: :smtp, source: source} = destination}, pool, state)
       when pool != nil do
    if source == state.opts.routing.source_address,
      do: {:deliver, Map.merge(destination, %{source: %{}, pool: pool})},
      else: {:deliver, destination}
  end

  defp with_pool(route, _pool, _state), do: route

  # In a cluster, another node may deliver it.
  defp placed(route, %{opts: %{cluster: %{} = cluster}}, envelope),
    do: Placement.place(route, cluster, envelope)

  defp placed(route, _state, _envelope), do: route

  defp job(state, id, message, destination, sender, recipients) do
    envelope = message.entry.envelope
    filter = envelope.content_filter != nil

    %{
      queue_id: id,
      destination: destination,
      recipients: recipients,
      sender: sender,
      body_type: envelope.body_type,
      path: message.path,
      message_offset: message.message_offset,
      message_size: message.message_size,
      prefix: message.prefix,
      requiretls: envelope.requiretls and not filter,
      smtputf8: envelope.smtputf8,
      xforward: if(filter, do: xforward(envelope)),
      dsn: job_dsn(envelope, recipients),
      chunking: Map.get(state.opts, :chunking, false),
      priority: envelope.priority,
      deliver_by: if(not filter, do: envelope.deliver_by),
      rrvs: if(filter, do: %{}, else: Map.take(envelope.rrvs, recipients))
    }
  end

  # Ready jobs by destination, in priority order, then first come first
  # served.
  defp add_job(state, job) do
    key = {-job.priority, state.seq, job}

    ready =
      Map.update(state.ready, job.destination, :gb_sets.singleton(key), &:gb_sets.add(key, &1))

    %{state | ready: ready, seq: state.seq + 1}
  end

  defp head_priority(state, destination) do
    {priority, _seq, _job} = :gb_sets.smallest(Map.fetch!(state.ready, destination))
    priority
  end

  defp deadline_passed?(%{deliver_by: %{mode: mode, deadline: deadline}}, mode),
    do: not DateTime.after?(deadline, DateTime.utc_now())

  defp deadline_passed?(_envelope, _mode), do: false

  defp fail_pending(message, status, text) do
    records =
      for address <- Entry.pending(message.entry),
          do: {:recipient, address, :failed, details({status, text})}

    append(message, records)
  end

  # The DSN parameters to relay with the message, if any.
  defp job_dsn(envelope, recipients) do
    dsn = Map.take(envelope.dsn, recipients)

    if envelope.ret == nil and envelope.envid == nil and dsn == %{},
      do: nil,
      else: %{ret: envelope.ret, envid: envelope.envid, recipients: dsn}
  end

  # What the content filter is told about the message's origin.
  defp xforward(envelope) do
    %{
      addr: envelope.remote_ip,
      helo: envelope.helo,
      proto: proto(envelope.protocol),
      ident: envelope.queue_id,
      source: if(envelope.auth_user || envelope.remote_ip == nil, do: "LOCAL", else: "REMOTE")
    }
  end

  defp proto("E" <> _), do: "ESMTP"
  defp proto("SMTP" <> _), do: "SMTP"
  defp proto(_protocol), do: nil

  # Mail forwarded to another domain goes out with its SRS sender, if it
  # has one, so SPF passes at the destination. Not to a content filter.
  defp job_sender(_state, %{content_filter: filter} = envelope, _rcpt, _route) when filter != nil,
    do: envelope.sender

  defp job_sender(state, %{srs_sender: srs} = envelope, rcpt, {:deliver, %{transport: :smtp}})
       when srs != nil do
    with {:ok, {_local, domain}} <- Sovite.Validators.split_mailbox(rcpt, utf8: true),
         :remote <- Routing.class(state.opts.routing, String.downcase(domain, :ascii)) do
      srs
    else
      _ -> envelope.sender
    end
  end

  defp job_sender(_state, envelope, _rcpt, _route), do: envelope.sender

  defp immediate_result({rcpt, {:defer, status, text}}),
    do: {rcpt, :deferred, details({status, text})}

  defp immediate_result({rcpt, {:fail, status, text}}),
    do: {rcpt, :failed, details({status, text})}

  # No success notification: the message was not delivered.
  defp immediate_result({rcpt, {:discard, text}}),
    do: {rcpt, :delivered, details({"2.0.0", "discarded: #{text}"})}

  defp details({status, text}),
    do: %{status: status, reply: text, remote: nil, smtp: false, at: DateTime.utc_now()}

  ## Running deliveries

  # Starts workers while there are free slots, serving the destination
  # that started a delivery least recently first.
  defp dispatch(%{draining: true} = state), do: state
  defp dispatch(state), do: state |> resume_idle(now_ms()) |> start_workers()

  # No free slot: an idle worker makes room for a destination waiting.
  defp start_workers(state) when map_size(state.running) >= state.opts.max_deliveries do
    case {startable(state, now_ms()), oldest_idle(state)} do
      {{[_ | _], _waiting}, ref} when ref != nil -> stop_idle(state, ref)
      _ -> state
    end
  end

  defp start_workers(state) do
    now = now_ms()
    {allowed, waiting} = startable(state, now)

    case Enum.sort_by(
           allowed,
           &{head_priority(state, &1), Map.get(state.destination_last, &1, 0)}
         ) do
      [] -> schedule_rate_timer(state, waiting, now)
      [destination | _] -> state |> start_worker(destination, now) |> start_workers()
    end
  end

  ## Idle workers

  defp idle(state, ref, destination) do
    timer = Process.send_after(self(), {:idle_expired, ref}, state.opts.connection_cache_time)
    entry = {ref, timer, now_ms()}
    %{state | idle: Map.update(state.idle, destination, [entry], &(&1 ++ [entry]))}
  end

  # Ready jobs go to idle workers of their destination first.
  defp resume_idle(state, now) do
    Enum.reduce(state.idle, state, fn {destination, _workers}, state ->
      resume_idle(state, destination, now)
    end)
  end

  defp resume_idle(state, destination, now) do
    with [{ref, timer, _since} | rest] <- Map.get(state.idle, destination),
         {job, state} <- next_job(state, destination, now) do
      Process.cancel_timer(timer)
      send(state.running[ref].pid, {__MODULE__, {:next, job}})

      state = put_in(state.running[ref].job, job)

      state = %{
        state
        | idle: put_idle(state.idle, destination, rest),
          destination_last: Map.put(state.destination_last, destination, now)
      }

      resume_idle(state, destination, now)
    else
      _ -> state
    end
  end

  defp oldest_idle(state) do
    state.idle
    |> Enum.flat_map(fn {_destination, workers} -> workers end)
    |> Enum.min_by(fn {_ref, _timer, since} -> since end, fn -> nil end)
    |> case do
      nil -> nil
      {ref, _timer, _since} -> ref
    end
  end

  defp stop_idle(state) do
    refs = for {_destination, workers} <- state.idle, {ref, _timer, _since} <- workers, do: ref
    Enum.reduce(refs, state, &stop_idle(&2, &1))
  end

  # Tells an idle worker to close its connection and stop.
  defp stop_idle(state, ref) do
    case unidle(state, ref) do
      {:ok, state} ->
        send(state.running[ref].pid, {__MODULE__, :stop})
        state

      :error ->
        state
    end
  end

  defp unidle(state, ref) do
    Enum.find_value(state.idle, :error, fn {destination, workers} ->
      case List.keytake(workers, ref, 0) do
        {{^ref, timer, _since}, rest} ->
          Process.cancel_timer(timer)
          {:ok, %{state | idle: put_idle(state.idle, destination, rest)}}

        nil ->
          nil
      end
    end)
  end

  defp put_idle(idle, destination, []), do: Map.delete(idle, destination)
  defp put_idle(idle, destination, workers), do: Map.put(idle, destination, workers)

  # Destinations with ready jobs and a free slot: those the rate delay
  # allows now, and those that have to wait.
  defp startable(state, now) do
    state.ready
    |> Map.keys()
    |> Enum.filter(&below_concurrency?(state, &1))
    |> Enum.split_with(&rate_allows?(state, &1, now))
  end

  defp below_concurrency?(state, destination),
    do: Map.get(state.destination_running, destination, 0) < state.opts.destination_concurrency

  defp rate_allows?(%{opts: %{destination_rate_delay: nil}}, _destination, _now), do: true

  defp rate_allows?(state, destination, now) do
    case Map.fetch(state.destination_last, destination) do
      {:ok, last} -> now - last >= state.opts.destination_rate_delay
      :error -> true
    end
  end

  defp schedule_rate_timer(state, [], _now), do: state

  defp schedule_rate_timer(state, waiting, now) do
    if state.rate_timer, do: Process.cancel_timer(state.rate_timer)

    wait =
      waiting
      |> Enum.map(&(state.destination_last[&1] + state.opts.destination_rate_delay - now))
      |> Enum.min()
      |> max(0)

    %{state | rate_timer: Process.send_after(self(), :dispatch, wait)}
  end

  defp start_worker(state, destination, now) do
    {job, state} = pop_job(state, destination)

    task =
      Task.Supervisor.async_nolink(state.task_supervisor, __MODULE__, :work, [
        self(),
        job,
        state.opts.delivery
      ])

    %{
      state
      | running:
          Map.put(state.running, task.ref, %{pid: task.pid, destination: destination, job: job}),
        workers: Map.put(state.workers, task.pid, task.ref),
        destination_running: Map.update(state.destination_running, destination, 1, &(&1 + 1)),
        destination_last: Map.put(state.destination_last, destination, now)
    }
  end

  defp next_job(state, destination, now) do
    if Map.has_key?(state.ready, destination) and rate_allows?(state, destination, now),
      do: pop_job(state, destination),
      else: nil
  end

  defp pop_job(state, destination) do
    {{_priority, _seq, job}, queue} = :gb_sets.take_smallest(Map.fetch!(state.ready, destination))

    ready =
      if :gb_sets.is_empty(queue),
        do: Map.delete(state.ready, destination),
        else: Map.put(state.ready, destination, queue)

    {job, %{state | ready: ready}}
  end

  defp worker_exited(state, ref) do
    state =
      case unidle(state, ref) do
        {:ok, state} -> state
        :error -> state
      end

    {worker, running} = Map.pop!(state.running, ref)

    destination_running =
      case Map.fetch!(state.destination_running, worker.destination) do
        1 -> Map.delete(state.destination_running, worker.destination)
        count -> Map.put(state.destination_running, worker.destination, count - 1)
      end

    if running == %{}, do: Enum.each(state.drain_waiters, &GenServer.reply(&1, :ok))

    %{
      state
      | running: running,
        workers: Map.delete(state.workers, worker.pid),
        destination_running: destination_running,
        drain_waiters: if(running == %{}, do: [], else: state.drain_waiters)
    }
  end

  defp job_finished(state, job, results) do
    case Map.fetch(state.messages, job.queue_id) do
      {:ok, message} ->
        message = record_results(message, results)
        message = %{message | jobs: message.jobs - 1}

        if message.jobs == 0,
          do: finalize(state, job.queue_id, message),
          else: put_in(state.messages[job.queue_id], message)

      :error ->
        state
    end
  end

  defp record_results(message, results) do
    append(
      message,
      for({address, status, details} <- results, do: {:recipient, address, status, details})
    )
  end

  # Writes records to the queue file and applies them. If the write fails
  # the state is still updated, so this run does not repeat a delivery;
  # the records are lost only if the server also stops before the next
  # attempt.
  defp append(message, []), do: message

  defp append(message, records) do
    end_offset =
      case Spool.append(message.path, message.end_offset, records) do
        {:ok, end_offset} ->
          end_offset

        {:error, reason} ->
          Logger.error("cannot write delivery records: #{:file.format_error(reason)}",
            queue_id: message.entry.envelope.queue_id
          )

          message.end_offset
      end

    entry = Enum.reduce(records, message.entry, &Entry.apply_record(&2, &1))
    %{message | entry: entry, end_offset: end_offset}
  end

  ## Finishing an attempt

  defp finalize(state, id, %{after: :delete} = message),
    do: remove(state, id, message, :deleted)

  defp finalize(state, id, message) do
    {failures_notified, message} = notify_failures(state, message)
    {successes_notified, message} = notify_successes(state, message)
    notified = failures_notified and successes_notified

    cond do
      Entry.pending(message.entry) == [] and notified ->
        remove(state, id, message)

      Entry.pending(message.entry) != [] and expired?(state, message) ->
        finalize(state, id, expire(message))

      Entry.pending(message.entry) != [] and deadline_passed?(message.entry.envelope, :return) ->
        finalize(state, id, fail_pending(message, "5.4.7", "delivery time expired (DELIVERBY)"))

      true ->
        defer(state, id, message)
    end
  end

  defp notify_failures(state, message) do
    case Entry.unnotified_failures(message.entry) do
      [] ->
        {true, message}

      failures ->
        record = {:notified, Enum.map(failures, &elem(&1, 0))}
        # NOTIFY=NEVER, or without FAILURE: not reported.
        reported = Enum.filter(failures, &Entry.notify?(message.entry, elem(&1, 0), :failure))

        {result, message} =
          if reported == [],
            do: {:ok, append(message, [record])},
            else: send_notification(state, :failure, message, reported, record)

        user = message.entry.envelope.auth_user
        if result == :ok, do: Outbound.failed(state.opts[:outbound], user, length(failures))
        {result == :ok, message}
    end
  end

  # NOTIFY=SUCCESS: delivered recipients and expanded aliases. Not for
  # the copy sent to a content filter: it comes back as a new message.
  # Never to the null sender.
  defp notify_successes(_state, %{entry: %{envelope: %{sender: ""}}} = message),
    do: {true, message}

  defp notify_successes(state, message) do
    entry = message.entry

    delivered =
      if entry.envelope.content_filter, do: [], else: Entry.unnotified_successes(entry)

    expanded =
      for alias <- Entry.unnotified_expansions(entry) do
        {alias,
         %{
           status: "2.0.0",
           reply: "expanded to several recipients",
           remote: nil,
           smtp: false,
           at: entry.envelope.received_at || DateTime.utc_now(),
           action: :expanded
         }}
      end

    case delivered ++ expanded do
      [] ->
        {true, message}

      successes ->
        record = {:notified, Enum.map(successes, &elem(&1, 0))}
        {result, message} = send_notification(state, :success, message, successes, record)
        {result == :ok, message}
    end
  end

  # Queues a notification and appends `record` once it is safely queued.
  defp send_notification(state, kind, message, recipients, record) do
    case Bounce.notify(kind, message.entry, message, recipients, bounce_opts(state)) do
      {:ok, notification_id} ->
        if notification_id, do: GenServer.cast(self(), {:enqueued, notification_id})
        {:ok, append(message, [record])}

      {:error, reason} ->
        Logger.error("cannot queue #{kind} notification: #{inspect(reason)}",
          queue_id: message.entry.envelope.queue_id
        )

        {:error, message}
    end
  end

  defp bounce_opts(state) do
    routing = state.opts.routing

    state.opts
    |> Map.take([:hostname, :directory, :max_lifetime, :double_bounce_recipient])
    |> Map.put(:size_limit, Map.get(state.opts, :bounce_size_limit, 50_000))
    |> Map.put(:expand, fn address ->
      case Recipients.expand(routing, address) do
        {:ok, addresses} -> addresses
        # Keep the notification: it goes to the address as it is.
        {:error, _kind, _text} -> [address]
      end
    end)
  end

  # From the release of a message on hold.
  defp age(message) do
    envelope = message.entry.envelope

    case Envelope.release_time(envelope) || envelope.received_at do
      %DateTime{} = start -> max(DateTime.diff(DateTime.utc_now(), start, :millisecond), 0)
      nil -> 0
    end
  end

  defp expired?(state, message), do: age(message) >= state.opts.max_lifetime

  # The last temporary error becomes permanent: 4.x.y turns into 5.x.y.
  defp expire(message) do
    records =
      for address <- Entry.pending(message.entry) do
        last = message.entry.recipients[address].details || details({"4.4.7", "not delivered"})
        status = "5" <> binary_part(last.status, 1, byte_size(last.status) - 1)
        reply = if last.smtp, do: last.reply, else: "#{last.reply} (delivery time expired)"

        {:recipient, address, :failed,
         %{last | status: status, reply: reply, at: DateTime.utc_now()}}
      end

    %{append(message, records) | expired: true}
  end

  defp remove(state, id, message, reason \\ nil) do
    reason =
      cond do
        reason != nil -> reason
        message.expired -> :expired
        Entry.with_status(message.entry, :failed) != [] -> :bounced
        true -> :delivered
      end

    case Spool.remove(state.opts.directory, :active, id, reason) do
      :ok ->
        :ok

      {:error, error} ->
        Logger.error("cannot remove message: #{:file.format_error(error)}", queue_id: id)
    end

    %{state | messages: Map.delete(state.messages, id)}
  end

  defp defer(state, id, message) do
    message = maybe_warn(state, message)
    attempts = message.entry.attempts + 1
    delay = Backoff.delay(attempts, min: state.opts.min_backoff, max: state.opts.max_backoff)
    next_attempt = next_attempt(message.entry.envelope, delay)
    message = append(message, [{:retry, attempts, next_attempt}])
    state = %{state | messages: Map.delete(state.messages, id)}
    queue = if message.after == :hold, do: :hold, else: :deferred

    case Spool.move(state.opts.directory, id, :active, queue) do
      :ok when queue == :hold ->
        admin_event(:held, id)
        state

      :ok ->
        :telemetry.execute(
          [:sovite, :queue, :message, :deferred],
          %{attempts: attempts, recipients: length(Entry.pending(message.entry))},
          %{queue_id: id, next_attempt: DateTime.to_iso8601(next_attempt)}
        )

        due =
          if message.after == :requeue,
            do: 0,
            else: DateTime.to_unix(next_attempt, :millisecond)

        state
        |> add_deferred(id, due, pending_domains(message.entry))
        |> activate_due()
        |> schedule_wake()

      {:error, reason} ->
        # The file stays in active/ and is picked up again after a restart.
        Logger.error("cannot defer message: #{:file.format_error(reason)}", queue_id: id)
        state
    end
  end

  # Before a DELIVERBY deadline, at the latest at it.
  defp next_attempt(envelope, delay) do
    now = DateTime.utc_now()
    next = DateTime.add(now, delay, :millisecond)

    case envelope.deliver_by do
      %{deadline: deadline} ->
        if DateTime.after?(deadline, now) and DateTime.after?(next, deadline),
          do: deadline,
          else: next

      nil ->
        next
    end
  end

  defp maybe_warn(state, message) do
    if warning_due?(state, message) do
      entry = message.entry
      by = deadline_passed?(entry.envelope, :notify)

      pending =
        for address <- Entry.pending(entry), Entry.notify?(entry, address, :delay) do
          {address, warning_details(entry.recipients[address].details, by)}
        end

      if pending == [] do
        append(message, [:warned])
      else
        {_result, message} = send_notification(state, :delay, message, pending, :warned)
        message
      end
    else
      message
    end
  end

  # DELIVERBY with N: the deadline passed (RFC 2852 §4.1.4.1).
  defp warning_details(_details, true),
    do: details({"4.4.7", "delivery time expired (DELIVERBY), still trying"})

  defp warning_details(details, false), do: details || details({"4.0.0", "not yet attempted"})

  defp warning_due?(state, %{entry: entry} = message) do
    delay = state.opts.delay_warning

    not entry.warned and entry.envelope.sender != "" and
      (deadline_passed?(entry.envelope, :notify) or (delay != nil and age(message) >= delay))
  end

  defp now_ms, do: System.monotonic_time(:millisecond)
end
