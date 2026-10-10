defmodule Sovite.Core.QueueManager do
  @moduledoc """
  Schedules queued messages for delivery, like Postfix's `qmgr`.

  ## Lifecycle

  On startup, messages left in `active/` by a crash or `kill -9` go back
  to `incoming/` (`Sovite.Queue.Spool.recover/1`), and the retry times of
  `deferred/` messages are read from their records.

  A message is picked up from `incoming/` (right after it is queued, and
  by a periodic scan) or from `deferred/` (when its retry time comes) and
  moved to `active/`. Its pending recipients are routed
  (`Sovite.Core.Router`) and grouped into jobs: one per destination, with
  at most `delivery.max_recipients` recipients each. Jobs run in
  `Sovite.Core.Delivery` workers.

  Each job's results are appended to the queue file and `fsync`ed before
  anything else happens, so a crash never loses a delivery result: at
  worst, the recipients of the jobs in flight are delivered again, which
  SMTP allows. When all jobs of a message are done:

    1. Failed recipients are reported to the sender (`Sovite.Core.Bounce`).
    2. If no recipient is pending, the message is deleted.
    3. If the message is older than `queue.max_lifetime`, its pending
       recipients fail and are reported, and it is deleted.
    4. Otherwise it is deferred: a delay warning is sent if due
       (`queue.delay_warning`), and the next attempt is scheduled with
       exponential backoff (`Sovite.Queue.Backoff`).

  ## Limits

    * `delivery.max_deliveries` workers run at once.
    * `delivery.destination_concurrency` of them per destination.
    * `delivery.destination_rate_delay` between two deliveries to the same
      destination.

  A worker that finishes a job may get the next job for the same
  destination and send it over the same connection.
  """

  use GenServer

  require Logger

  alias Sovite.Core.{Bounce, Delivery, Recipients, Router, Routing}
  alias Sovite.Queue.{Backoff, Entry, Spool}
  alias Sovite.SMTP.Client

  defstruct [
    :opts,
    :task_supervisor,
    :wake_timer,
    :rate_timer,
    messages: %{},
    deferred: :gb_sets.new(),
    deferred_due: %{},
    ready: %{},
    running: %{},
    workers: %{},
    destination_running: %{},
    destination_last: %{},
    backlog: false
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
  """
  @spec opts(Sovite.Core.Config.t(), Sovite.Core.Repo.t() | nil) :: keyword()
  def opts(config, repo \\ nil) do
    [
      routing: Routing.new(config, repo),
      directory: config.queue.directory,
      hostname: config.server.hostname,
      local_domains: config.domains.local,
      max_lifetime: config.queue.max_lifetime,
      min_backoff: config.queue.min_backoff,
      max_backoff: config.queue.max_backoff,
      delay_warning: config.queue.delay_warning,
      double_bounce_recipient: config.bounce.double_bounce_recipient,
      maildir: config.maildir,
      pipes: config.pipe,
      delimiter: config.routing.extension_delimiter
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

  @doc "Counts of messages and deliveries, for status output and tests."
  @spec stats(GenServer.server()) :: %{
          active: non_neg_integer(),
          deferred: non_neg_integer(),
          deliveries: non_neg_integer()
        }
  def stats(server), do: GenServer.call(server, :stats)

  ## Server

  @impl true
  def init(opts) do
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
      # The spool's private tmp/, emptied by Spool.init/1.
      tmp_dir: Path.join(opts.directory, "tmp")
    }

    {:ok, task_supervisor} = Task.Supervisor.start_link()

    state = %__MODULE__{
      opts: Map.put(opts, :delivery, delivery),
      task_supervisor: task_supervisor
    }

    {:ok, state, {:continue, :recover}}
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

    case reusable && next_job(state, worker.destination, now) do
      {job, state} ->
        state = put_in(state.running[ref].job, job)
        state = put_in(state.destination_last[worker.destination], now)
        {:reply, {:next, job}, state}

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

  def handle_call(:stats, _from, state) do
    stats = %{
      active: map_size(state.messages),
      deferred: map_size(state.deferred_due),
      deliveries: map_size(state.running)
    }

    {:reply, stats, state}
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

    case GenServer.call(manager, {:job_done, results, connection != nil}, :infinity) do
      {:next, job} ->
        work(manager, job, opts, connection)

      :stop ->
        if connection, do: connection |> elem(0) |> Client.quit()
        :ok
    end
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

        add_deferred(state, id, due)

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

  defp add_deferred(state, id, due) do
    %{
      state
      | deferred: :gb_sets.add({due, id}, state.deferred),
        deferred_due: Map.put(state.deferred_due, id, due)
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
                deferred_due: Map.delete(state.deferred_due, id)
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
          {:ok, loaded} ->
            message = %{
              entry: Entry.new(loaded.envelope, loaded.records),
              path: path,
              message_offset: loaded.message_offset,
              message_size: loaded.message_size,
              prefix: loaded.prefix,
              end_offset: loaded.end_offset,
              jobs: 0,
              expired: false
            }

            plan(state, id, message)

          {:error, reason} ->
            corrupt(state, id, :active, reason)
        end

      # Picked up already, or removed by the administrator.
      {:error, :enoent} ->
        state

      {:error, reason} ->
        Logger.error("cannot activate message: #{:file.format_error(reason)}", queue_id: id)
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

    {remote, immediate} =
      message.entry
      |> Entry.pending()
      |> Enum.map(&{&1, Router.route(state.opts.routing, envelope.sender, &1)})
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
          chunk <- Enum.chunk_every(recipients, state.opts.max_recipients) do
        %{
          queue_id: id,
          destination: destination,
          recipients: chunk,
          sender: sender,
          body_type: envelope.body_type,
          path: message.path,
          message_offset: message.message_offset,
          message_size: message.message_size,
          prefix: message.prefix
        }
      end

    if jobs == [] do
      finalize(state, id, message)
    else
      state = put_in(state.messages[id], %{message | jobs: length(jobs)})

      ready =
        Enum.reduce(jobs, state.ready, fn job, ready ->
          Map.update(ready, job.destination, :queue.from_list([job]), &:queue.in(job, &1))
        end)

      %{state | ready: ready}
    end
  end

  # Mail forwarded to another domain goes out with its SRS sender, if it
  # has one, so SPF passes at the destination.
  defp job_sender(state, %{srs_sender: srs} = envelope, rcpt, {:deliver, %{transport: :smtp}})
       when srs != nil do
    with {:ok, {_local, domain}} <- Sovite.Validators.split_mailbox(rcpt),
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

  defp immediate_result({rcpt, {:discard, text}}),
    do: {rcpt, :delivered, details({"2.0.0", "discarded: #{text}"})}

  defp details({status, text}),
    do: %{status: status, reply: text, remote: nil, smtp: false, at: DateTime.utc_now()}

  ## Running deliveries

  # Starts workers while there are free slots, serving the destination
  # that started a delivery least recently first.
  defp dispatch(state) when map_size(state.running) >= state.opts.max_deliveries, do: state

  defp dispatch(state) do
    now = now_ms()
    {allowed, waiting} = startable(state, now)

    case Enum.sort_by(allowed, &Map.get(state.destination_last, &1, 0)) do
      [] -> schedule_rate_timer(state, waiting, now)
      [destination | _] -> state |> start_worker(destination, now) |> dispatch()
    end
  end

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
    {{:value, job}, queue} = :queue.out(Map.fetch!(state.ready, destination))

    ready =
      if :queue.is_empty(queue),
        do: Map.delete(state.ready, destination),
        else: Map.put(state.ready, destination, queue)

    {job, %{state | ready: ready}}
  end

  defp worker_exited(state, ref) do
    {worker, running} = Map.pop!(state.running, ref)

    destination_running =
      case Map.fetch!(state.destination_running, worker.destination) do
        1 -> Map.delete(state.destination_running, worker.destination)
        count -> Map.put(state.destination_running, worker.destination, count - 1)
      end

    %{
      state
      | running: running,
        workers: Map.delete(state.workers, worker.pid),
        destination_running: destination_running
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

  defp finalize(state, id, message) do
    {notified, message} = notify_failures(state, message)

    cond do
      Entry.pending(message.entry) == [] and notified ->
        remove(state, id, message)

      Entry.pending(message.entry) != [] and expired?(state, message) ->
        finalize(state, id, expire(message))

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
        {result, message} = send_notification(state, :failure, message, failures, record)
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
    |> Map.put(:expand, fn address ->
      case Recipients.expand(routing, address) do
        {:ok, addresses} -> addresses
        # Keep the notification: it goes to the address as it is.
        {:error, _kind, _text} -> [address]
      end
    end)
  end

  defp age(message) do
    case message.entry.envelope.received_at do
      %DateTime{} = received_at -> DateTime.diff(DateTime.utc_now(), received_at, :millisecond)
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

  defp remove(state, id, message) do
    reason =
      cond do
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
    next_attempt = DateTime.add(DateTime.utc_now(), delay, :millisecond)
    message = append(message, [{:retry, attempts, next_attempt}])
    state = %{state | messages: Map.delete(state.messages, id)}

    case Spool.move(state.opts.directory, id, :active, :deferred) do
      :ok ->
        :telemetry.execute(
          [:sovite, :queue, :message, :deferred],
          %{attempts: attempts, recipients: length(Entry.pending(message.entry))},
          %{queue_id: id, next_attempt: DateTime.to_iso8601(next_attempt)}
        )

        state
        |> add_deferred(id, DateTime.to_unix(next_attempt, :millisecond))
        |> schedule_wake()

      {:error, reason} ->
        # The file stays in active/ and is picked up again after a restart.
        Logger.error("cannot defer message: #{:file.format_error(reason)}", queue_id: id)
        state
    end
  end

  defp maybe_warn(state, message) do
    if warning_due?(state, message) do
      entry = message.entry

      pending =
        for address <- Entry.pending(entry) do
          {address, entry.recipients[address].details || details({"4.0.0", "not yet attempted"})}
        end

      {_result, message} = send_notification(state, :delay, message, pending, :warned)
      message
    else
      message
    end
  end

  defp warning_due?(%{opts: %{delay_warning: nil}}, _message), do: false

  defp warning_due?(state, %{entry: entry} = message) do
    not entry.warned and entry.envelope.sender != "" and age(message) >= state.opts.delay_warning
  end

  defp now_ms, do: System.monotonic_time(:millisecond)
end
