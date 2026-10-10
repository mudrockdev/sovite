defmodule Sovite.Core.MTASTS do
  @moduledoc """
  Finds the MTA-STS policies (RFC 8461) of the domains Sovite delivers
  to, when `mta_sts.enabled` is on. `Sovite.Core.Delivery` applies them.

  `policy/2` follows RFC 8461 §5.1 for a domain:

    1. It looks up the `_mta-sts.<domain>` TXT record.
    2. If its `id` is the one of the policy cached in the database
       (`mta_sts_policies`) and that policy has not expired, the cached
       policy is used.
    3. Otherwise the policy is fetched from
       `https://mta-sts.<domain>/.well-known/mta-sts.txt` and cached for
       its `max_age`.

  When the record is missing or the lookup or fetch fails, a cached
  policy that has not expired is still used, so an attacker who blocks
  DNS or HTTPS cannot turn a policy off. Without one the domain has no
  policy, and the failure is returned for TLS-RPT.

  Concurrent requests for a domain share one lookup, and answers are
  remembered for a minute, so a burst of deliveries to one domain makes
  one DNS query.

  ## Options

    * `:repo` - the `Sovite.Core.Repo` reference. Required.
    * `:resolver` - defaults to `Sovite.DNS.default_resolver/0`.
    * `:fetch` - options for `Sovite.TLS.MTASTS.fetch/2`, such as
      `:timeout`.
    * `:name` - the registered name.

  ## Telemetry

    * `[:sovite, :mta_sts, :fetched]` - `%{}`, `%{domain, policy_id, mode}`
    * `[:sovite, :mta_sts, :failed]` - `%{}`, `%{domain, reason}`: no
      policy could be fetched, and no cached one was used.
  """

  use GenServer

  alias Sovite.Core.Repo.Tables.MTASTSPolicies
  alias Sovite.TLS.MTASTS
  alias Sovite.TLS.MTASTS.Policy

  @remember 60_000

  @typedoc """
  The policy to apply, or `nil`, and why a policy that may exist could
  not be found: a TLS-RPT result type (RFC 8460 §4.3.2.2) and a
  description.
  """
  @type result :: %{
          policy: Policy.t() | nil,
          failure:
            {:sts_policy_fetch_error | :sts_policy_invalid | :sts_webpki_invalid, String.t()}
            | nil
        }

  @doc false
  def child_spec(opts), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}

  @doc "Starts the policy cache."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @doc """
  Returns the policy of `domain`. Policies with mode `none` are returned
  as no policy.
  """
  @spec policy(GenServer.server(), String.t(), timeout()) :: result()
  def policy(server, domain, timeout \\ 90_000) do
    GenServer.call(server, {:policy, String.downcase(domain, :ascii)}, timeout)
  catch
    :exit, reason ->
      %{
        policy: nil,
        failure: {:sts_policy_fetch_error, "policy lookup failed: #{inspect(reason)}"}
      }
  end

  @impl true
  def init(opts) do
    {:ok, tasks} = Task.Supervisor.start_link()

    {:ok,
     %{
       repo: Keyword.fetch!(opts, :repo),
       resolver: Keyword.get_lazy(opts, :resolver, &Sovite.DNS.default_resolver/0),
       fetch: Keyword.get(opts, :fetch, []),
       tasks: tasks,
       # domain => [from]
       waiting: %{},
       # domain => {result, expires_at in monotonic ms}
       recent: %{}
     }}
  end

  @impl true
  def handle_call({:policy, domain}, from, state) do
    now = System.monotonic_time(:millisecond)

    case state.recent do
      %{^domain => {result, until}} when until > now ->
        {:reply, result, state}

      _ ->
        {:noreply, lookup(state, domain, from)}
    end
  end

  defp lookup(state, domain, from) do
    case state.waiting do
      %{^domain => waiters} ->
        put_in(state.waiting[domain], [from | waiters])

      _ ->
        server = self()
        config = Map.take(state, [:repo, :resolver, :fetch])

        Task.Supervisor.start_child(state.tasks, fn ->
          send(server, {:found, domain, find(config, domain, DateTime.utc_now())})
        end)

        put_in(state.waiting[domain], [from])
    end
  end

  @impl true
  def handle_info({:found, domain, result}, state) do
    {waiters, waiting} = Map.pop(state.waiting, domain, [])
    Enum.each(waiters, &GenServer.reply(&1, result))
    now = System.monotonic_time(:millisecond)

    recent =
      state.recent
      |> Map.reject(fn {_domain, {_result, until}} -> until <= now end)
      |> Map.put(domain, {result, now + @remember})

    {:noreply, %{state | waiting: waiting, recent: recent}}
  end

  def handle_info(_message, state), do: {:noreply, state}

  ## Lookup

  @doc false
  # The RFC 8461 §5.1 steps, without the process: for tests.
  @spec find(map(), String.t(), DateTime.t()) :: result()
  def find(config, domain, now) do
    cached = cached(config.repo, domain, now)

    case MTASTS.discover(config.resolver, domain) do
      {:ok, id} when cached != nil and cached.id == id ->
        applied(cached.policy)

      {:ok, id} ->
        fetch(config, domain, id, cached, now)

      {:error, _reason} when cached != nil ->
        applied(cached.policy)

      {:error, {:dns, reason}} ->
        failed(domain, {:sts_policy_fetch_error, "_mta-sts lookup failed: #{reason}"})

      # No record, or an unusable one: the domain has no policy.
      {:error, _} ->
        %{policy: nil, failure: nil}
    end
  end

  defp fetch(config, domain, id, cached, now) do
    case MTASTS.fetch(domain, config.fetch) do
      {:ok, policy} ->
        store(config.repo, domain, id, policy, now)

        :telemetry.execute([:sovite, :mta_sts, :fetched], %{}, %{
          domain: domain,
          policy_id: id,
          mode: policy.mode
        })

        applied(policy)

      {:error, _reason} when cached != nil ->
        applied(cached.policy)

      {:error, reason} ->
        failed(domain, fetch_failure(reason))
    end
  end

  defp fetch_failure({:tls, reason}),
    do: {:sts_webpki_invalid, "policy host TLS failed: #{Sovite.TLS.format_error(reason)}"}

  defp fetch_failure({:invalid_policy, reason}),
    do: {:sts_policy_invalid, "invalid policy: #{inspect(reason)}"}

  defp fetch_failure(reason),
    do: {:sts_policy_fetch_error, "policy fetch failed: #{inspect(reason)}"}

  defp failed(domain, {_type, text} = failure) do
    :telemetry.execute([:sovite, :mta_sts, :failed], %{}, %{domain: domain, reason: text})
    %{policy: nil, failure: failure}
  end

  defp applied(%Policy{mode: :none}), do: %{policy: nil, failure: nil}
  defp applied(policy), do: %{policy: policy, failure: nil}

  defp cached(repo, domain, now) do
    with %{} = row <- MTASTSPolicies.get(repo, domain),
         :gt <- DateTime.compare(row.expires_at, now),
         {:ok, policy} <- MTASTS.parse_policy(row.policy) do
      %{id: row.policy_id, policy: policy}
    else
      _ -> nil
    end
  end

  defp store(repo, domain, id, policy, now) do
    now = DateTime.truncate(now, :second)

    MTASTSPolicies.put(repo, %{
      domain: domain,
      policy_id: id,
      mode: policy.mode,
      max_age: policy.max_age,
      policy: policy.text,
      fetched_at: now,
      expires_at: DateTime.add(now, policy.max_age)
    })
  end
end
