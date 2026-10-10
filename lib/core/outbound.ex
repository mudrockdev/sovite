defmodule Sovite.Core.Outbound do
  @moduledoc """
  Outbound abuse protection (`[outbound]`): detects accounts that are
  probably compromised, from how much of the mail they send fails.

  Each recipient an authenticated user's message is queued for counts as
  sent, and each one that fails for good (and is bounced) as failed,
  over the last `outbound.window`. A user with at least
  `outbound.min_failures` failures, making up at least
  `outbound.max_failure_percent` of what they sent, is suspended for
  `outbound.suspend_time`: their `MAIL` commands get `550 5.7.1`. Spam
  sent from a stolen account goes to many addresses that do not exist,
  so its failure rate spikes. Sending volume is capped by the user rate
  limits (`rate_limit.user_messages` and `rate_limit.user_recipients`).

  Suspensions are kept in memory: restarting Sovite lifts them.

  ## Telemetry

    * `[:sovite, :outbound, :suspended]` - `%{sent, failed}`, `%{user,
      suspend_time}`
  """

  alias Sovite.Abuse.{Cache, RateLimit}

  @doc """
  The options from the config, with the `Sovite.Abuse.RateLimit` and
  `Sovite.Abuse.Cache` (for suspensions) to use. `nil` when it is off.
  """
  @spec opts(Sovite.Core.Config.t(), atom() | nil, atom() | nil) :: map() | nil
  def opts(%{outbound: %{enabled: true} = outbound}, rate_limit, cache)
      when rate_limit != nil and cache != nil do
    outbound
    |> Map.take([:max_failure_percent, :min_failures, :window, :suspend_time])
    |> Map.merge(%{rate_limit: rate_limit, cache: cache})
  end

  def opts(_config, _rate_limit, _cache), do: nil

  @doc "Whether `user` is suspended."
  @spec suspended?(map() | nil, String.t()) :: boolean()
  def suspended?(nil, _user), do: false
  def suspended?(opts, user), do: Cache.get(opts.cache, {:suspended, key(user)}) != :error

  @doc "Counts `count` recipients queued for `user`."
  @spec sent(map() | nil, String.t() | nil, non_neg_integer()) :: :ok
  def sent(opts, user, count) when opts == nil or user == nil or count == 0, do: :ok

  def sent(opts, user, count) do
    RateLimit.add(opts.rate_limit, {:outbound_sent, key(user)}, opts.window, count)
    :ok
  end

  @doc "Counts `count` failed recipients of `user`, and suspends the user if needed."
  @spec failed(map() | nil, String.t() | nil, non_neg_integer()) :: :ok
  def failed(opts, user, count) when opts == nil or user == nil or count == 0, do: :ok

  def failed(opts, user, count) do
    user = key(user)
    failed = RateLimit.add(opts.rate_limit, {:outbound_failed, user}, opts.window, count)
    sent = RateLimit.count(opts.rate_limit, {:outbound_sent, user}, opts.window)

    if failed >= opts.min_failures and failed * 100 >= opts.max_failure_percent * max(sent, 1) and
         not suspended?(opts, user) do
      Cache.put(opts.cache, {:suspended, user}, true, opts.suspend_time)

      :telemetry.execute([:sovite, :outbound, :suspended], %{sent: sent, failed: failed}, %{
        user: user,
        suspend_time: opts.suspend_time
      })
    end

    :ok
  end

  defp key(user), do: String.downcase(user)
end
