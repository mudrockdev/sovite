defmodule Sovite.Core.Screen do
  @moduledoc """
  Anti-abuse checks of SMTP clients, run by `Sovite.Core.SMTPHandler`
  before its own checks of each stage. Clients in
  `smtp.trusted_networks` skip all of them.

  ## The screen

  On listeners with `screen` (by default those in `smtp` mode), each
  client gets a score, as with Postfix's postscreen:

    * The client address is looked up in the `[[screen.dnsbl]]` lists
      (`Sovite.Abuse.DNSBL`), in the background. Each list it is on adds
      its weight; allow lists such as DNSWL have negative weights.
    * With `screen.greet_delay`, the greeting waits that long. A client
      that talks first adds `screen.early_talker_weight`.
    * At `EHLO` and `MAIL`, the `[[screen.rhsbl]]` lists are checked for
      the `EHLO` name and the sender's domain.

  A client that reaches `screen.threshold` is refused: before the
  greeting with `554 5.7.1`, then the connection is closed; at `EHLO` or
  `MAIL`, that command gets `554 5.7.1`. A client at or below
  `screen.allow_threshold` is allow-listed: the domain lists and
  greylisting are skipped. A client that passed the greeting, without
  talking first or a failed lookup, is remembered for `screen.cache_time`
  and not delayed or looked up again meanwhile.

  ## Rate limits

  The `[rate_limit]` limits count, per client address (per /64 for
  IPv6), new connections (`421 4.7.0` and closed), messages (`MAIL`,
  `450 4.7.1`), and recipients (`450 4.7.1`); and per authenticated user,
  messages and recipients. Authenticated clients only count against the
  user limits.

  ## Greylisting

  With `greylist.enabled`, a valid recipient from an unknown client
  network and sender is deferred with `450 4.7.1` until the client tries
  again after `greylist.delay`, see `Sovite.Core.Greylist`. Authenticated
  and allow-listed clients, and listeners without `screen`, skip it.

  ## Outbound

  Authenticated users whose mail fails too often are suspended, see
  `Sovite.Core.Outbound`; their `MAIL` gets `550 5.7.1`.

  ## Telemetry

    * `[:sovite, :screen, :rejected]` - `%{score}`, `%{session_id,
      remote_ip, stage, reasons}`, when a client reaches the threshold.
  """

  alias Sovite.Abuse.{Cache, DNSBL, RateLimit}
  alias Sovite.Core.{Greylist, Outbound}
  alias Sovite.SMTP.Reply

  @doc """
  The options for a listener. `runtime` has `:screen` (the listener
  screens clients), `:screen_cache` (a `Sovite.Abuse.Cache`),
  `:rate_limit` (a `Sovite.Abuse.RateLimit`), `:repo`, and `:outbound`
  (`Sovite.Core.Outbound` options).
  """
  @spec opts(Sovite.Core.Config.t(), keyword()) :: map()
  def opts(config, runtime) do
    screen = config.screen
    lists = fn kind -> Enum.filter(screen.rhsbl, &(kind in &1.check)) |> Enum.map(&list/1) end

    %{
      enabled: Keyword.get(runtime, :screen, false),
      greet_delay: screen.greet_delay,
      early_talker_weight: screen.early_talker_weight,
      threshold: screen.threshold,
      allow_threshold: screen.allow_threshold,
      lookup_timeout: screen.lookup_timeout,
      cache_time: screen.cache_time,
      dnsbl: Enum.map(screen.dnsbl, &list/1),
      helo_lists: lists.(:helo),
      sender_lists: lists.(:sender),
      cache: runtime[:screen_cache],
      rate_limit: runtime[:rate_limit],
      limits: config.rate_limit,
      greylist: Greylist.opts(config, runtime[:repo]),
      outbound: runtime[:outbound]
    }
  end

  defp list(list), do: Map.take(list, [:zone, :weight, :codes])

  @doc "The screen state of a new session."
  @spec new() :: map()
  def new,
    do: %{
      score: 0,
      helo_score: 0,
      sender_score: 0,
      reasons: [],
      lookup: nil,
      allowlisted: false,
      checked: false
    }

  # Clients the screen looks at.
  defp screened?(state), do: state.screen.enabled and not state.trusted

  defp inbound?(state), do: not state.trusted and state.identity == nil

  ## Connect

  @doc "Counts the connection against `rate_limit.client_connections`."
  @spec limit_connection(map()) :: {:ok, map()} | {:close, Reply.t(), map()}
  def limit_connection(state) do
    if not state.trusted and limited?(state, :client_connections, client_key(state)) do
      text = "#{state.hostname} Error: too many connections from your address"
      {:close, Reply.new(421, "4.7.0", text), state}
    else
      {:ok, state}
    end
  end

  @doc """
  Starts screening the client: looks it up in the DNS lists, and asks
  for the greeting delay.
  """
  @spec connect(map()) :: {:ok, map()} | {:pause, pos_integer(), map()}
  def connect(state) do
    opts = state.screen

    cond do
      not screened?(state) ->
        {:ok, state}

      cached = cached(state) ->
        {:ok, put_score(state, %{cached | lookup: nil, checked: true})}

      true ->
        lookup =
          if opts.dnsbl != [],
            do:
              DNSBL.async_score(state.resolver, {:ip, ip(state)}, opts.dnsbl,
                timeout: opts.lookup_timeout
              )

        state = put_score(state, %{state.score | lookup: lookup})
        if opts.greet_delay, do: {:pause, opts.greet_delay, state}, else: {:ok, state}
    end
  end

  defp cached(%{screen: %{cache: nil}}), do: nil

  defp cached(state) do
    case Cache.get(state.screen.cache, {:passed, ip(state)}) do
      {:ok, score} -> score
      :error -> nil
    end
  end

  @doc "Scores the client before the greeting, see the moduledoc."
  @spec greet(binary(), map()) :: {:ok, map()} | {:close, Reply.t(), map()}
  def greet(early, state) do
    if screened?(state) and not state.score.checked,
      do: score(early, state),
      else: {:ok, state}
  end

  defp score(early, state) do
    opts = state.screen
    lookup = lookup_result(state.score.lookup, opts.lookup_timeout)
    early_talker = early != ""

    reasons =
      Enum.map(lookup.hits, &"listed by #{&1.zone}") ++
        if(early_talker, do: ["talked before the greeting"], else: [])

    score = lookup.score + if(early_talker, do: opts.early_talker_weight, else: 0)

    screen = %{
      state.score
      | score: score,
        reasons: reasons,
        lookup: nil,
        allowlisted: score <= opts.allow_threshold,
        checked: true
    }

    state = put_score(state, screen)

    if score >= opts.threshold do
      rejected(state, :connect, score, reasons)
      ip = state |> ip() |> :inet.ntoa()
      text = "Service unavailable; client [#{ip}] blocked: #{Enum.join(reasons, ", ")}"
      {:close, Reply.new(554, "5.7.1", text), state}
    else
      if not early_talker and lookup.complete, do: remember(state, screen)
      {:ok, state}
    end
  end

  defp lookup_result(nil, _timeout), do: %{score: 0, hits: [], complete: true}

  defp lookup_result(lookup, timeout) do
    case DNSBL.await(lookup, timeout) do
      {:ok, result} -> Map.put(result, :complete, result.errors == [])
      {:error, :timeout} -> %{score: 0, hits: [], complete: false}
    end
  end

  defp remember(%{screen: %{cache: nil}}, _screen), do: :ok

  defp remember(state, screen),
    do: Cache.put(state.screen.cache, {:passed, ip(state)}, screen, state.screen.cache_time)

  ## EHLO and MAIL

  @doc "Checks the `EHLO` name in the RHSBL lists."
  @spec helo(map()) :: {:ok, map()} | {:reply, Reply.t(), map()}
  def helo(state) do
    lists = state.screen.helo_lists

    if domain_checks?(state, lists) and not String.starts_with?(state.helo, "[") do
      result = domain_score(state, state.helo, lists)
      state = put_score(state, %{state.score | helo_score: result.score})
      domain_verdict(state, :helo, result, "<#{state.helo}>: Helo command rejected")
    else
      {:ok, put_score(state, %{state.score | helo_score: 0})}
    end
  end

  @doc """
  Checks a `MAIL` command: suspension and sending limits of the user,
  message limits of the client, and the sender's domain in the RHSBL
  lists.
  """
  @spec mail(String.t(), map()) :: {:ok, map()} | {:reply, Reply.t(), map()}
  def mail(sender, state) do
    state = put_score(state, %{state.score | sender_score: 0})

    cond do
      state.trusted ->
        {:ok, state}

      state.identity != nil ->
        user_mail(state)

      limited?(state, :client_messages, client_key(state)) ->
        ip = state |> ip() |> :inet.ntoa()
        text = "Error: too many messages from [#{ip}], try again later"
        {:reply, Reply.new(450, "4.7.1", text), state}

      true ->
        sender_domain(sender, state)
    end
  end

  defp user_mail(state) do
    user = String.downcase(state.identity)

    cond do
      Outbound.suspended?(state.screen.outbound, user) ->
        text = "Sending suspended for #{state.identity}: too many failed deliveries"
        {:reply, Reply.new(550, "5.7.1", text), state}

      limited?(state, :user_messages, {:user, user}) ->
        {:reply, quota_exceeded(state), state}

      true ->
        {:ok, state}
    end
  end

  defp sender_domain(sender, state) do
    lists = state.screen.sender_lists

    with true <- domain_checks?(state, lists),
         domain when is_binary(domain) <- domain(sender) do
      result = domain_score(state, domain, lists)
      state = put_score(state, %{state.score | sender_score: result.score})
      domain_verdict(state, :mail, result, "<#{sender}>: Sender address rejected")
    else
      _ -> {:ok, state}
    end
  end

  # The domain is after the last "@"; the null sender has none.
  defp domain(sender) do
    case String.split(sender, "@") do
      [_no_domain] -> nil
      parts -> List.last(parts)
    end
  end

  defp domain_checks?(state, lists),
    do: lists != [] and screened?(state) and inbound?(state) and not state.score.allowlisted

  defp domain_score(state, domain, lists),
    do:
      DNSBL.score(state.resolver, {:domain, domain}, lists, timeout: state.screen.lookup_timeout)

  defp domain_verdict(state, stage, result, prefix) do
    score = total(state)

    if result.hits != [] and score >= state.screen.threshold do
      reasons = Enum.map(result.hits, &"listed by #{&1.zone}")
      rejected(state, stage, score, reasons)
      {:reply, Reply.new(554, "5.7.1", "#{prefix}: #{Enum.join(reasons, ", ")}"), state}
    else
      {:ok, state}
    end
  end

  defp total(%{score: score}), do: score.score + score.helo_score + score.sender_score

  ## RCPT

  @doc """
  Checks an accepted recipient: greylisting, and the recipient limits of
  the user or the client.
  """
  @spec rcpt(String.t(), map()) :: {:ok, map()} | {:reply, Reply.t(), map()}
  def rcpt(recipient, state) do
    cond do
      state.trusted ->
        {:ok, state}

      state.identity != nil ->
        if limited?(state, :user_recipients, {:user, String.downcase(state.identity)}),
          do: {:reply, quota_exceeded(state), state},
          else: {:ok, state}

      true ->
        client_rcpt(recipient, state)
    end
  end

  defp client_rcpt(recipient, state) do
    greylist =
      if screened?(state) and not state.score.allowlisted,
        do: Greylist.check(state.screen.greylist, ip(state), state.sender || "", recipient),
        else: :pass

    case greylist do
      {:defer, seconds} ->
        text = "<#{recipient}>: Recipient address rejected: Greylisted, try again in #{seconds}s"
        {:reply, Reply.new(450, "4.7.1", text), state}

      :pass ->
        if limited?(state, :client_recipients, client_key(state)) do
          ip = state |> ip() |> :inet.ntoa()
          text = "Error: too many recipients from [#{ip}], try again later"
          {:reply, Reply.new(450, "4.7.1", text), state}
        else
          {:ok, state}
        end
    end
  end

  defp quota_exceeded(state),
    do: Reply.new(450, "4.7.1", "Sending limit exceeded for #{state.identity}, try again later")

  ## Helpers

  defp limited?(%{screen: %{rate_limit: nil}}, _limit, _key), do: false

  defp limited?(state, limit, key) do
    case Map.fetch!(state.screen.limits, limit) do
      nil ->
        false

      {count, window} ->
        RateLimit.hit(state.screen.rate_limit, {limit, key}, count, window) != :ok
    end
  end

  defp client_key(state), do: {:client, state |> ip() |> address_key()}

  @doc false
  # IPv6 clients usually control a whole /64, so they count per /64.
  def address_key({a, b, c, d, _, _, _, _}), do: {a, b, c, d, 0, 0, 0, 0}
  def address_key(ip), do: ip

  defp ip(state), do: state.connection.remote_ip

  defp put_score(state, score), do: %{state | score: score}

  defp rejected(state, stage, score, reasons) do
    :telemetry.execute([:sovite, :screen, :rejected], %{score: score}, %{
      session_id: state.connection.session_id,
      remote_ip: ip(state),
      stage: stage,
      reasons: reasons
    })
  end
end
