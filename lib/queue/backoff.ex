defmodule Sovite.Queue.Backoff do
  @moduledoc """
  Retry delays for deferred messages (RFC 5321 §4.5.4.1).

  The delay doubles with each attempt, from `min` up to `max`:

      iex> Sovite.Queue.Backoff.delay(1, min: 300_000, max: 3_600_000, jitter: 0)
      300_000
      iex> Sovite.Queue.Backoff.delay(3, min: 300_000, max: 3_600_000, jitter: 0)
      1_200_000
      iex> Sovite.Queue.Backoff.delay(10, min: 300_000, max: 3_600_000, jitter: 0)
      3_600_000

  A random jitter spreads out retries of messages that were deferred
  together, so they do not all hit the destination at once.
  """

  @doc """
  Milliseconds to wait after failed attempt number `attempts` (1 for
  the first attempt).

  ## Options

    * `:min` - delay after the first attempt, in milliseconds. Required.
    * `:max` - largest delay, in milliseconds. Required.
    * `:jitter` - fraction of the delay to add or subtract at random.
      Defaults to `0.1`.
  """
  @spec delay(pos_integer(), keyword()) :: pos_integer()
  def delay(attempts, opts) when is_integer(attempts) and attempts > 0 do
    min = Keyword.fetch!(opts, :min)
    max = Keyword.fetch!(opts, :max)
    jitter = Keyword.get(opts, :jitter, 0.1)

    # Capping the exponent keeps the integer small for very old messages.
    base = min(min * Integer.pow(2, min(attempts - 1, 32)), max)
    spread = round(base * jitter)
    offset = if spread > 0, do: :rand.uniform(2 * spread + 1) - spread - 1, else: 0
    max(base + offset, 1)
  end
end
