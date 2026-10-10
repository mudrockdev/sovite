defmodule Sovite.TLS.MTASTS.Policy do
  @moduledoc """
  An MTA-STS policy (RFC 8461 §3.2), as served at
  `https://mta-sts.<domain>/.well-known/mta-sts.txt`.

    * `mode` - `:enforce` (deliver only over verified TLS to a matching
      MX), `:testing` (deliver anyway, but report failures with TLS-RPT),
      or `:none` (the domain no longer uses MTA-STS).
    * `mx` - the allowed MX host patterns, lower-cased: host names, or
      `*.` followed by a host name to allow any one extra leftmost label.
      Empty only with mode `:none`.
    * `max_age` - how long the policy may be cached, in seconds, at most
      31557600 (about a year).
    * `text` - the policy body as fetched, so it can be stored and parsed
      again with `Sovite.TLS.MTASTS.parse_policy/1`.

  `Sovite.TLS.MTASTS.parse_policy/1` builds it, and
  `Sovite.TLS.MTASTS.match?/2` checks MX hosts against it.
  """

  @enforce_keys [:mode, :mx, :max_age, :text]
  defstruct [:mode, :mx, :max_age, :text]

  @typedoc "What a sender does when delivery to a domain cannot meet the policy."
  @type mode :: :enforce | :testing | :none

  @type t :: %__MODULE__{
          mode: mode(),
          mx: [String.t()],
          max_age: non_neg_integer(),
          text: String.t()
        }
end
