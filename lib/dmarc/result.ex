defmodule Sovite.DMARC.Result do
  @moduledoc """
  The outcome of `Sovite.DMARC.check/3`.

    * `result` - `:pass` if SPF or DKIM passed with an aligned domain,
      `:fail` if neither did, `:none` without a policy, `:temperror` on
      a DNS error, and `:permerror` for a From domain that is not a
      domain name.
    * `disposition` - what the policy asks for this message, after
      sampling. Always `:none` unless `result` is `:fail`.
    * `applied` - which policy tag gave the disposition on `:fail`: `:p`
      for the domain that published the record, `:sp` for a subdomain,
      `:np` for a subdomain that does not exist.
    * `sampled` - whether the failing message was selected by `pct=`
      (and the record is not in testing mode), so the disposition is the
      one published. When `false`, it is one step milder.
    * `dkim_domain` - the `d=` of the first passing, aligned DKIM
      signature.
    * `reason` - a human-readable note, for logs and reports.
  """

  alias Sovite.DMARC.{Policy, Record}

  @enforce_keys [:result, :from_domain]
  defstruct [
    :result,
    :from_domain,
    policy: nil,
    disposition: :none,
    applied: nil,
    sampled: false,
    spf_aligned: false,
    dkim_aligned: false,
    dkim_domain: nil,
    reason: nil
  ]

  @type t :: %__MODULE__{
          result: :pass | :fail | :none | :temperror | :permerror,
          from_domain: String.t(),
          policy: Policy.t() | nil,
          disposition: Record.policy(),
          applied: :p | :sp | :np | nil,
          sampled: boolean(),
          spf_aligned: boolean(),
          dkim_aligned: boolean(),
          dkim_domain: String.t() | nil,
          reason: String.t() | nil
        }
end
