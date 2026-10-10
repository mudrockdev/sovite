defmodule Sovite.SPF.Result do
  @moduledoc """
  The outcome of an SPF check.

    * `:result` - one of the results of RFC 7208 §2.6.
    * `:domain` - the domain that was checked.
    * `:explanation` - the expanded `exp=` text, only on `:fail` and only
      if the record has a usable one.
    * `:reason` - a human-readable diagnostic for `:none`, `:temperror`,
      and `:permerror`, such as `"too many DNS lookups"`.
    * `:mechanism` - the term that matched, as written in the record
      (`"ip4:192.0.2.0/24"`, `"-all"`, `"include:_spf.example.net"`), or
      `nil` if none did.
  """

  @enforce_keys [:result]
  defstruct [:result, domain: nil, explanation: nil, reason: nil, mechanism: nil]

  @type t :: %__MODULE__{
          result: Sovite.SPF.result(),
          domain: String.t() | nil,
          explanation: String.t() | nil,
          reason: String.t() | nil,
          mechanism: String.t() | nil
        }
end
