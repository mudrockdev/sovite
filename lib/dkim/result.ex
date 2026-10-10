defmodule Sovite.DKIM.Result do
  @moduledoc """
  The outcome for one signature. `b` is the start of the signature, to
  tell signatures apart in `Authentication-Results:` (`header.b`, RFC
  6008).
  """

  defstruct [:result, :domain, :selector, :identity, :algorithm, :b, :reason]

  @type t :: %__MODULE__{
          result: :pass | :fail | :neutral | :temperror | :permerror,
          domain: String.t() | nil,
          selector: String.t() | nil,
          identity: String.t() | nil,
          algorithm: String.t() | nil,
          b: String.t() | nil,
          reason: String.t() | nil
        }
end
