defmodule Sovite.DMARC.Policy do
  @moduledoc """
  A discovered DMARC policy: the record, the domain it was found at
  (the From domain or one of its parents), and the From domain's
  Organizational Domain. See `Sovite.DMARC.discover/2`.
  """

  alias Sovite.DMARC.Record

  @enforce_keys [:record, :domain, :org_domain]
  defstruct [:record, :domain, :org_domain]

  @type t :: %__MODULE__{record: Record.t(), domain: String.t(), org_domain: String.t()}
end
