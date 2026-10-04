defmodule Sovite.Queue.Entry do
  @moduledoc """
  The delivery state of a queued message: its envelope, plus the
  `Sovite.Queue.Record`s appended so far, replayed in order.

  Each recipient is `:pending` (never tried), `:deferred`, `:delivered`,
  or `:failed`. Final states never change, so a record replayed after a
  crash cannot bring a delivered recipient back.
  """

  alias Sovite.Queue.{Envelope, Record}

  @enforce_keys [:envelope, :recipients]
  defstruct [:envelope, :recipients, :next_attempt, attempts: 0, warned: false]

  @typedoc "The state of one recipient."
  @type recipient :: %{
          status: :pending | Record.status(),
          details: Record.details() | nil,
          notified: boolean()
        }

  @type t :: %__MODULE__{
          envelope: Envelope.t(),
          recipients: %{String.t() => recipient()},
          attempts: non_neg_integer(),
          next_attempt: DateTime.t() | nil,
          warned: boolean()
        }

  @doc "Builds the state from an envelope and its records."
  @spec new(Envelope.t(), [Record.t()]) :: t()
  def new(%Envelope{} = envelope, records \\ []) do
    recipients =
      Map.new(envelope.recipients, &{&1, %{status: :pending, details: nil, notified: false}})

    Enum.reduce(
      records,
      %__MODULE__{envelope: envelope, recipients: recipients},
      &apply_record(&2, &1)
    )
  end

  @doc "Applies one record. Records for unknown recipients are ignored."
  @spec apply_record(t(), Record.t()) :: t()
  def apply_record(entry, {:recipient, address, status, details}) do
    update_recipient(entry, address, fn
      %{status: final} = recipient when final in [:delivered, :failed] -> recipient
      recipient -> %{recipient | status: status, details: details}
    end)
  end

  def apply_record(entry, {:notified, addresses}) do
    Enum.reduce(addresses, entry, fn address, entry ->
      update_recipient(entry, address, &%{&1 | notified: true})
    end)
  end

  def apply_record(entry, {:retry, attempts, next_attempt}),
    do: %{entry | attempts: attempts, next_attempt: next_attempt}

  def apply_record(entry, :warned), do: %{entry | warned: true}

  defp update_recipient(entry, address, fun) do
    case Map.fetch(entry.recipients, address) do
      {:ok, recipient} -> put_in(entry.recipients[address], fun.(recipient))
      :error -> entry
    end
  end

  @doc "Recipients still to be delivered (pending or deferred), in envelope order."
  @spec pending(t()) :: [String.t()]
  def pending(entry), do: with_status(entry, [:pending, :deferred])

  @doc "Recipients with `status`, in envelope order."
  @spec with_status(t(), Record.status() | :pending | [Record.status() | :pending]) :: [
          String.t()
        ]
  def with_status(entry, statuses) do
    statuses = List.wrap(statuses)
    Enum.filter(entry.envelope.recipients, &(entry.recipients[&1].status in statuses))
  end

  @doc "Failed recipients the sender has not been told about, with their details."
  @spec unnotified_failures(t()) :: [{String.t(), Record.details()}]
  def unnotified_failures(entry) do
    for address <- with_status(entry, :failed),
        %{notified: false, details: details} <- [entry.recipients[address]],
        do: {address, details}
  end

  @doc "Returns `true` when every recipient is delivered or failed."
  @spec done?(t()) :: boolean()
  def done?(entry), do: pending(entry) == []
end
