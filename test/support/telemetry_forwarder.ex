defmodule Sovite.Test.TelemetryForwarder do
  @moduledoc """
  Forwards `:telemetry` events to a test process as
  `{:telemetry, event, measurements, metadata}`.

      Sovite.Test.TelemetryForwarder.attach([[:sovite, :queue, :message, :removed]])

  Events are global, so tests that run concurrently should match on
  metadata they own, such as a queue ID. The handler is detached when the
  test ends.
  """

  import ExUnit.Callbacks, only: [on_exit: 1]

  def attach(events) do
    id = "forwarder-#{System.unique_integer([:positive])}"
    :ok = :telemetry.attach_many(id, events, &__MODULE__.handle_event/4, self())
    on_exit(fn -> :telemetry.detach(id) end)
    :ok
  end

  @doc false
  def handle_event(event, measurements, metadata, pid),
    do: send(pid, {:telemetry, event, measurements, metadata})
end
