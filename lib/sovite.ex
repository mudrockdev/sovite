defmodule Sovite do
  @moduledoc """
  Sovite, a Mail Transfer Agent written in Elixir/OTP.

  The `:sovite` application starts the MTA only when the `:start_mta`
  application env is `true`. Production releases set it in
  `config/runtime.exs`. When Sovite is a library dependency, nothing
  starts, and the components (`Sovite.Validators`, `Sovite.DNS`, ...) can
  be used on their own.

  To run the MTA inside another application's supervision tree, see
  `Sovite.Core.Supervisor`.
  """

  use Application

  alias Sovite.Core.Control

  @impl true
  def start(_type, _args) do
    children =
      if Application.get_env(:sovite, :start_mta, false),
        do: [Sovite.Core.Supervisor],
        else: []

    Supervisor.start_link(children, strategy: :one_for_one, name: Sovite.Supervisor)
  end

  # Before the tree stops: drain the MTA while all of it still runs (see
  # Sovite.Core.Control).
  @impl true
  def prep_stop(state) do
    if Process.whereis(Control), do: Control.drain(Control)
    state
  catch
    :exit, _reason -> state
  end
end
