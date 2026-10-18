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

  In the single-binary build, the command line picks between the server
  and the commands (see `Sovite.Core.Standalone`).
  """

  use Application

  alias Sovite.Core.{Control, Standalone}

  @impl true
  def start(_type, _args) do
    case Standalone.command() do
      # Before the VM's own command line would run: it would take the
      # command for a script.
      {:run, command} ->
        command.() |> System.halt()

      :server ->
        Standalone.keep_running()
        start_tree(Application.get_env(:sovite, :start_mta, false))

      nil ->
        start_tree(Application.get_env(:sovite, :start_mta, false))
    end
  end

  defp start_tree(start_mta) do
    children = if start_mta, do: [Sovite.Core.Supervisor], else: []
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
