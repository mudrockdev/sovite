defmodule Sovite.Systemd.Watchdog do
  @moduledoc """
  Sends the systemd watchdog ping (`WATCHDOG=1`) every half watchdog
  interval, for units with `WatchdogSec=`.

      children = [
        {Sovite.Systemd.Watchdog, check: &MyApp.healthy?/0}
      ]

  The first ping is sent at start. When the watchdog is disabled (see
  `Sovite.Systemd.watchdog_interval/1`), as outside systemd, `start_link/1`
  returns `:ignore` and no process runs.

  A `:check` function makes the ping depend on the service's health: when
  it returns anything but `true`, or raises, that tick's ping is skipped,
  and systemd restarts the service once a whole interval passes without
  one. It runs in the watchdog process, so a check that hangs stops the
  pings too.

  ## Options

    * `:check` - a 0-arity function returning `true` when the service is
      healthy. Defaults to none: every tick pings.
    * `:env` - a map of environment variables to read instead of the OS
      environment, as in `Sovite.Systemd`.
    * `:name` - registered name of the process.

  ## Telemetry

    * `[:sovite, :systemd, :watchdog, :skipped]` - `%{}`, `%{reason}`: the
      check failed, so no ping was sent. `reason` is what the check
      returned, or `{kind, reason}` when it raised, threw, or exited.
  """

  use GenServer

  alias Sovite.Systemd

  @doc "Starts the watchdog, or returns `:ignore` when it is disabled."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    opts = Keyword.validate!(opts, [:check, :env, :name])

    case opts[:name] do
      nil -> GenServer.start_link(__MODULE__, opts)
      name -> GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  @impl true
  def init(opts) do
    notify_opts = Keyword.take(opts, [:env])

    case Systemd.watchdog_interval(notify_opts) do
      {:ok, interval} ->
        state = %{
          check: opts[:check],
          notify_opts: notify_opts,
          period: max(div(interval, 2), 1)
        }

        {:ok, state, {:continue, :ping}}

      :disabled ->
        :ignore
    end
  end

  @impl true
  def handle_continue(:ping, state), do: {:noreply, tick(state)}

  @impl true
  def handle_info(:ping, state), do: {:noreply, tick(state)}

  defp tick(state) do
    case check(state.check) do
      :ok ->
        Systemd.watchdog(state.notify_opts)

      {:error, reason} ->
        :telemetry.execute([:sovite, :systemd, :watchdog, :skipped], %{}, %{reason: reason})
    end

    Process.send_after(self(), :ping, state.period)
    state
  end

  defp check(nil), do: :ok

  defp check(fun) do
    case fun.() do
      true -> :ok
      other -> {:error, other}
    end
  catch
    kind, reason -> {:error, {kind, reason}}
  end
end
