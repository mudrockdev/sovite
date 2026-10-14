defmodule Sovite.Core.Control.Signals do
  @moduledoc false
  # A handler of the VM's signal server: sends SIGHUP to the Control
  # process as `:sighup`. Other signals keep their default handling
  # (SIGTERM stops the VM gracefully).

  @behaviour :gen_event

  @id {__MODULE__, :control}

  @doc "Handles SIGHUP for `control`."
  def install(control) do
    :ok = :os.set_signal(:sighup, :handle)
    _ = :gen_event.delete_handler(:erl_signal_server, @id, :replaced)
    :gen_event.add_handler(:erl_signal_server, @id, control)
  end

  @doc "Stops handling SIGHUP for `control`."
  def remove(control) do
    case :gen_event.call(:erl_signal_server, @id, :control) do
      ^control ->
        _ = :gen_event.delete_handler(:erl_signal_server, @id, :removed)
        :os.set_signal(:sighup, :default)

      _ ->
        :ok
    end
  catch
    _kind, _reason -> :ok
  end

  @impl true
  def init(control), do: {:ok, control}

  @impl true
  def handle_event(:sighup, control) do
    send(control, :sighup)
    {:ok, control}
  end

  def handle_event(_signal, control), do: {:ok, control}

  @impl true
  def handle_call(:control, control), do: {:ok, control, control}

  @impl true
  def handle_info(_message, control), do: {:ok, control}

  @impl true
  def terminate(_reason, _control), do: :ok
end
