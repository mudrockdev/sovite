defmodule Sovite.SMTP.Server.Connection do
  @moduledoc """
  Runs a `Sovite.SMTP.Server.Session` on an accepted socket. Started by
  `Sovite.Listener`; see `Sovite.SMTP.Server` for the public API.

  The socket is read in `active: :once` mode, so a client that floods the
  server only fills the kernel buffers, and every read is followed by the
  replies to all complete commands in it.

  On server shutdown, open sessions get `421 4.3.2` before the socket is
  closed.

  ## Telemetry

    * `[:sovite, :smtp, :server, :session, :start]` - `%{system_time}`,
      `%{session_id, remote_ip}`
    * `[:sovite, :smtp, :server, :session, :stop]` - `%{duration}`, same metadata
  """

  @behaviour Sovite.Listener.Handler

  use GenServer, restart: :temporary

  alias Sovite.Listener
  alias Sovite.SMTP.Reply
  alias Sovite.SMTP.Server.Session

  @impl Sovite.Listener.Handler
  def start_link(info, opts), do: GenServer.start_link(__MODULE__, {info, opts})

  @impl Sovite.Listener.Handler
  def reject(socket, _reason, opts) do
    hostname = opts |> Keyword.fetch!(:session) |> Keyword.fetch!(:hostname)
    reply = Reply.new(421, "4.7.0", "#{hostname} Error: too many connections")
    :gen_tcp.send(socket, Reply.encode(reply))
  end

  @impl GenServer
  def init({info, opts}) do
    # Trapping exits gets terminate/2 called on shutdown.
    Process.flag(:trap_exit, true)
    {:ok, %{info: info, opts: opts, session: nil, started_at: nil}, {:continue, :handshake}}
  end

  @impl GenServer
  def handle_continue(:handshake, %{info: info} = state) do
    case Listener.handshake(info) do
      :ok ->
        connection = Map.take(info, [:remote_ip, :remote_port, :local_ip, :local_port, :listener])
        {result, output, session} = Session.new(connection, Keyword.fetch!(state.opts, :session))
        state = %{state | session: session, started_at: System.monotonic_time()}

        :telemetry.execute(
          [:sovite, :smtp, :server, :session, :start],
          %{system_time: System.system_time()},
          metadata(state)
        )

        respond(result, output, state)

      {:error, :timeout} ->
        {:stop, :normal, state}
    end
  end

  @impl GenServer
  def handle_info({:tcp, socket, data}, %{info: %{socket: socket}} = state) do
    {result, output, session} = Session.handle_input(state.session, data)
    respond(result, output, %{state | session: session})
  end

  def handle_info({:tcp_closed, _socket}, state), do: {:stop, :normal, state}
  def handle_info({:tcp_error, _socket, _reason}, state), do: {:stop, :normal, state}

  def handle_info(:timeout, state) do
    {result, output, session} = Session.handle_timeout(state.session)
    respond(result, output, %{state | session: session})
  end

  def handle_info({:EXIT, _pid, reason}, state), do: {:stop, reason, state}
  def handle_info(_message, state), do: {:noreply, state, timeout(state)}

  @impl GenServer
  def terminate(_reason, %{session: nil, info: info}), do: :gen_tcp.close(info.socket)

  def terminate(reason, state) do
    if reason == :shutdown or match?({:shutdown, _}, reason) do
      reply = Reply.new(421, "4.3.2", "#{hostname(state)} Service shutting down")
      _ = :gen_tcp.send(state.info.socket, Reply.encode(reply))
    end

    Session.terminate(state.session, reason)
    :gen_tcp.close(state.info.socket)

    :telemetry.execute(
      [:sovite, :smtp, :server, :session, :stop],
      %{duration: System.monotonic_time() - state.started_at},
      metadata(state)
    )
  end

  defp respond(result, output, state) do
    send_result =
      if IO.iodata_length(output) > 0, do: :gen_tcp.send(state.info.socket, output), else: :ok

    cond do
      result == :close or send_result != :ok ->
        # The session has already ended; do not send 421 on top.
        {:stop, :normal, state}

      :inet.setopts(state.info.socket, active: :once) != :ok ->
        {:stop, :normal, state}

      true ->
        {:noreply, state, timeout(state)}
    end
  end

  defp timeout(%{session: nil}), do: :infinity
  defp timeout(%{session: session}), do: Session.timeout(session)

  defp hostname(state), do: state.opts |> Keyword.fetch!(:session) |> Keyword.fetch!(:hostname)

  defp metadata(state),
    do: %{session_id: Session.session_id(state.session), remote_ip: state.info.remote_ip}
end
