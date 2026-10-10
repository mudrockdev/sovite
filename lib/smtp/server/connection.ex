defmodule Sovite.SMTP.Server.Connection do
  @moduledoc """
  Runs a `Sovite.SMTP.Server.Session` on an accepted socket. Started by
  `Sovite.Listener`; see `Sovite.SMTP.Server` for the public API.

  The socket is read in `active: :once` mode, so a client that floods the
  server only fills the kernel buffers, and every read is followed by the
  replies to all complete commands in it.

  With implicit TLS (RFC 8314), the TLS handshake runs before the
  greeting. With `STARTTLS`, it runs when the session asks for it. A
  failed handshake closes the connection.

  A tarpitted session's output is sent after its delay (see
  `Sovite.SMTP.Server.Session.take_delay/1`); the socket is not read
  meanwhile.

  On server shutdown, open sessions get `421 4.3.2` before the socket is
  closed.

  ## Telemetry

    * `[:sovite, :smtp, :server, :session, :start]` - `%{system_time}`,
      `%{session_id, remote_ip}`
    * `[:sovite, :smtp, :server, :session, :stop]` - `%{duration}`, same metadata
    * `[:sovite, :smtp, :server, :tls, :stop]` - `%{duration}`,
      `%{session_id, remote_ip, protocol, cipher, sni, error}`. `error` is
      `nil` on success, otherwise the `:ssl` reason, and the other TLS
      fields are `nil`.
  """

  @behaviour Sovite.Listener.Handler

  use GenServer, restart: :temporary

  alias Sovite.Listener
  alias Sovite.SMTP.Reply
  alias Sovite.SMTP.Server.Session
  alias Sovite.TLS

  @impl Sovite.Listener.Handler
  def start_link(info, opts), do: GenServer.start_link(__MODULE__, {info, opts})

  @impl Sovite.Listener.Handler
  def reject(socket, _reason, opts) do
    # A TLS client would read a plaintext reply as a broken handshake.
    unless opts[:implicit_tls] do
      hostname = opts |> Keyword.fetch!(:session) |> Keyword.fetch!(:hostname)
      reply = Reply.new(421, "4.7.0", "#{hostname} Error: too many connections")
      :gen_tcp.send(socket, Reply.encode(reply))
    end
  end

  @impl GenServer
  def init({info, opts}) do
    # Trapping exits gets terminate/2 called on shutdown.
    Process.flag(:trap_exit, true)

    state = %{
      info: info,
      opts: opts,
      socket: info.socket,
      transport: :gen_tcp,
      session_id: 8 |> :crypto.strong_rand_bytes() |> Base.encode32(padding: false, case: :lower),
      ssl_opts: nil,
      session: nil,
      started_at: nil,
      tarpit: false
    }

    {:ok, state, {:continue, :handshake}}
  end

  @impl GenServer
  def handle_continue(:handshake, %{info: info} = state) do
    with :ok <- Listener.handshake(info),
         {:ok, ssl_opts} <- tls_options(state),
         {:ok, state, tls} <- implicit_tls(state, ssl_opts) do
      start_session(state, ssl_opts, tls)
    else
      _ -> {:stop, :normal, state}
    end
  end

  defp tls_options(state) do
    case state.opts[:tls] do
      fun when is_function(fun, 0) -> {:ok, fun.()}
      opts -> {:ok, opts}
    end
  catch
    # The certificate store is down: carry on without TLS.
    :exit, _reason -> {:ok, nil}
  end

  defp implicit_tls(state, ssl_opts) do
    cond do
      not Keyword.get(state.opts, :implicit_tls, false) -> {:ok, state, nil}
      ssl_opts == nil -> :error
      true -> upgrade(state, ssl_opts)
    end
  end

  defp start_session(state, ssl_opts, tls) do
    connection =
      state.info
      |> Map.take([:remote_ip, :remote_port, :local_ip, :local_port, :listener])
      |> Map.merge(%{session_id: state.session_id, tls: tls})

    session_opts =
      state.opts
      |> Keyword.fetch!(:session)
      |> Keyword.put(:starttls, ssl_opts != nil and tls == nil)

    {result, output, session} = Session.new(connection, session_opts)
    state = %{state | session: session, ssl_opts: ssl_opts, started_at: System.monotonic_time()}

    :telemetry.execute(
      [:sovite, :smtp, :server, :session, :start],
      %{system_time: System.system_time()},
      metadata(state)
    )

    respond(result, output, state)
  end

  @impl GenServer
  def handle_info({kind, socket, data}, %{socket: socket} = state) when kind in [:tcp, :ssl] do
    {result, output, session} = Session.handle_input(state.session, data)
    respond(result, output, %{state | session: session})
  end

  def handle_info({kind, _socket}, state) when kind in [:tcp_closed, :ssl_closed],
    do: {:stop, :normal, state}

  def handle_info({kind, _socket, _reason}, state) when kind in [:tcp_error, :ssl_error],
    do: {:stop, :normal, state}

  def handle_info({:tarpit, result, output}, state),
    do: send_output(result, output, %{state | tarpit: false})

  def handle_info(:timeout, state) do
    {result, output, session} = Session.handle_timeout(state.session)
    respond(result, output, %{state | session: session})
  end

  def handle_info({:EXIT, _pid, reason}, state), do: {:stop, reason, state}
  def handle_info(_message, state), do: {:noreply, state, timeout(state)}

  @impl GenServer
  def terminate(_reason, %{session: nil} = state), do: close(state)

  def terminate(reason, state) do
    if reason == :shutdown or match?({:shutdown, _}, reason) do
      reply = Reply.new(421, "4.3.2", "#{hostname(state)} Service shutting down")
      _ = send_data(state, Reply.encode(reply))
    end

    Session.terminate(state.session, reason)
    close(state)

    :telemetry.execute(
      [:sovite, :smtp, :server, :session, :stop],
      %{duration: System.monotonic_time() - state.started_at},
      metadata(state)
    )
  end

  # A tarpitted session's output waits for its delay. The socket is not
  # read meanwhile.
  defp respond(result, output, state) do
    {delay, session} = Session.take_delay(state.session)
    state = %{state | session: session}

    if delay > 0 do
      Process.send_after(self(), {:tarpit, result, output}, delay)
      {:noreply, %{state | tarpit: true}}
    else
      send_output(result, output, state)
    end
  end

  defp send_output(result, output, state) do
    send_result = if IO.iodata_length(output) > 0, do: send_data(state, output), else: :ok

    cond do
      result == :close or send_result != :ok ->
        # The session has already ended; do not send 421 on top.
        {:stop, :normal, state}

      result == :starttls ->
        starttls(state)

      setopts(state, active: :once) != :ok ->
        {:stop, :normal, state}

      true ->
        {:noreply, state, timeout(state)}
    end
  end

  defp starttls(state) do
    case upgrade(state, state.ssl_opts) do
      {:ok, state, tls} ->
        {result, output, session} = Session.handle_tls(state.session, tls)
        respond(result, output, %{state | session: session})

      :error ->
        # No reply is possible: the client is mid-handshake.
        {:stop, :normal, state}
    end
  end

  # Runs the server side of a TLS handshake on the TCP socket.
  defp upgrade(state, ssl_opts) do
    started = System.monotonic_time()
    timeout = Keyword.get(state.opts, :tls_handshake_timeout, 60_000)

    result =
      try do
        :ssl.handshake(state.socket, ssl_opts, timeout)
      catch
        :exit, reason -> {:error, reason}
      end

    {state, tls, error} =
      with {:ok, socket} <- result,
           {:ok, tls} <- TLS.info(socket) do
        {%{state | socket: socket, transport: :ssl}, tls, nil}
      else
        {:error, reason} -> {state, nil, reason}
      end

    :telemetry.execute(
      [:sovite, :smtp, :server, :tls, :stop],
      %{duration: System.monotonic_time() - started},
      %{
        session_id: state.session_id,
        remote_ip: state.info.remote_ip,
        protocol: tls && tls.protocol,
        cipher: tls && tls.cipher,
        sni: tls && tls.sni,
        error: error
      }
    )

    if tls, do: {:ok, state, tls}, else: :error
  end

  defp send_data(%{transport: :gen_tcp, socket: socket}, data), do: :gen_tcp.send(socket, data)
  defp send_data(%{transport: :ssl, socket: socket}, data), do: :ssl.send(socket, data)

  defp setopts(%{transport: :gen_tcp, socket: socket}, opts), do: :inet.setopts(socket, opts)
  defp setopts(%{transport: :ssl, socket: socket}, opts), do: :ssl.setopts(socket, opts)

  defp close(%{transport: :gen_tcp, socket: socket}), do: :gen_tcp.close(socket)
  defp close(%{transport: :ssl, socket: socket}), do: :ssl.close(socket)

  defp timeout(%{session: nil}), do: :infinity
  defp timeout(%{tarpit: true}), do: :infinity
  defp timeout(%{session: session}), do: Session.timeout(session)

  defp hostname(state), do: state.opts |> Keyword.fetch!(:session) |> Keyword.fetch!(:hostname)

  defp metadata(state), do: %{session_id: state.session_id, remote_ip: state.info.remote_ip}
end
