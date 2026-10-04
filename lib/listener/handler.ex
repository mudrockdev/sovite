defmodule Sovite.Listener.Handler do
  @moduledoc """
  Behaviour for the process that serves one accepted connection.

  The listener starts it with `start_link/2` under its connection
  supervisor, then hands over the socket. The process must call
  `Sovite.Listener.handshake/1` before using the socket.
  """

  @doc "Starts the connection process. `opts` is the listener's `:handler_opts`."
  @callback start_link(Sovite.Listener.connection_info(), opts :: term()) ::
              GenServer.on_start()

  @doc """
  Called in the acceptor when a connection is refused because of a limit,
  before the socket is closed. Use it to send a protocol-level refusal,
  such as SMTP `421`. It must not block for long.
  """
  @callback reject(:gen_tcp.socket(), Sovite.Listener.reject_reason(), opts :: term()) :: any()

  @optional_callbacks reject: 3
end
