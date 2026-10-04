defmodule Sovite.Listener do
  @moduledoc """
  A TCP listener with an acceptor pool and connection limits.

  Each accepted connection is served by its own process, started from a
  `Sovite.Listener.Handler` module under the listener's connection
  supervisor. Connections over a limit are refused: the handler's
  optional `reject/3` callback can send a protocol-level refusal first.

      children = [
        {Sovite.Listener, port: 2525, handler: MyHandler, handler_opts: []}
      ]

  IPv4-mapped IPv6 peer addresses are reported as IPv4. IPv6 listeners
  are IPv6-only, so `0.0.0.0` and `::` can listen on the same port.

  ## Options

    * `:port` - TCP port, `0` for any free port. Required.
    * `:ip` - address to listen on. Defaults to `{0, 0, 0, 0}`.
    * `:handler` - a `Sovite.Listener.Handler` module. Required.
    * `:handler_opts` - passed to the handler. Defaults to `[]`.
    * `:id` - label in telemetry metadata and connection info. Defaults
      to `"<ip>:<port>"`.
    * `:name` - registered name of the listener supervisor.
    * `:acceptors` - number of acceptor processes. Defaults to 10.
    * `:max_connections` - concurrent connections. Defaults to 1000.
    * `:max_connections_per_ip` - concurrent connections from one remote
      address, or `nil` for no limit. Defaults to `nil`.

  ## Telemetry

    * `[:sovite, :listener, :connection, :start]` - `%{system_time}`,
      `%{listener, remote_ip, remote_port}`
    * `[:sovite, :listener, :connection, :stop]` - `%{duration}`, same metadata
    * `[:sovite, :listener, :connection, :rejected]` - `%{}`,
      `%{listener, remote_ip, reason}`
  """

  use Supervisor

  @typedoc "Why a connection was refused."
  @type reject_reason :: :max_connections | :max_connections_per_ip

  @typedoc "Passed to the handler's `start_link/2`."
  @type connection_info :: %{
          listener: String.t(),
          socket: :gen_tcp.socket(),
          remote_ip: :inet.ip_address(),
          remote_port: :inet.port_number(),
          local_ip: :inet.ip_address(),
          local_port: :inet.port_number()
        }

  @defaults [
    ip: {0, 0, 0, 0},
    handler_opts: [],
    id: nil,
    name: nil,
    acceptors: 10,
    max_connections: 1000,
    max_connections_per_ip: nil
  ]

  @doc false
  def child_spec(opts) do
    %{
      id:
        {__MODULE__,
         Keyword.get(opts, :id) || {Keyword.get(opts, :ip), Keyword.fetch!(opts, :port)}},
      start: {__MODULE__, :start_link, [opts]},
      type: :supervisor
    }
  end

  @doc "Starts the listener. See the module docs for options."
  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts) do
    opts = Keyword.validate!(opts, [:port, :handler] ++ @defaults)

    for key <- [:port, :handler],
        not Keyword.has_key?(opts, key),
        do: raise(ArgumentError, "missing required option #{inspect(key)}")

    case opts[:name] do
      nil -> Supervisor.start_link(__MODULE__, opts)
      name -> Supervisor.start_link(__MODULE__, opts, name: name)
    end
  end

  @doc """
  Waits until the listener has handed the socket in `info` over to the
  calling connection process. Call it before using the socket.
  """
  @spec handshake(connection_info(), timeout()) :: :ok | {:error, :timeout}
  def handshake(%{socket: socket}, timeout \\ 5_000) do
    receive do
      {:sovite_listener, :ready, ^socket} -> :ok
    after
      timeout -> {:error, :timeout}
    end
  end

  @doc "Returns the address and port the listener is bound to."
  @spec sockname(Supervisor.supervisor()) ::
          {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, term()}
  def sockname(listener), do: listener |> child(:server) |> GenServer.call(:sockname)

  @doc "Returns the number of open connections."
  @spec connection_count(Supervisor.supervisor()) :: non_neg_integer()
  def connection_count(listener),
    do:
      listener |> child(:connections) |> DynamicSupervisor.count_children() |> Map.fetch!(:active)

  defp child(listener, id) do
    listener
    |> Supervisor.which_children()
    |> Enum.find_value(fn {child_id, pid, _type, _modules} -> child_id == id && pid end)
  end

  @impl true
  def init(opts) do
    children = [
      %{
        id: :connections,
        start:
          {DynamicSupervisor, :start_link,
           [[strategy: :one_for_one, max_children: opts[:max_connections]]]},
        type: :supervisor
      },
      %{id: :server, start: {Sovite.Listener.Server, :start_link, [{self(), opts}]}}
    ]

    # The connection counts live in the server, so they restart together.
    Supervisor.init(children, strategy: :one_for_all)
  end
end
