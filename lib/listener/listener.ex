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

  ## PROXY protocol

  Behind HAProxy or a load balancer, the listener can read a PROXY
  protocol header (version 1 or 2, see `Sovite.ProxyProtocol`) from each
  connection to learn the real client. It is read in the connection
  process, by `handshake/2`, so slow clients cannot hold up accepting.
  With a `PROXY` command over TCP, the connection info's `remote_*` and
  `local_*` addresses are the header's source and destination; `peer_ip`
  and `peer_port` are always the proxy's end of the connection. A `LOCAL`
  command (a health check) or an unknown family keeps the peer's
  addresses. A missing or invalid header, or one that does not arrive in
  time, closes the connection.

  Connection limits, including `:max_connections_per_ip`, and the
  `:connection` telemetry events see the peer: the proxy's address, not
  the client's, since they apply before the header is read.

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
    * `:proxy_protocol` - expect a PROXY protocol header. Defaults to
      `false`.
    * `:proxy_networks` - with `:proxy_protocol`, the `Sovite.Net`
      networks of the proxies. Connections from them must start with a
      header; others are served as direct clients, with no header read.
      `nil`, the default, means every connection must start with one.
    * `:proxy_timeout` - milliseconds to wait for the header. Defaults
      to 10 seconds.

  ## Telemetry

    * `[:sovite, :listener, :connection, :start]` - `%{system_time}`,
      `%{listener, remote_ip, remote_port}`
    * `[:sovite, :listener, :connection, :stop]` - `%{duration}`, same metadata
    * `[:sovite, :listener, :connection, :rejected]` - `%{}`,
      `%{listener, remote_ip, reason}`
    * `[:sovite, :listener, :proxy, :error]` - `%{}`,
      `%{listener, remote_ip, reason}`: no valid PROXY header, so the
      connection is closed. `remote_ip` is the peer's address and
      `reason` a `Sovite.ProxyProtocol.read/3` error.
  """

  use Supervisor

  alias Sovite.Net
  alias Sovite.ProxyProtocol
  alias Sovite.ProxyProtocol.Header

  @typedoc "Why a connection was refused."
  @type reject_reason :: :max_connections | :max_connections_per_ip

  @typedoc """
  Passed to the handler's `start_link/2`, and returned updated by
  `handshake/2`:

    * `:remote_ip`, `:remote_port` - the client. With the PROXY protocol,
      the header's source once `handshake/2` returns.
    * `:local_ip`, `:local_port` - the server address the client
      connected to. With the PROXY protocol, the header's destination.
    * `:peer_ip`, `:peer_port` - the other end of the TCP connection:
      the client, or the proxy.
    * `:proxy` - the PROXY protocol header, or `nil` when none was read.
  """
  @type connection_info :: %{
          listener: String.t(),
          socket: :gen_tcp.socket(),
          remote_ip: :inet.ip_address(),
          remote_port: :inet.port_number(),
          local_ip: :inet.ip_address(),
          local_port: :inet.port_number(),
          peer_ip: :inet.ip_address(),
          peer_port: :inet.port_number(),
          proxy: Header.t() | nil
        }

  @defaults [
    ip: {0, 0, 0, 0},
    handler_opts: [],
    id: nil,
    name: nil,
    acceptors: 10,
    max_connections: 1000,
    max_connections_per_ip: nil,
    proxy_protocol: false,
    proxy_networks: nil,
    proxy_timeout: 10_000
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
  calling connection process, then reads the PROXY protocol header if
  the connection must send one. Call it before using the socket, and use
  the connection info it returns.

  `timeout` is for the handover; the header has the listener's
  `:proxy_timeout`. Returns `{:error, :timeout}` without a handover, or
  `{:error, {:proxy, reason}}` without a valid header, after closing the
  socket (see `Sovite.ProxyProtocol.read/3` for the reasons).
  """
  @spec handshake(connection_info(), timeout()) ::
          {:ok, connection_info()} | {:error, :timeout | {:proxy, term()}}
  def handshake(%{socket: socket} = info, timeout \\ 5_000) do
    receive do
      {:sovite_listener, :ready, ^socket, nil} -> {:ok, info}
      {:sovite_listener, :ready, ^socket, proxy_timeout} -> read_proxy(info, proxy_timeout)
    after
      timeout -> {:error, :timeout}
    end
  end

  defp read_proxy(info, timeout) do
    case ProxyProtocol.read(info.socket, timeout) do
      {:ok, header} ->
        {:ok, Map.merge(info, Map.put(proxied_addresses(header), :proxy, header))}

      {:error, reason} ->
        :telemetry.execute(
          [:sovite, :listener, :proxy, :error],
          %{},
          %{listener: info.listener, remote_ip: info.peer_ip, reason: reason}
        )

        :gen_tcp.close(info.socket)
        {:error, {:proxy, reason}}
    end
  end

  defp proxied_addresses(%Header{
         command: :proxy,
         transport: transport,
         source: {source_ip, source_port},
         destination: {destination_ip, destination_port}
       })
       when transport in [:tcp4, :tcp6] do
    %{
      remote_ip: Net.normalize(source_ip),
      remote_port: source_port,
      local_ip: Net.normalize(destination_ip),
      local_port: destination_port
    }
  end

  # LOCAL (health checks), UNKNOWN, and other transports.
  defp proxied_addresses(_header), do: %{}

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
