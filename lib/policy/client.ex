defmodule Sovite.Policy.Client do
  @moduledoc """
  Asks a policy server what to do, over TCP, a Unix socket, or the
  standard input and output of a program.

      {:ok, conn} = Client.connect({:inet, "127.0.0.1", 10023})

      {:ok, "DEFER_IF_PERMIT Greylisted", conn} =
        Client.request(conn, protocol_state: "RCPT", client_address: {192, 0, 2, 7}, ...)

      :ok = Client.close(conn)

  `check/3` connects, asks once, and closes. A connection can carry any
  number of requests, one after the other: keep it to save the connection
  setup, as Postfix does. Only the process that opened a connection may
  use it.

  The reply's `action` is returned as text: parse it with
  `Sovite.Policy.parse_action/1`. Other attributes of the reply are
  ignored. Requests are encoded with `Sovite.Policy.encode_request/1`.

  ## Addresses

    * `{:inet, host, port}` - TCP. `host` is a name, an IP address string,
      or an IP address tuple.
    * `{:unix, path}` - a Unix socket.
    * `{:command, [program | args]}` - a program, started for each
      connection with the protocol on its standard input and output, as
      Postfix's spawn(8) runs policyd-spf. It runs directly, never through
      a shell, with the environment of the VM; its standard error is not
      read. `program` is an absolute path or found in `PATH`. Closing the
      connection closes its standard input, which ends such programs.

  `parse_address/1` reads them from Postfix-style strings.

  ## Errors

  A failed request closes the connection; connect again for the next
  request. Reasons:

    * `:closed` - the server closed the connection or the program
      exited, maybe because it was idle for too long, or the connection
      was closed already. Reconnecting usually works.
    * `:timeout` - no complete reply in time.
    * `:response_too_large` - the reply is over `:max_response` bytes.
    * `:invalid_response` - the reply is malformed or has no `action`.

  `connect/2` returns `:timeout` or the socket error, such as
  `:econnrefused` or `:enoent`, and `:enoent` or `:eacces` when the
  program cannot be run.

  ## Options

  For `connect/2` and `check/3`; `request/3` takes `:timeout` and
  `:max_response`, overriding those given to `connect/2`.

    * `:timeout` - milliseconds for each request, to send it and get the
      whole reply. Defaults to 100 seconds, like Postfix's
      `smtpd_policy_service_timeout`.
    * `:connect_timeout` - milliseconds. Defaults to 10 seconds.
    * `:max_response` - bytes of a reply. Defaults to 4096.

  ## Telemetry

    * `[:sovite, :policy, :client, :request, :stop]` - `%{duration}`,
      `%{address, action}`, for each reply. `action` is the text.
    * `[:sovite, :policy, :client, :error]` - `%{duration}`, `%{address,
      reason}`, when connecting or a request fails. `reason` is an error
      above.
  """

  alias Sovite.Policy
  alias Sovite.Policy.Codec

  @defaults [timeout: 100_000, connect_timeout: 10_000, max_response: 4096]

  @enforce_keys [:address, :io, :timeout, :max_response]
  defstruct [:address, :io, :timeout, :max_response, reader: Codec.new()]

  @opaque t :: %__MODULE__{}

  @typedoc "Where the policy server is, see the module docs."
  @type address ::
          {:inet, host :: String.t() | :inet.ip_address(), :inet.port_number()}
          | {:unix, Path.t()}
          | {:command, [String.t(), ...]}

  @typedoc "Why a request failed, see the module docs."
  @type error :: :closed | :timeout | :response_too_large | :invalid_response

  @doc """
  Parses an address string:

    * `inet:host:port`, or `inet:[ipv6]:port` for an IPv6 address
    * `unix:path`
    * `spawn:program args...` - the program and its arguments, split on
      whitespace (not a Postfix syntax)

  ## Examples

      iex> Sovite.Policy.Client.parse_address("inet:127.0.0.1:10023")
      {:ok, {:inet, "127.0.0.1", 10023}}

      iex> Sovite.Policy.Client.parse_address("inet:[::1]:9998")
      {:ok, {:inet, "::1", 9998}}

      iex> Sovite.Policy.Client.parse_address("spawn:/usr/bin/policyd-spf /etc/spf.conf")
      {:ok, {:command, ["/usr/bin/policyd-spf", "/etc/spf.conf"]}}
  """
  @spec parse_address(String.t()) :: {:ok, address()} | {:error, :invalid_address}
  def parse_address("inet:" <> rest), do: parse_inet(rest)

  def parse_address("unix:" <> path) when path != "" do
    if String.contains?(path, <<0>>), do: {:error, :invalid_address}, else: {:ok, {:unix, path}}
  end

  def parse_address("spawn:" <> command) do
    case String.split(command) do
      [] -> {:error, :invalid_address}
      argv -> {:ok, {:command, argv}}
    end
  end

  def parse_address(_address), do: {:error, :invalid_address}

  defp parse_inet(rest) do
    {host, port} =
      case Regex.run(~r/\A\[([^\[\]]+)\]:(\d+)\z/, rest) do
        [_all, host, port] -> {host, port}
        nil -> split_host_port(rest)
      end

    with true <- host != "" and not String.match?(host, ~r/[\s\[\]\/\x00]/),
         {port, ""} when port in 1..65_535 <- Integer.parse(port) do
      {:ok, {:inet, host, port}}
    else
      _ -> {:error, :invalid_address}
    end
  end

  # The port follows the last colon; a bare IPv6 address is not allowed.
  defp split_host_port(rest) do
    case String.split(rest, ":") do
      [host, port] -> {host, port}
      _ -> {"", ""}
    end
  end

  @doc "Connects to a policy server. See the module docs for options."
  @spec connect(address(), keyword()) :: {:ok, t()} | {:error, term()}
  def connect(address, opts \\ []) do
    opts = Keyword.validate!(opts, @defaults)
    started = System.monotonic_time()

    case open(address, opts[:connect_timeout]) do
      {:ok, io} ->
        {:ok,
         %__MODULE__{
           address: address,
           io: io,
           timeout: opts[:timeout],
           max_response: opts[:max_response]
         }}

      {:error, reason} ->
        error(address, reason, started)
    end
  end

  defp open({:inet, host, port}, timeout) do
    {address, family} = inet_host(host)
    tcp_connect(address, port, [family, nodelay: true], timeout)
  end

  defp open({:unix, path}, timeout), do: tcp_connect({:local, path}, 0, [:local], timeout)

  defp open({:command, [program | args]}, _timeout) do
    with {:ok, executable} <- executable(program) do
      try do
        port =
          Port.open({:spawn_executable, executable}, [
            :binary,
            :exit_status,
            :use_stdio,
            :hide,
            args: args
          ])

        # A linked port that fails to write (EPIPE) would kill the
        # caller. Unlinked, it is monitored instead, and closed by a
        # watcher when the caller exits.
        Process.unlink(port)
        watch(port, self())
        {:ok, {:port, port, :erlang.monitor(:port, port)}}
      rescue
        error in ErlangError -> {:error, port_error(error.original)}
      end
    end
  end

  defp watch(port, owner) do
    spawn(fn ->
      owner_ref = Process.monitor(owner)
      port_ref = :erlang.monitor(:port, port)

      receive do
        {:DOWN, ^owner_ref, :process, _pid, _reason} -> close_port(port)
        {:DOWN, ^port_ref, :port, _port, _reason} -> :ok
      end
    end)
  end

  defp inet_host(host) when is_tuple(host), do: {host, family(host)}

  defp inet_host(host) when is_binary(host) do
    case :inet.parse_strict_address(String.to_charlist(host)) do
      {:ok, ip} -> {ip, family(ip)}
      {:error, _} -> {String.to_charlist(host), :inet}
    end
  end

  defp family(ip) when tuple_size(ip) == 8, do: :inet6
  defp family(_ip), do: :inet

  defp tcp_connect(address, port, family_opts, timeout) do
    opts = [:binary, active: false, packet: :raw, send_timeout_close: true] ++ family_opts

    case :gen_tcp.connect(address, port, opts, timeout) do
      {:ok, socket} -> {:ok, {:socket, socket}}
      {:error, _reason} = error -> error
    end
  end

  defp executable(program) do
    path =
      if Path.type(program) == :absolute, do: program, else: System.find_executable(program)

    with path when is_binary(path) <- path,
         {:ok, %File.Stat{type: :regular, mode: mode}} <- File.stat(path),
         true <- Bitwise.band(mode, 0o111) != 0 do
      {:ok, path}
    else
      nil -> {:error, :enoent}
      {:error, reason} -> {:error, reason}
      _not_executable -> {:error, :eacces}
    end
  end

  defp port_error(reason) when is_atom(reason), do: reason
  defp port_error(_reason), do: :eacces

  @doc """
  Sends a request and waits for the reply's action. See
  `Sovite.Policy.encode_request/1` for `attrs`, and the module docs for
  errors and options. After an error the connection is closed.
  """
  @spec request(t(), Policy.attributes(), keyword()) ::
          {:ok, action :: String.t(), t()} | {:error, error()}
  def request(%__MODULE__{} = conn, attrs, opts \\ []) do
    opts = Keyword.validate!(opts, timeout: conn.timeout, max_response: conn.max_response)
    started = System.monotonic_time()
    deadline = System.monotonic_time(:millisecond) + opts[:timeout]

    with :ok <- send_request(conn, Policy.encode_request(attrs), opts[:timeout]),
         {:ok, attrs, reader} <- receive_reply(conn, deadline, opts[:max_response]),
         {:ok, action} <- Map.fetch(attrs, "action") |> or_invalid() do
      :telemetry.execute(
        [:sovite, :policy, :client, :request, :stop],
        %{duration: System.monotonic_time() - started},
        %{address: conn.address, action: action}
      )

      {:ok, action, %{conn | reader: reader}}
    else
      {:error, reason} ->
        close(conn)
        error(conn.address, reason, started)
    end
  end

  defp or_invalid({:ok, _action} = ok), do: ok
  defp or_invalid(:error), do: {:error, :invalid_response}

  defp send_request(%{io: {:socket, socket}}, data, timeout) do
    with :ok <- :inet.setopts(socket, send_timeout: timeout),
         :ok <- :gen_tcp.send(socket, data) do
      :ok
    else
      {:error, :timeout} -> {:error, :timeout}
      {:error, _reason} -> {:error, :closed}
    end
  end

  defp send_request(%{io: {:port, port, _ref}}, data, _timeout) do
    Port.command(port, data)
    :ok
  rescue
    ArgumentError -> {:error, :closed}
  end

  defp receive_reply(conn, deadline, max_response) do
    limits = %{max_line: max_response, max_attributes: :infinity, max_size: max_response}

    case Codec.read(conn.reader, "", limits) do
      {:more, reader} -> receive_more(conn, reader, deadline, limits)
      other -> reply_result(other)
    end
  end

  defp receive_more(conn, reader, deadline, limits) do
    case recv(conn.io, max(deadline - System.monotonic_time(:millisecond), 0)) do
      {:ok, data} ->
        case Codec.read(reader, data, limits) do
          {:more, reader} -> receive_more(conn, reader, deadline, limits)
          other -> reply_result(other)
        end

      {:error, _reason} = error ->
        error
    end
  end

  defp reply_result({:ok, _attrs, _reader} = ok), do: ok
  defp reply_result({:error, :malformed}), do: {:error, :invalid_response}
  defp reply_result({:error, _too_large}), do: {:error, :response_too_large}

  defp recv({:socket, socket}, timeout) do
    case :gen_tcp.recv(socket, 0, timeout) do
      {:ok, data} -> {:ok, data}
      {:error, :timeout} -> {:error, :timeout}
      {:error, _reason} -> {:error, :closed}
    end
  end

  defp recv({:port, port, ref}, timeout) do
    receive do
      {^port, {:data, data}} -> {:ok, data}
      {^port, {:exit_status, _status}} -> {:error, :closed}
      {:DOWN, ^ref, :port, _port, _reason} -> {:error, :closed}
    after
      timeout -> {:error, :timeout}
    end
  end

  @doc "Closes the connection. Closing it again does nothing."
  @spec close(t()) :: :ok
  def close(%__MODULE__{io: {:socket, socket}}) do
    _ = :gen_tcp.close(socket)
    :ok
  end

  def close(%__MODULE__{io: {:port, port, ref}}) do
    Process.demonitor(ref, [:flush])
    close_port(port)
    flush(port)
  end

  defp close_port(port) do
    Port.close(port)
  rescue
    ArgumentError -> true
  end

  defp flush(port) do
    receive do
      {^port, _message} -> flush(port)
    after
      0 -> :ok
    end
  end

  @doc """
  Connects, sends one request, and closes. See `connect/2` and
  `request/3`.

      {:ok, action} = Client.check({:unix, "/run/postgrey.sock"}, attrs)
  """
  @spec check(address(), Policy.attributes(), keyword()) ::
          {:ok, action :: String.t()} | {:error, term()}
  def check(address, attrs, opts \\ []) do
    with {:ok, conn} <- connect(address, opts),
         {:ok, action, conn} <- request(conn, attrs) do
      close(conn)
      {:ok, action}
    end
  end

  defp error(address, reason, started) do
    :telemetry.execute(
      [:sovite, :policy, :client, :error],
      %{duration: System.monotonic_time() - started},
      %{address: address, reason: reason}
    )

    {:error, reason}
  end
end
