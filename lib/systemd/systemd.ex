defmodule Sovite.Systemd do
  @moduledoc """
  The systemd service manager protocol, without libsystemd: readiness and
  status notifications (sd_notify(3)), the watchdog (sd_watchdog_enabled(3),
  see `Sovite.Systemd.Watchdog`), and socket activation (sd_listen_fds(3)).

      :ok = Sovite.Systemd.ready(status: "Accepting mail")

  Everything is read from the environment systemd sets for the service.
  Outside systemd these variables are missing, and every function is a
  no-op: notifications return `{:error, :no_socket}`, `listen_fds/1`
  returns `[]`, and `watchdog_interval/1` returns `:disabled`. Callers can
  ignore the results.

  Notifications are only accepted from the service's main process unless
  the unit sets `NotifyAccess=all`, so the BEAM must be the process
  systemd started (a release's start script `exec`s it, which is enough).

  ## Options

  Every function takes:

    * `:env` - a map of environment variables to read instead of the OS
      environment, for tests. Defaults to reading `System.get_env/1`.
  """

  @typedoc """
  A notification: a string such as `"READY=1"`, or a list of `{key,
  value}` pairs, sent as `KEY=value` lines. Atom keys are upcased, so
  `[ready: 1, status: "Started"]` sends `"READY=1\\nSTATUS=Started\\n"`.
  Newlines in values are replaced by spaces.
  """
  @type state :: String.t() | [{atom() | String.t(), String.Chars.t()}]

  @typedoc """
  Why a notification was not sent: `:no_socket` outside systemd,
  `:invalid_socket` for a `NOTIFY_SOCKET` that is not an absolute path or
  an abstract `@name`, `:unsupported` for a VSOCK address, or a
  `:socket` error.
  """
  @type notify_error :: :no_socket | :invalid_socket | :unsupported | term()

  @fd_start 3
  @send_timeout 5_000

  @doc """
  Sends a notification to the service manager, through the unix datagram
  socket in `NOTIFY_SOCKET`. A socket name starting with `@` is in the
  abstract namespace.

  Returns `:ok` once the datagram is sent, or `{:error, reason}` (see
  `t:notify_error/0`). It never raises.
  """
  @spec notify(state(), keyword()) :: :ok | {:error, notify_error()}
  def notify(state, opts \\ []) do
    with {:ok, path} <- socket_path(getenv(opts, "NOTIFY_SOCKET")) do
      send_datagram(path, encode(state))
    end
  end

  @doc """
  Sends `READY=1`: the service has started. Takes the `:status` option, a
  text sent with it (see `status/2`).
  """
  @spec ready(keyword()) :: :ok | {:error, notify_error()}
  def ready(opts \\ []), do: notify_with_status([{"READY", 1}], opts)

  @doc """
  Sends `RELOADING=1`: the service is reloading its configuration. Send
  `ready/1` when done. Takes the `:status` option, as `ready/1`.

  `MONOTONIC_USEC` is sent with it when `monotonic_usec/0` can read the
  clock, as `Type=notify-reload` units need. Where it cannot, use
  `Type=notify`.
  """
  @spec reloading(keyword()) :: :ok | {:error, notify_error()}
  def reloading(opts \\ []) do
    monotonic =
      case monotonic_usec() do
        {:ok, usec} -> [{"MONOTONIC_USEC", usec}]
        :error -> []
      end

    notify_with_status([{"RELOADING", 1} | monotonic], opts)
  end

  @doc """
  Sends `STOPPING=1`: the service is shutting down. Takes the `:status`
  option, as `ready/1`.
  """
  @spec stopping(keyword()) :: :ok | {:error, notify_error()}
  def stopping(opts \\ []), do: notify_with_status([{"STOPPING", 1}], opts)

  @doc """
  Sends `STATUS=text`, shown by `systemctl status`. Newlines in `text`
  are replaced by spaces.
  """
  @spec status(String.t(), keyword()) :: :ok | {:error, notify_error()}
  def status(text, opts \\ []), do: notify([{"STATUS", text}], opts)

  @doc """
  Sends `WATCHDOG=1`, the watchdog keep-alive ping. See
  `Sovite.Systemd.Watchdog` to send it on a schedule.
  """
  @spec watchdog(keyword()) :: :ok | {:error, notify_error()}
  def watchdog(opts \\ []), do: notify("WATCHDOG=1", opts)

  @doc """
  Sends `EXTEND_TIMEOUT_USEC=usec`: the start, reload, or stop in progress
  needs `usec` more microseconds.
  """
  @spec extend_timeout(non_neg_integer(), keyword()) :: :ok | {:error, notify_error()}
  def extend_timeout(usec, opts \\ []) when is_integer(usec) and usec >= 0,
    do: notify([{"EXTEND_TIMEOUT_USEC", usec}], opts)

  @doc "Returns whether `NOTIFY_SOCKET` is set, so notifications can be sent."
  @spec notify_socket?(keyword()) :: boolean()
  def notify_socket?(opts \\ []), do: getenv(opts, "NOTIFY_SOCKET") not in [nil, ""]

  @doc """
  Returns the current time of `CLOCK_MONOTONIC` in microseconds, the clock
  of `MONOTONIC_USEC`, or `:error` when the runtime does not read that
  clock.

  Erlang's own monotonic time has an arbitrary offset, and its rate can be
  corrected, so this reads the runtime's OS monotonic time source instead,
  when it is `clock_gettime(CLOCK_MONOTONIC)` (as on Linux).
  """
  @spec monotonic_usec() :: {:ok, non_neg_integer()} | :error
  def monotonic_usec do
    source = :erlang.system_info(:os_monotonic_time_source)

    with {:function, :clock_gettime} <- List.keyfind(source, :function, 0),
         {:clock_id, :CLOCK_MONOTONIC} <- List.keyfind(source, :clock_id, 0),
         {:time, time} when is_integer(time) <- List.keyfind(source, :time, 0) do
      {:ok, :erlang.convert_time_unit(time, :native, :microsecond)}
    else
      _ -> :error
    end
  end

  @doc """
  Returns the watchdog interval in milliseconds, from `WATCHDOG_USEC`, or
  `:disabled`. The watchdog is disabled when `WATCHDOG_USEC` is not a
  positive integer, or when `WATCHDOG_PID` is set to another process.

  The service must send `watchdog/1` within every interval; sending it
  every half interval is the usual choice.
  """
  @spec watchdog_interval(keyword()) :: {:ok, pos_integer()} | :disabled
  def watchdog_interval(opts \\ []) do
    with true <- for_this_process?(getenv(opts, "WATCHDOG_PID"), true),
         {:ok, usec} when usec > 0 <- parse_integer(getenv(opts, "WATCHDOG_USEC")) do
      {:ok, max(div(usec, 1000), 1)}
    else
      _ -> :disabled
    end
  end

  @doc """
  Returns the sockets systemd passed for socket activation, as `{name,
  fd}` pairs in order, or `[]` when there are none or they are meant for
  another process (`LISTEN_PID`).

  Names come from `FileDescriptorName=` in the socket units
  (`LISTEN_FDNAMES`). When they are missing, or their number does not
  match, every name is `"unknown"`.

  Turn a listening TCP socket into a `:gen_tcp` socket with
  `listen_socket/2`.

  ## Options

    * `:env` - as in the module docs.
    * `:unset` - remove `LISTEN_PID`, `LISTEN_FDS`, and `LISTEN_FDNAMES`
      from the OS environment, so processes started later do not see
      them. Ignored with `:env`. Defaults to `false`.
  """
  @spec listen_fds(keyword()) :: [{String.t(), non_neg_integer()}]
  def listen_fds(opts \\ []) do
    fds =
      with true <- for_this_process?(getenv(opts, "LISTEN_PID"), false),
           {:ok, count} when count >= 0 <- parse_integer(getenv(opts, "LISTEN_FDS")) do
        Enum.zip(names(getenv(opts, "LISTEN_FDNAMES"), count), fd_range(count))
      else
        _ -> []
      end

    if Keyword.get(opts, :unset, false) and not Keyword.has_key?(opts, :env) do
      Enum.each(["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"], &System.delete_env/1)
    end

    fds
  end

  @doc """
  Opens a `:gen_tcp` listen socket on `fd`, an inherited listening socket
  (from `listen_fds/1`). `opts` are `:gen_tcp.listen/2` options, such as
  `:binary` and `active: false`. The socket is already bound, so leave
  out `:ip` and `:port`.

  `:gen_tcp` must be told the socket's family. Without `:inet`, `:inet6`,
  or `:local` in `opts`, each is tried in turn, since opening a socket as
  the wrong family fails without closing it.
  """
  @spec listen_socket(non_neg_integer(), [:gen_tcp.listen_option()]) ::
          {:ok, :gen_tcp.socket()} | {:error, term()}
  def listen_socket(fd, opts \\ []) when is_integer(fd) and fd >= 0 do
    if Enum.any?(opts, &(&1 in [:inet, :inet6, :local] or match?({:tcp_module, _}, &1))) do
      :gen_tcp.listen(0, [{:fd, fd} | opts])
    else
      listen_any_family(fd, [:inet, :inet6, :local], opts)
    end
  end

  @doc """
  The address an inherited socket is bound to, as `{ip, port}` for a TCP
  or UDP socket, or `{:local, path}`. The socket is not changed: this
  looks at a duplicate of `fd`. Returns `:error` for a closed fd or
  another kind of socket.
  """
  @spec socket_address(non_neg_integer()) ::
          {:ok, {:inet.ip_address(), :inet.port_number()} | {:local, binary()}} | :error
  def socket_address(fd) when is_integer(fd) and fd >= 0 do
    case :socket.open(fd, %{dup: true}) do
      {:ok, socket} ->
        try do
          socket |> :socket.sockname() |> bound_address()
        after
          :socket.close(socket)
        end

      {:error, _reason} ->
        :error
    end
  catch
    _kind, _reason -> :error
  end

  defp bound_address({:ok, %{family: family, addr: ip, port: port}})
       when family in [:inet, :inet6],
       do: {:ok, {ip, port}}

  defp bound_address({:ok, %{family: :local, path: path}}), do: {:ok, {:local, path}}
  defp bound_address(_result), do: :error

  defp listen_any_family(fd, [family | rest], opts) do
    case :gen_tcp.listen(0, [{:fd, fd}, family | opts]) do
      {:error, :einval} when rest != [] -> listen_any_family(fd, rest, opts)
      result -> result
    end
  end

  defp getenv(opts, name) do
    case Keyword.fetch(opts, :env) do
      {:ok, env} -> Map.get(env, name)
      :error -> System.get_env(name)
    end
  end

  # An unset WATCHDOG_PID means the watchdog is for us; an unset
  # LISTEN_PID means the sockets are not.
  defp for_this_process?(nil, unset), do: unset

  defp for_this_process?(value, _unset),
    do: parse_integer(value) == {:ok, String.to_integer(System.pid())}

  defp parse_integer(nil), do: :error

  defp parse_integer(value) do
    case Integer.parse(value) do
      {integer, ""} -> {:ok, integer}
      _ -> :error
    end
  end

  defp names(nil, count), do: List.duplicate("unknown", count)

  defp names(value, count) do
    case String.split(value, ":") do
      names when length(names) == count -> names
      _ -> List.duplicate("unknown", count)
    end
  end

  defp fd_range(0), do: []
  defp fd_range(count), do: Enum.to_list(@fd_start..(@fd_start + count - 1))

  defp notify_with_status(fields, opts) do
    {status, opts} = Keyword.pop(opts, :status)
    fields = if status, do: fields ++ [{"STATUS", status}], else: fields
    notify(fields, opts)
  end

  defp socket_path(nil), do: {:error, :no_socket}
  defp socket_path(""), do: {:error, :no_socket}
  defp socket_path("/" <> _ = path), do: {:ok, path}
  defp socket_path("@" <> name), do: {:ok, <<0, name::binary>>}
  defp socket_path("vsock" <> _), do: {:error, :unsupported}
  defp socket_path(_other), do: {:error, :invalid_socket}

  defp encode(state) when is_binary(state), do: state

  defp encode(fields) when is_list(fields) do
    for {key, value} <- fields, into: "" do
      key = if is_atom(key), do: key |> Atom.to_string() |> String.upcase(), else: key
      value = value |> to_string() |> String.replace(["\r\n", "\n", "\r"], " ")
      key <> "=" <> value <> "\n"
    end
  end

  defp send_datagram(path, data) do
    with {:ok, socket} <- :socket.open(:local, :dgram, :default) do
      try do
        sendto(socket, path, data)
      after
        :socket.close(socket)
      end
    end
  end

  # The timeout keeps a full receive queue from blocking the caller for
  # good. Anything :socket raises becomes an error too: a notification
  # must never take the caller down.
  defp sendto(socket, path, data) do
    case :socket.sendto(socket, data, %{family: :local, path: path}, @send_timeout) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
      # A datagram is sent whole or not at all.
      {:ok, _rest} -> {:error, :partial}
    end
  catch
    kind, reason -> {:error, {kind, reason}}
  end
end
