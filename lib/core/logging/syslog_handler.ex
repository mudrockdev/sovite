defmodule Sovite.Core.Logging.SyslogHandler do
  @moduledoc """
  `:logger` handler that sends log lines to a syslog daemon: to a local
  socket such as `/dev/log` (journald, rsyslog, syslog-ng), or over UDP
  to a remote host.

  Messages use the classic BSD format (RFC 3164) by default:

      <22>Oct  4 12:00:00 sovite[812]: queue_id=4Xb2Kq event=queue.message.enqueued queue.message.enqueued: ...

  with the host name added for remote daemons, or RFC 5424:

      <22>1 2026-10-04T12:00:00.123456Z mx1 sovite 812 - - queue_id=4Xb2Kq ...

  The tag is `sovite`, the facility `mail` unless configured, and the
  severity follows the log level. The message is the line of the text
  formatter without its date and level, or a JSON object with
  `format: :json`. Messages over 8 KiB are cut.

  Sending never blocks: when the daemon is not running or cannot keep
  up, lines are dropped.

  Run it under a supervisor, like `Sovite.Core.Logging.FileHandler`:

      {Sovite.Core.Logging.SyslogHandler,
       id: :sovite_syslog,
       address: {:unix, "/dev/log"},
       facility: :mail,
       format: :rfc3164,
       formatter: Sovite.Core.Logging.formatter(:text)}

  ## Options

    * `:id` - the `:logger` handler ID. Required.
    * `:address` - `{:unix, path}` or `{:udp, host, port}`. Required.
    * `:formatter` - the `{module, config}` formatter of the message.
      Required.
    * `:facility` - `:mail`, `:daemon`, `:user`, or `:local0` to
      `:local7`. Defaults to `:mail`.
    * `:format` - `:rfc3164` or `:rfc5424`. Defaults to `:rfc3164`.
    * `:hostname` - for remote daemons and RFC 5424. Defaults to the
      system's host name.
    * `:replace` - ID of a handler that is silenced (level `:none`) while
      this one runs.
  """

  @behaviour :logger_handler

  use GenServer

  @facilities %{
    user: 1,
    mail: 2,
    daemon: 3,
    local0: 16,
    local1: 17,
    local2: 18,
    local3: 19,
    local4: 20,
    local5: 21,
    local6: 22,
    local7: 23
  }

  @severities %{
    emergency: 0,
    alert: 1,
    critical: 2,
    error: 3,
    warning: 4,
    notice: 5,
    info: 6,
    debug: 7
  }

  @max_message 8192
  @months ~w(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)

  @doc false
  def child_spec(opts),
    do: %{id: {__MODULE__, Keyword.fetch!(opts, :id)}, start: {__MODULE__, :start_link, [opts]}}

  @doc "Opens the socket and installs the `:logger` handler."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc """
  Encodes one syslog message. `time` is a UTC `DateTime`; `config` has
  the `:facility`, `:format`, `:hostname`, `:local` (no host name in RFC
  3164 messages to a local socket), `:pid`, and `:utc` (RFC 3164 times
  in UTC instead of local time) keys.
  """
  @spec encode(:logger.level(), DateTime.t(), iodata(), map()) :: binary()
  def encode(level, time, message, config) do
    pri = Map.fetch!(@facilities, config.facility) * 8 + Map.fetch!(@severities, level)
    message = message |> IO.iodata_to_binary() |> String.trim_trailing("\n")

    header =
      case config.format do
        :rfc3164 ->
          host = if config.local, do: "", else: config.hostname <> " "
          "<#{pri}>#{classic_time(time, config.utc)} #{host}sovite[#{config.pid}]: "

        :rfc5424 ->
          "<#{pri}>1 #{DateTime.to_iso8601(time)} #{config.hostname} sovite #{config.pid} - - "
      end

    binary_part_max(header <> message, @max_message)
  end

  # Classic syslog has no zone: like other programs, use local time.
  defp classic_time(time, false) do
    {{y, mo, d}, {h, mi, s}} = :calendar.universal_time_to_local_time(NaiveDateTime.to_erl(time))
    classic_time(%{time | year: y, month: mo, day: d, hour: h, minute: mi, second: s}, true)
  end

  defp classic_time(time, true) do
    month = Enum.at(@months, time.month - 1)
    day = time.day |> Integer.to_string() |> String.pad_leading(2)
    "#{month} #{day} #{Calendar.strftime(time, "%H:%M:%S")}"
  end

  # Cut at a character boundary.
  defp binary_part_max(data, max) when byte_size(data) <= max, do: data
  defp binary_part_max(data, max), do: String.slice(binary_part(data, 0, max), 0..-2//1)

  ## :logger handler callbacks, run in the logging process

  @impl :logger_handler
  def adding_handler(%{config: %{socket: _, destination: _}} = config), do: {:ok, config}
  def adding_handler(config), do: {:error, {:invalid_handler_config, config}}

  @impl :logger_handler
  def changing_config(_set_or_update, %{config: handler_config}, new_config),
    do: {:ok, Map.put(new_config, :config, handler_config)}

  @impl :logger_handler
  def log(%{level: level, meta: meta} = event, %{config: config, formatter: {module, fconfig}}) do
    time = DateTime.from_unix!(Map.get(meta, :time, :os.system_time(:microsecond)), :microsecond)
    message = module.format(event, fconfig)
    data = encode(level, time, message, config)

    # A timeout of 0: drop the line rather than wait for the daemon.
    _ = :socket.sendto(config.socket, data, config.destination, 0)
    :ok
  catch
    _kind, _reason -> :ok
  end

  ## Owner process

  @impl GenServer
  def init(opts) do
    Process.flag(:trap_exit, true)

    case open(Keyword.fetch!(opts, :address)) do
      {:ok, socket, destination, local} -> install(opts, socket, destination, local)
      {:error, reason} -> {:stop, {:syslog, reason}}
    end
  end

  defp install(opts, socket, destination, local) do
    id = Keyword.fetch!(opts, :id)

    config = %{
      socket: socket,
      destination: destination,
      local: local,
      facility: Keyword.get(opts, :facility, :mail),
      format: Keyword.get(opts, :format, :rfc3164),
      hostname: Keyword.get_lazy(opts, :hostname, &hostname/0),
      pid: System.pid(),
      utc: Application.get_env(:logger, :utc_log, false)
    }

    replace = Keyword.get(opts, :replace)

    replaced =
      case replace && :logger.get_handler_config(replace) do
        {:ok, replaced} -> replaced
        _ -> nil
      end

    handler = %{
      config: config,
      formatter: Keyword.fetch!(opts, :formatter),
      level: Keyword.get(opts, :level, :all),
      filters: if(replaced, do: replaced.filters, else: [])
    }

    :ok = :logger.add_handler(id, __MODULE__, handler)
    if replaced, do: :ok = :logger.update_handler_config(replace, :level, :none)

    {:ok, %{id: id, socket: socket, replace: replace, replaced_level: replaced && replaced.level}}
  end

  @impl GenServer
  def terminate(_reason, state) do
    _ = :logger.remove_handler(state.id)

    if state.replaced_level,
      do: :logger.update_handler_config(state.replace, :level, state.replaced_level)

    :socket.close(state.socket)
  end

  defp open({:unix, path}) do
    with {:ok, socket} <- :socket.open(:local, :dgram, :default),
         do: {:ok, socket, %{family: :local, path: path}, true}
  end

  defp open({:udp, host, port}) do
    with {:ok, ip} <- resolve(host),
         family = if(tuple_size(ip) == 8, do: :inet6, else: :inet),
         {:ok, socket} <- :socket.open(family, :dgram, :udp),
         do: {:ok, socket, %{family: family, addr: ip, port: port}, false}
  end

  defp resolve(host) when is_tuple(host), do: {:ok, host}

  defp resolve(host) do
    case :inet.getaddr(String.to_charlist(host), :inet) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> :inet.getaddr(String.to_charlist(host), :inet6)
    end
  end

  defp hostname do
    {:ok, name} = :inet.gethostname()
    List.to_string(name)
  end
end
