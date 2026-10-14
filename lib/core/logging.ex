defmodule Sovite.Core.Logging do
  @moduledoc """
  Configures logging from the `[log]` config section.

  Logs go to standard output through the VM's default `:logger` handler,
  or, when `directory` is set, to rotating files written by
  `Sovite.Core.Logging.FileHandler`. With `syslog`, they also go to the
  syslog daemon (`Sovite.Core.Logging.SyslogHandler`), instead of to
  standard output.

  Every log line about a message carries its queue ID in the `:queue_id`
  metadata key, so one message's lifecycle can be followed with grep.
  `metadata_keys/0` lists the standard keys. See `docs/logging.md`.
  """

  alias Sovite.Core.Logging.{FileHandler, JSONFormatter, SyslogHandler}

  @metadata_keys [:queue_id, :session_id, :remote_ip, :event]

  @type config :: %{
          level: :debug | :info | :notice | :warning | :error,
          format: :text | :json,
          directory: Path.t() | nil,
          file_name: String.t(),
          date_format: String.t(),
          max_size: pos_integer(),
          rotation: FileHandler.rotation(),
          max_files: non_neg_integer(),
          symlink: String.t() | nil,
          syslog: boolean(),
          syslog_address: {:unix, Path.t()} | {:udp, String.t() | :inet.ip_address(), 1..65_535},
          syslog_facility: atom(),
          syslog_format: :rfc3164 | :rfc5424
        }

  @doc """
  Formats an IP address for the `:remote_ip` metadata key. The text
  formatter skips tuples, so addresses are logged as strings.
  """
  @spec format_ip(:inet.ip_address() | nil) :: String.t() | nil
  def format_ip(nil), do: nil
  def format_ip(ip), do: ip |> :inet.ntoa() |> List.to_string()

  @doc "Metadata keys included in every log format."
  @spec metadata_keys() :: [atom()]
  def metadata_keys, do: @metadata_keys

  @doc "Applies the log level and format to the default handler."
  @spec configure(config()) :: :ok
  def configure(%{level: level, format: format}) do
    Logger.configure(level: level)

    # The default handler can be missing if the host app removed it.
    _ = :logger.update_handler_config(:default, :formatter, formatter(format))
    :ok
  end

  @doc """
  Returns the child specs that write logs to files and to syslog, or
  `[]` when logging to standard output only.

  These handlers silence the default handler while they run, so lines
  are not written twice.
  """
  @spec child_specs(config()) :: [Supervisor.module_spec()]
  def child_specs(log), do: file_specs(log) ++ syslog_specs(log)

  defp file_specs(%{directory: nil}), do: []

  defp file_specs(log) do
    [
      {FileHandler,
       id: :sovite_file,
       formatter: formatter(log.format, colors: [enabled: false]),
       replace: :default,
       config: Map.take(log, FileHandler.config_keys())}
    ]
  end

  defp syslog_specs(%{syslog: true} = log) do
    # Syslog adds the time and severity itself.
    formatter =
      case log.format do
        :text ->
          Logger.Formatter.new(
            format: "$metadata$message\n",
            metadata: @metadata_keys,
            colors: [enabled: false]
          )

        :json ->
          formatter(:json)
      end

    [
      {SyslogHandler,
       id: :sovite_syslog,
       address: log.syslog_address,
       facility: log.syslog_facility,
       format: log.syslog_format,
       formatter: formatter,
       replace: if(log.directory == nil, do: :default)}
    ]
  end

  defp syslog_specs(_log), do: []

  @doc """
  Returns the `:logger` formatter for `format`.

  For `:text`, `opts` are passed to `Logger.Formatter.new/1`.
  """
  @spec formatter(:text | :json, keyword()) :: {module(), term()}
  def formatter(format, opts \\ [])

  def formatter(:text, opts),
    do:
      Logger.Formatter.new(
        [format: "$date $time [$level] $metadata$message\n", metadata: @metadata_keys] ++ opts
      )

  def formatter(:json, _opts), do: {JSONFormatter, %{metadata: @metadata_keys}}
end
