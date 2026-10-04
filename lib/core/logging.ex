defmodule Sovite.Core.Logging do
  @moduledoc """
  Configures the VM's default `:logger` handler from the `[log]` config
  section.

  Every log line about a message carries its queue ID in the `:queue_id`
  metadata key, so one message's lifecycle can be followed with grep.
  `metadata_keys/0` lists the standard keys. See `docs/logging.md`.
  """

  alias Sovite.Core.Logging.JSONFormatter

  @metadata_keys [:queue_id, :session_id, :remote_ip, :event]

  @doc "Metadata keys included in every log format."
  @spec metadata_keys() :: [atom()]
  def metadata_keys, do: @metadata_keys

  @doc "Applies the log level and format to the default handler."
  @spec configure(%{level: Logger.level(), format: :text | :json}) :: :ok
  def configure(%{level: level, format: format}) do
    Logger.configure(level: level)

    # The default handler can be missing if the host app removed it.
    _ = :logger.update_handler_config(:default, :formatter, formatter(format))
    :ok
  end

  @doc "Returns the `:logger` formatter for `format`."
  @spec formatter(:text | :json) :: {module(), term()}
  def formatter(:text),
    do:
      Logger.Formatter.new(
        format: "$date $time [$level] $metadata$message\n",
        metadata: @metadata_keys
      )

  def formatter(:json), do: {JSONFormatter, %{metadata: @metadata_keys}}
end
