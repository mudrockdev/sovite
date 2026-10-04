import Config

# Boot-time log format. Once the MTA loads its config file,
# Sovite.Core.Logging applies the [log] section on top of this.
config :logger, :default_formatter,
  format: "$date $time [$level] $metadata$message\n",
  metadata: [:queue_id, :session_id, :remote_ip, :event]
