defmodule Sovite.Core.Config do
  @moduledoc """
  Loads, validates, and stores the Sovite configuration file.

  The file is TOML. Every key is checked against a schema: unknown keys,
  wrong types, and invalid values are all reported together, each with the
  path of the bad key. See `docs/configuration.md` for the reference.

  The running configuration is kept in `:persistent_term`. Read it with
  `get/0`.
  """

  alias Sovite.Core.Config.{Error, Schema}

  @default_path "/etc/sovite/sovite.toml"

  @schema [
    {:server, {:section, [{:hostname, :hostname, default: &__MODULE__.system_hostname/0}]}, []},
    {:queue,
     {:section,
      [
        {:directory, :absolute_path, default: "/var/spool/sovite"},
        {:max_lifetime, :duration, default: "5d"},
        {:min_backoff, :duration, default: "5m"},
        {:max_backoff, :duration, default: "1h"},
        {:delay_warning, :duration, []}
      ]}, []},
    {:listener,
     {:list,
      {:section,
       [
         {:address, :ip_address, default: "0.0.0.0"},
         {:port, {:integer, 0, 65_535}, default: 25}
       ]}}, default: [%{}]},
    {:smtp,
     {:section,
      [
        {:max_message_size, :byte_size, default: "25M"},
        {:max_recipients, {:integer, 1, 100_000}, default: 100},
        {:max_connections, {:integer, 1, 1_000_000}, default: 1000},
        {:max_connections_per_ip, {:integer, 1, 1_000_000}, default: 20},
        {:max_errors, {:integer, 1, 1000}, default: 10},
        {:command_timeout, :duration, default: "5m"},
        {:data_timeout, :duration, default: "5m"},
        {:bare_line_endings, {:enum, [:reject, :normalize]}, default: :reject},
        {:vrfy, :boolean, default: false},
        {:trusted_networks, {:list, :cidr}, default: []}
      ]}, []},
    {:domains,
     {:section,
      [
        {:local, {:list, :domain}, []},
        {:relay, {:list, :domain}, default: []},
        {:local_recipients, {:list, :mailbox}, []}
      ]}, []},
    {:delivery,
     {:section,
      [
        {:relayhost, :relayhost, []},
        {:max_deliveries, {:integer, 1, 100_000}, default: 100},
        {:destination_concurrency, {:integer, 1, 100_000}, default: 20},
        {:destination_rate_delay, :duration, []},
        {:max_recipients, {:integer, 1, 100_000}, default: 50},
        {:max_addresses, {:integer, 1, 100}, default: 5},
        {:ip_versions, {:list, {:enum, [:ipv6, :ipv4]}}, default: ["ipv6", "ipv4"]},
        {:connect_timeout, :duration, default: "30s"}
      ]}, []},
    {:bounce, {:section, [{:double_bounce_recipient, :mailbox, []}]}, []},
    {:log,
     {:section,
      [
        {:level, {:enum, [:debug, :info, :notice, :warning, :error]}, default: :info},
        {:format, {:enum, [:text, :json]}, default: :text},
        {:directory, :absolute_path, []},
        {:file_name, :file_name_pattern, default: "sovite.{date}.{n}.log"},
        {:date_format, :strftime, default: "%Y-%m-%d"},
        {:max_size, :byte_size, default: "100M"},
        {:rotation, {:enum, [:never, :hourly, :daily, :weekly, :monthly]}, default: :daily},
        {:max_files, {:integer, 0, 100_000}, default: 14},
        {:symlink, :file_name, []}
      ]}, []}
  ]

  defstruct [:server, :queue, :listener, :smtp, :domains, :delivery, :bounce, :log]

  @type t :: %__MODULE__{
          server: %{hostname: String.t()},
          queue: %{
            directory: Path.t(),
            max_lifetime: pos_integer(),
            min_backoff: pos_integer(),
            max_backoff: pos_integer(),
            delay_warning: pos_integer() | nil
          },
          listener: [%{address: :inet.ip_address(), port: :inet.port_number()}],
          smtp: %{
            max_message_size: pos_integer(),
            max_recipients: pos_integer(),
            max_connections: pos_integer(),
            max_connections_per_ip: pos_integer(),
            max_errors: pos_integer(),
            command_timeout: pos_integer(),
            data_timeout: pos_integer(),
            bare_line_endings: :reject | :normalize,
            vrfy: boolean(),
            trusted_networks: [Sovite.Net.network()]
          },
          domains: %{
            local: [String.t()],
            relay: [String.t()],
            local_recipients: [String.t()] | nil
          },
          delivery: %{
            relayhost: %{host: String.t(), port: :inet.port_number(), mx: boolean()} | nil,
            max_deliveries: pos_integer(),
            destination_concurrency: pos_integer(),
            destination_rate_delay: pos_integer() | nil,
            max_recipients: pos_integer(),
            max_addresses: pos_integer(),
            ip_versions: [:ipv6 | :ipv4, ...],
            connect_timeout: pos_integer()
          },
          bounce: %{double_bounce_recipient: String.t() | nil},
          log: Sovite.Core.Logging.config()
        }

  @doc """
  Returns the config file path: `$SOVITE_CONFIG` if set, otherwise
  `#{@default_path}`.
  """
  @spec default_path() :: Path.t()
  def default_path, do: System.get_env("SOVITE_CONFIG") || @default_path

  @doc "Reads, parses, and validates the config file at `path`."
  @spec load(Path.t()) :: {:ok, t()} | {:error, [Error.t()]}
  def load(path) do
    case File.read(path) do
      {:ok, contents} ->
        parse(contents)

      {:error, reason} ->
        {:error, [%Error{reason: "cannot read #{path}: #{:file.format_error(reason)}"}]}
    end
  end

  @doc "Parses and validates TOML config `contents`."
  @spec parse(String.t()) :: {:ok, t()} | {:error, [Error.t()]}
  def parse(contents) do
    case Toml.decode(contents) do
      {:ok, map} ->
        validate(map)

      {:error, {:invalid_toml, reason}} ->
        {:error, [%Error{reason: "invalid TOML: " <> String.trim(reason)}]}

      {:error, reason} ->
        {:error, [%Error{reason: "invalid TOML: #{inspect(reason)}"}]}
    end
  end

  @doc """
  Validates a decoded config map (string keys, as produced by a TOML
  decoder), fills in defaults, and returns the config struct.
  """
  @spec validate(map()) :: {:ok, t()} | {:error, [Error.t()]}
  def validate(map) do
    with {:ok, values} <- Schema.validate(map, @schema),
         :ok <- check(values) do
      # Like Postfix's mydestination, the server is its own final
      # destination unless told otherwise.
      values =
        update_in(values.domains.local, fn
          nil -> [String.downcase(values.server.hostname, :ascii)]
          local -> local
        end)

      {:ok, struct!(__MODULE__, values)}
    end
  end

  # Rules that involve more than one key.
  defp check(values) do
    errors =
      [
        values.queue.min_backoff > values.queue.max_backoff &&
          %Error{
            path: ["queue", "max_backoff"],
            reason: "must not be less than queue.min_backoff"
          },
        values.delivery.ip_versions == [] &&
          %Error{path: ["delivery", "ip_versions"], reason: "must not be empty"},
        Enum.uniq(values.delivery.ip_versions) != values.delivery.ip_versions &&
          %Error{path: ["delivery", "ip_versions"], reason: "must not repeat a version"}
      ]
      |> Enum.filter(& &1)

    if errors == [], do: :ok, else: {:error, errors}
  end

  @doc "Stores `config` as the running configuration."
  @spec put(t()) :: :ok
  def put(%__MODULE__{} = config), do: :persistent_term.put(__MODULE__, config)

  @doc "Returns the running configuration. Raises if none has been stored."
  @spec get() :: t()
  def get, do: :persistent_term.get(__MODULE__)

  @doc false
  # Default for server.hostname. Not always an FQDN, so production configs
  # should set the hostname explicitly.
  def system_hostname, do: :net_adm.localhost() |> List.to_string() |> String.downcase()
end
