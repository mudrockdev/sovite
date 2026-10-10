defmodule Sovite.Core.Config do
  @moduledoc """
  Loads, validates, and stores the Sovite configuration file.

  The file is TOML. Every key is checked against a schema: unknown keys,
  wrong types, and invalid values are all reported together, each with the
  path of the bad key. See `docs/configuration.md` for the reference.

  The running configuration is kept in `:persistent_term`. Read it with
  `get/0`.
  """

  alias Sovite.Core.Config.{AuthRules, Error, RoutingRules, Schema, TransportRules}
  alias Sovite.Core.{Repo, Restrictions}

  @default_path "/etc/sovite/sovite.toml"

  @tls_levels [:none, :may, :encrypt, :verify, :dane]

  @schema [
    {:server,
     {:section,
      [
        {:hostname, :hostname, default: &__MODULE__.system_hostname/0},
        {:authserv_id, :hostname, []}
      ]}, []},
    {:database,
     {:section,
      [
        {:adapter, {:enum, [:sqlite, :postgres, :mysql]}, default: :sqlite},
        {:path, :absolute_path, default: "/var/lib/sovite/sovite.db"},
        {:url, {:url, ["postgres", "postgresql", "ecto", "mysql"]}, []},
        {:pool_size, {:integer, 1, 1000}, default: 5},
        {:ssl, :boolean, default: false}
      ]}, []},
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
         {:port, {:integer, 0, 65_535}, []},
         {:mode, {:enum, [:smtp, :submission, :submissions, :lmtp]}, default: :smtp},
         {:auth, :boolean, []},
         {:require_tls, :boolean, []},
         {:require_auth, :boolean, []},
         {:tls_min_version, :tls_version, []},
         {:tls_ciphers, :ciphers, []}
       ]}}, default: [%{}]},
    {:tls,
     {:section,
      [
        {:certificate,
         {:list,
          {:section,
           [
             {:cert_file, :absolute_path, required: true},
             {:key_file, :absolute_path, required: true}
           ]}}, default: []},
        {:min_version, :tls_version, default: "1.2"},
        {:ciphers, :ciphers, []},
        {:reload_interval, :duration, default: "1m"},
        {:acme,
         {:section,
          [
            {:enabled, :boolean, default: false},
            {:directory_url, {:url, ["https", "http"]},
             default: "https://acme-v02.api.letsencrypt.org/directory"},
            {:email, :mailbox, []},
            {:domains, {:list, :hostname}, default: []},
            {:accept_terms, :boolean, default: false},
            {:storage, :absolute_path, default: "/var/lib/sovite/acme"},
            {:http_address, :ip_address, default: "0.0.0.0"},
            {:http_port, {:integer, 0, 65_535}, default: 80},
            {:renew_before, :duration, default: "30d"}
          ]}, []}
      ]}, []},
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
        {:trusted_networks, {:list, :cidr}, default: []},
        {:max_hops, {:integer, 1, 1000}, default: 50},
        {:requiretls, :boolean, default: true}
      ]}, []},
    {:domains,
     {:section,
      [
        {:local, {:list, :domain}, []},
        {:relay, {:list, :domain}, default: []},
        {:aliased, {:list, :domain}, default: []},
        {:hosted, {:list, :domain}, default: []},
        {:local_recipients, {:list, :mailbox}, []}
      ]}, []},
    {:routing,
     {:section,
      [
        {:extension_delimiter, :delimiter, default: ""},
        {:hide_subdomains, {:list, :hide_subdomain}, default: []},
        {:hide_subdomains_exceptions, {:list, :string}, default: []},
        {:always_bcc, :mailbox, []},
        {:local_transport, :transport, default: "local"},
        {:mailbox_transport, :transport, default: "mailbox"},
        {:relay_transport, :transport, default: "smtp"},
        {:remote_transport, :transport, default: "smtp"},
        {:rewrite_headers, :boolean, default: true}
      ]}, []},
    {:restrictions,
     {:section,
      for(stage <- Restrictions.stages(), do: {stage, {:list, :restriction}, default: []})}, []},
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
        {:connect_timeout, :duration, default: "30s"},
        {:tls, {:enum, @tls_levels}, default: :dane},
        {:tls_policy, {:map, :tls_destination, {:enum, @tls_levels}}, default: %{}},
        {:tls_ca_file, :absolute_path, []},
        {:relayhost_username, :string, []},
        {:relayhost_password, :string, []},
        {:source_address, {:list, :ip_address}, default: []}
      ]}, []},
    {:maildir, {:section, [{:local, :maildir_template, []}, {:mailbox, :maildir_template, []}]},
     []},
    {:pipe,
     {:map, :pipe_name,
      {:section,
       [
         {:command, :command, required: true},
         {:sandbox, :command, []},
         {:timeout, :duration, default: "10m"},
         {:directory, :absolute_path, default: "/"},
         {:env, {:map, :env_name, :string}, default: %{}},
         {:trace_headers, :boolean, default: true}
       ]}}, default: %{}},
    {:auth,
     {:section,
      [
        {:backend, {:enum, [:database, :file, :ldap, :dovecot]}, default: :database},
        {:mechanisms, {:list, {:enum, [:"SCRAM-SHA-256", :PLAIN, :LOGIN, :OAUTHBEARER]}}, []},
        {:plaintext, :boolean, default: false},
        {:max_failures, {:integer, 1, 100_000}, default: 10},
        {:failure_window, :duration, default: "10m"},
        {:ban_time, :duration, default: "1h"},
        {:failure_delay, :duration, default: "1s"},
        {:sender_check, :boolean, default: true},
        {:senders, {:map, :string, {:list, :sender_pattern}}, default: %{}},
        {:file, {:section, [{:path, :absolute_path, []}]}, []},
        {:ldap,
         {:section,
          [
            {:servers, {:list, :hostname}, default: []},
            {:port, {:integer, 1, 65_535}, []},
            {:security, {:enum, [:starttls, :ldaps, :none]}, default: :starttls},
            {:base, :string, []},
            {:filter, :ldap_filter, default: "(mail=%u)"},
            {:dn_template, :string, []},
            {:bind_dn, :string, []},
            {:bind_password, :string, []},
            {:timeout, :duration, default: "10s"}
          ]}, []},
        {:dovecot, {:section, [{:socket, :string, []}, {:timeout, :duration, default: "30s"}]},
         []},
        {:oauth,
         {:section,
          [
            {:introspection_url, {:url, ["https", "http"]}, []},
            {:client_id, :string, []},
            {:client_secret, :string, []},
            {:username_claim, :string, default: "username"},
            {:required_scope, :string, []}
          ]}, []}
      ]}, []},
    {:submission, {:section, [{:strip_headers, {:list, :string}, default: ["Return-Path"]}]}, []},
    {:spf,
     {:section,
      [
        {:verify, :boolean, default: true},
        {:helo, :boolean, default: true},
        {:reject_fail, :boolean, default: false},
        {:timeout, :duration, default: "20s"}
      ]}, []},
    {:dkim,
     {:section,
      [
        {:verify, :boolean, default: true},
        {:sign, :boolean, default: true},
        {:headers, {:list, :header_name}, []},
        {:expiration, :duration, []},
        {:key,
         {:list,
          {:section,
           [
             {:domain, :domain, required: true},
             {:selector, :dkim_selector, required: true},
             {:file, :absolute_path, required: true},
             {:sign, :boolean, default: true}
           ]}}, default: []}
      ]}, []},
    {:arc,
     {:section,
      [
        {:verify, :boolean, default: true},
        {:seal, :boolean, default: false},
        {:domain, :domain, []},
        {:selector, :dkim_selector, []},
        {:trusted_sealers, {:list, :domain}, default: []}
      ]}, []},
    {:dmarc,
     {:section,
      [
        {:verify, :boolean, default: true},
        {:policy, {:enum, [:report, :enforce]}, default: :report},
        {:reports, :boolean, default: false},
        {:report_interval, :duration, default: "1d"},
        {:report_org, :string, []},
        {:report_from, :mailbox, []}
      ]}, []},
    {:srs,
     {:section,
      [
        {:enabled, :boolean, default: false},
        {:domain, :domain, []},
        {:secrets, {:list, :string}, default: []},
        {:max_age, {:integer, 1, 1000}, default: 21}
      ]}, []},
    {:dns,
     {:section,
      [
        {:nameservers, {:list, :ip_address}, default: []},
        {:port, {:integer, 1, 65_535}, default: 53},
        {:timeout, :duration, default: "5s"},
        {:dnssec, {:enum, [:auto, :on, :off]}, default: :auto}
      ]}, []},
    {:mta_sts,
     {:section,
      [
        {:enabled, :boolean, default: true},
        {:fetch_timeout, :duration, default: "60s"},
        {:serve, :boolean, default: false},
        {:address, :ip_address, default: "0.0.0.0"},
        {:port, {:integer, 0, 65_535}, default: 443},
        {:mode, {:enum, [:enforce, :testing, :none]}, default: :testing},
        {:mx, {:list, :mx_pattern}, default: []},
        {:max_age, :duration, default: "7d"}
      ]}, []},
    {:tls_rpt,
     {:section,
      [
        {:reports, :boolean, default: false},
        {:report_interval, :duration, default: "1d"},
        {:report_org, :string, []},
        {:report_from, :mailbox, []},
        {:contact_info, :string, []}
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

  defstruct [
    :server,
    :database,
    :queue,
    :listener,
    :tls,
    :smtp,
    :domains,
    :routing,
    :restrictions,
    :delivery,
    :maildir,
    :pipe,
    :auth,
    :submission,
    :spf,
    :dkim,
    :arc,
    :dmarc,
    :srs,
    :dns,
    :mta_sts,
    :tls_rpt,
    :bounce,
    :log
  ]

  @type tls_level :: :none | :may | :encrypt | :verify | :dane

  @type t :: %__MODULE__{
          server: %{hostname: String.t(), authserv_id: String.t()},
          database: %{
            adapter: :sqlite | :postgres | :mysql,
            path: Path.t(),
            url: String.t() | nil,
            pool_size: pos_integer(),
            ssl: boolean()
          },
          queue: %{
            directory: Path.t(),
            max_lifetime: pos_integer(),
            min_backoff: pos_integer(),
            max_backoff: pos_integer(),
            delay_warning: pos_integer() | nil
          },
          listener: [
            %{
              address: :inet.ip_address(),
              port: :inet.port_number(),
              mode: :smtp | :submission | :submissions | :lmtp,
              auth: boolean(),
              require_tls: boolean(),
              require_auth: boolean(),
              tls_min_version: :"tlsv1.2" | :"tlsv1.3" | nil,
              tls_ciphers: [String.t()] | nil
            }
          ],
          tls: %{
            certificate: [%{cert_file: Path.t(), key_file: Path.t()}],
            min_version: :"tlsv1.2" | :"tlsv1.3",
            ciphers: [String.t()] | nil,
            reload_interval: pos_integer(),
            acme: map()
          },
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
            trusted_networks: [Sovite.Net.network()],
            max_hops: pos_integer(),
            requiretls: boolean()
          },
          domains: %{
            local: [String.t()],
            relay: [String.t()],
            local_recipients: [String.t()] | nil,
            aliased: [String.t()],
            hosted: [String.t()]
          },
          routing: map(),
          restrictions: %{atom() => [String.t()]},
          delivery: %{
            relayhost: %{host: String.t(), port: :inet.port_number(), mx: boolean()} | nil,
            max_deliveries: pos_integer(),
            destination_concurrency: pos_integer(),
            destination_rate_delay: pos_integer() | nil,
            max_recipients: pos_integer(),
            max_addresses: pos_integer(),
            ip_versions: [:ipv6 | :ipv4, ...],
            connect_timeout: pos_integer(),
            tls: tls_level(),
            tls_policy: %{String.t() => tls_level()},
            tls_ca_file: Path.t() | nil,
            relayhost_username: String.t() | nil,
            relayhost_password: String.t() | nil,
            source_address: [:inet.ip_address()]
          },
          maildir: %{local: String.t() | nil, mailbox: String.t() | nil},
          pipe: %{
            String.t() => %{
              command: [String.t(), ...],
              sandbox: [String.t(), ...] | nil,
              timeout: pos_integer(),
              directory: Path.t(),
              env: %{String.t() => String.t()},
              trace_headers: boolean()
            }
          },
          auth: map(),
          submission: %{strip_headers: [String.t()]},
          spf: %{
            verify: boolean(),
            helo: boolean(),
            reject_fail: boolean(),
            timeout: pos_integer()
          },
          dkim: %{
            verify: boolean(),
            sign: boolean(),
            headers: [String.t()] | nil,
            expiration: pos_integer() | nil,
            key: [
              %{
                domain: String.t(),
                selector: String.t(),
                file: Path.t(),
                sign: boolean(),
                signing_key: Sovite.DKIM.SigningKey.t() | nil
              }
            ]
          },
          arc: %{
            verify: boolean(),
            seal: boolean(),
            domain: String.t() | nil,
            selector: String.t() | nil,
            trusted_sealers: [String.t()]
          },
          dmarc: %{
            verify: boolean(),
            policy: :report | :enforce,
            reports: boolean(),
            report_interval: pos_integer(),
            report_org: String.t(),
            report_from: String.t()
          },
          srs: %{
            enabled: boolean(),
            domain: String.t(),
            secrets: [String.t()],
            max_age: pos_integer()
          },
          dns: %{
            nameservers: [:inet.ip_address()],
            port: :inet.port_number(),
            timeout: pos_integer(),
            dnssec: :auto | :on | :off
          },
          mta_sts: %{
            enabled: boolean(),
            fetch_timeout: pos_integer(),
            serve: boolean(),
            address: :inet.ip_address(),
            port: :inet.port_number(),
            mode: :enforce | :testing | :none,
            mx: [String.t()],
            max_age: pos_integer()
          },
          tls_rpt: %{
            reports: boolean(),
            report_interval: pos_integer(),
            report_org: String.t(),
            report_from: String.t(),
            contact_info: String.t()
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
         values =
           values
           |> listener_defaults()
           |> local_domains()
           |> AuthRules.defaults()
           |> TransportRules.defaults(),
         {values, key_errors} = AuthRules.load_keys(values),
         :ok <- check(values, key_errors) do
      {:ok, struct!(__MODULE__, values)}
    end
  end

  # Like Postfix's mydestination, the server is its own final destination
  # unless told otherwise.
  defp local_domains(values) do
    update_in(values.domains.local, fn
      nil -> [String.downcase(values.server.hostname, :ascii)]
      local -> local
    end)
  end

  # Unset listener keys get the defaults of the listener's mode.
  @mode_defaults %{
    smtp: %{port: 25, auth: false, require_tls: false, require_auth: false},
    submission: %{port: 587, auth: true, require_tls: true, require_auth: true},
    submissions: %{port: 465, auth: true, require_tls: true, require_auth: true},
    lmtp: %{port: 24, auth: false, require_tls: false, require_auth: false}
  }

  defp listener_defaults(values),
    do: update_in(values.listener, &Enum.map(&1, fn listener -> with_mode_defaults(listener) end))

  defp with_mode_defaults(listener) do
    Map.merge(listener, Map.fetch!(@mode_defaults, listener.mode), fn
      _key, nil, default -> default
      _key, value, _default -> value
    end)
  end

  @doc "Returns whether any listener offers AUTH."
  @spec auth_enabled?(t() | map()) :: boolean()
  def auth_enabled?(config), do: Enum.any?(config.listener, & &1.auth)

  @doc """
  The DNS resolver for `config`: `Sovite.DNS.InetRes` with the `[dns]`
  nameservers, or the system's.
  """
  @spec resolver(t() | map()) :: Sovite.DNS.resolver()
  def resolver(%{dns: dns}) do
    trust_ad =
      case dns.dnssec do
        :auto -> :auto
        :on -> true
        :off -> false
      end

    nameservers =
      if dns.nameservers == [],
        do: [],
        else: [nameservers: Enum.map(dns.nameservers, &{&1, dns.port})]

    {Sovite.DNS.InetRes, nameservers ++ [timeout: dns.timeout, trust_ad: trust_ad]}
  end

  @doc "Returns whether TLS certificates are configured (files or ACME)."
  @spec tls_enabled?(t() | map()) :: boolean()
  def tls_enabled?(config), do: config.tls.certificate != [] or config.tls.acme.enabled

  @doc """
  The SASL mechanisms to offer: `auth.mechanisms`, or by default those
  the backend supports.
  """
  @spec auth_mechanisms(t() | map()) :: [String.t()]
  def auth_mechanisms(%{auth: auth}) do
    case auth.mechanisms do
      nil ->
        base =
          if auth.backend == :ldap,
            do: ["PLAIN", "LOGIN"],
            else: ["SCRAM-SHA-256", "PLAIN", "LOGIN"]

        base = if auth.backend == :dovecot, do: ["PLAIN", "LOGIN"], else: base
        if auth.oauth.introspection_url, do: base ++ ["OAUTHBEARER"], else: base

      mechanisms ->
        Enum.map(mechanisms, &Atom.to_string/1)
    end
  end

  # Rules that involve more than one key.
  defp check(values, key_errors) do
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
          %Error{path: ["delivery", "ip_versions"], reason: "must not repeat a version"},
        (values.delivery.relayhost_username != nil and values.delivery.relayhost == nil) &&
          %Error{path: ["delivery", "relayhost_username"], reason: "needs delivery.relayhost"}
      ]
      |> Kernel.++(database_errors(values.database))
      |> Kernel.++(listener_errors(values))
      |> Kernel.++(auth_errors(values))
      |> Kernel.++(acme_errors(values.tls.acme))
      |> Kernel.++(RoutingRules.errors(values))
      |> Kernel.++(key_errors)
      |> Kernel.++(AuthRules.errors(values))
      |> Kernel.++(TransportRules.errors(values))
      |> Enum.filter(& &1)

    if errors == [], do: :ok, else: {:error, errors}
  end

  defp database_errors(%{adapter: :sqlite}), do: []

  defp database_errors(database) do
    [
      database.url == nil &&
        %Error{path: ["database", "url"], reason: "is required for #{database.adapter}"},
      Repo.module(database.adapter) == nil &&
        %Error{
          path: ["database", "adapter"],
          reason:
            "#{inspect(Atom.to_string(database.adapter))} needs the #{inspect(Repo.driver(database.adapter))} dependency, which this build does not include"
        }
    ]
  end

  defp listener_errors(values) do
    tls = tls_enabled?(values)

    values.listener
    |> Enum.with_index()
    |> Enum.flat_map(fn {listener, index} ->
      for {field, reason} <- listener_problems(listener, tls, values.auth.plaintext),
          do: %Error{path: ["listener", "[#{index}]", field], reason: reason}
    end)
  end

  defp listener_problems(listener, tls, plaintext) do
    Enum.filter(
      [
        lmtp_port_problem(listener),
        implicit_tls_problem(listener, tls),
        require_tls_problem(listener, tls),
        auth_problem(listener, tls, plaintext),
        require_auth_problem(listener)
      ],
      & &1
    )
  end

  # RFC 2033 §5: LMTP must not be used on the SMTP port.
  defp lmtp_port_problem(%{mode: :lmtp, port: 25}), do: {"port", "LMTP must not use port 25"}
  defp lmtp_port_problem(_listener), do: nil

  defp implicit_tls_problem(%{mode: :submissions}, false),
    do: {"mode", ~s("submissions" needs a certificate in [tls])}

  defp implicit_tls_problem(_listener, _tls), do: nil

  defp require_tls_problem(%{require_tls: true, mode: mode}, false) when mode != :submissions,
    do: {"require_tls", "needs a certificate in [tls]"}

  defp require_tls_problem(_listener, _tls), do: nil

  defp auth_problem(%{auth: true}, false, false),
    do:
      {"auth",
       "needs a certificate in [tls], since AUTH is only offered over TLS (see auth.plaintext)"}

  defp auth_problem(_listener, _tls, _plaintext), do: nil

  defp require_auth_problem(%{require_auth: true, auth: false}),
    do: {"require_auth", "needs auth = true"}

  defp require_auth_problem(_listener), do: nil

  defp auth_errors(values) do
    if auth_enabled?(values),
      do: backend_errors(values.auth) ++ mechanism_errors(values.auth.backend, values),
      else: []
  end

  defp backend_errors(%{backend: :file, file: %{path: nil}}),
    do: [%Error{path: ["auth", "file", "path"], reason: ~s(is required with backend = "file")}]

  defp backend_errors(%{backend: :ldap, ldap: ldap}) do
    [
      ldap.servers == [] &&
        %Error{path: ["auth", "ldap", "servers"], reason: ~s(is required with backend = "ldap")},
      (ldap.base == nil and ldap.dn_template == nil) &&
        %Error{
          path: ["auth", "ldap", "base"],
          reason: "is required unless auth.ldap.dn_template is set"
        }
    ]
  end

  defp backend_errors(%{backend: :dovecot, dovecot: %{socket: nil}}),
    do: [
      %Error{
        path: ["auth", "dovecot", "socket"],
        reason: ~s(is required with backend = "dovecot")
      }
    ]

  defp backend_errors(_auth), do: []

  # Dovecot runs the mechanisms itself.
  defp mechanism_errors(:dovecot, _values), do: []

  defp mechanism_errors(backend, values) do
    mechanisms = auth_mechanisms(values)

    [
      ("OAUTHBEARER" in mechanisms and values.auth.oauth.introspection_url == nil) &&
        %Error{
          path: ["auth", "mechanisms"],
          reason: "OAUTHBEARER needs auth.oauth.introspection_url"
        },
      (backend == :ldap and "SCRAM-SHA-256" in mechanisms) &&
        %Error{
          path: ["auth", "mechanisms"],
          reason: "SCRAM-SHA-256 does not work with the ldap backend"
        }
    ]
  end

  defp acme_errors(%{enabled: false}), do: []

  defp acme_errors(acme) do
    [
      acme.domains == [] &&
        %Error{path: ["tls", "acme", "domains"], reason: "is required when ACME is enabled"},
      acme.email == nil &&
        %Error{path: ["tls", "acme", "email"], reason: "is required when ACME is enabled"},
      not acme.accept_terms &&
        %Error{
          path: ["tls", "acme", "accept_terms"],
          reason: "must be true: you must agree to the CA's terms of service to use ACME"
        }
    ]
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
