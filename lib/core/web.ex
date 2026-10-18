defmodule Sovite.Core.Web do
  @moduledoc """
  The web server: the status UI and the admin API, served with Plug and
  Cowboy on `admin.address` and `admin.port` (`127.0.0.1:9025` by
  default), with TLS from the certificate store when `admin.tls` is set.

    * `/api/...` - the admin API (`Sovite.Core.Web.API`), for `sovitectl`,
      monitoring, and the UI.
    * `/metrics` - Prometheus metrics (`Sovite.Core.Metrics`).
    * Everything else - the UI: the static build of `lib/core/sovite_web`,
      from `admin.web_root`, or `priv/web` in the release.

  Ports 80 and 443 stay with ACME (`tls.acme`) and the MTA-STS policy
  server (`mta_sts.serve`).

  ## Security

  The UI will have users of its own, so the web server is built for
  untrusted clients:

    * Only clients in `admin.allowed_networks` (loopback by default) get
      an answer other than `403`.
    * The API and `/metrics` need the bearer token from
      `admin.token_file` (created with a random token, mode `0600`, if it
      does not exist), compared in constant time. `/metrics` can be made
      public with `admin.public_metrics`.
    * Wrong tokens count as failed logins, like SMTP `AUTH` ones: they
      are logged as `auth.failure` (for fail2ban), and after
      `auth.max_failures` within `auth.failure_window` the client gets
      `429` for `auth.ban_time`.
    * Requests that change something (`POST`) from another site, by
      their `Origin` or `Sec-Fetch-Site`, get `403`, and no
      cross-origin (CORS) access is granted, so pages elsewhere can
      neither read the API nor act on it.
    * Every response has strict security headers: a
      `Content-Security-Policy` that allows the UI's own scripts only
      (inline scripts of its pages by their hash), no framing, no
      referrer, `nosniff`, same-origin opener and resource policies, a
      permissions policy that turns off device access, and with TLS,
      `Strict-Transport-Security`. API responses are never cached.
    * Request lines, headers, and connections are limited, and slow
      clients time out.

  ## Telemetry

    * `[:sovite, :web, :request, :stop]` - `%{duration}`,
      `%{method, path, status, remote_ip}`
    * `[:sovite, :web, :request, :exception]` - `%{}`,
      `%{method, path, kind, reason}`: a request that crashed, answered
      with `500`.
    * `[:sovite, :auth, :failure]` with `mechanism: "TOKEN"` and
      `reason: :invalid_token` for a wrong token.
  """

  require Logger

  alias Sovite.Core.Config
  alias Sovite.Core.Web.Router
  alias Sovite.TLS.CertStore

  @doc """
  The child specs of the web server for `config`: the failed-token
  counter and the Cowboy listener. `[]` with `admin.enabled = false`, or
  when the token file cannot be used (logged).
  """
  @spec child_specs(Config.t(), map()) :: [Supervisor.child_spec()]
  def child_specs(%{admin: %{enabled: false}}, _runtime), do: []

  def child_specs(config, runtime) do
    admin = config.admin

    case token(admin.token_file) do
      {:ok, token} ->
        penalty = runtime.args.names.web_penalty

        opts = %{
          instance: runtime.instance,
          control: runtime.control,
          queue_manager: runtime.queue_manager,
          metrics: runtime.metrics,
          repo: runtime.repo,
          penalty: penalty,
          token_hash: :crypto.hash(:sha256, token),
          https: admin.tls and runtime.cert_store != nil
        }

        [
          Supervisor.child_spec(
            {Sovite.Abuse.Penalty,
             name: penalty,
             max_failures: config.auth.max_failures,
             window: config.auth.failure_window,
             ban_time: config.auth.ban_time},
            id: {Sovite.Abuse.Penalty, penalty}
          ),
          listener_spec(admin, opts, runtime)
        ]

      {:error, reason} ->
        Logger.error("web server disabled: cannot use #{admin.token_file}: #{reason}")
        []
    end
  end

  defp listener_spec(admin, opts, runtime) do
    ref = runtime.args.names.web
    scheme = if opts.https, do: :https, else: :http

    options =
      [
        ref: ref,
        ip: admin.address,
        port: admin.port,
        transport_options: [num_acceptors: 10, max_connections: 100],
        protocol_options: [
          idle_timeout: 60_000,
          request_timeout: 10_000,
          max_request_line_length: 8192,
          max_header_name_length: 64,
          max_header_value_length: 8192,
          max_headers: 50,
          max_keepalive: 100
        ]
      ] ++ if(opts.https, do: tls_options(runtime.cert_store), else: [])

    Supervisor.child_spec(
      {Plug.Cowboy, scheme: scheme, plug: {Router, opts}, options: options},
      id: {Plug.Cowboy, ref}
    )
  end

  # The certificates as loaded now, and the current ones by SNI, so
  # renewed certificates are used without a restart.
  defp tls_options(store) do
    current = CertStore.server_options(store) || []

    Keyword.take(current, [:certs_keys, :versions, :ciphers]) ++
      [
        sni_fun: fn host ->
          case CertStore.server_options(store) do
            nil -> :undefined
            options -> Keyword.fetch!(options, :sni_fun).(host)
          end
        end
      ]
  end

  ## Token

  @doc """
  Reads the token in `path`, or creates the file with a random token if
  it does not exist. Returns `{:error, text}` if it cannot.
  """
  @spec token(Path.t()) :: {:ok, String.t()} | {:error, String.t()}
  def token(path) do
    case File.read(path) do
      {:ok, contents} ->
        case String.trim(contents) do
          token when byte_size(token) >= 16 -> {:ok, token}
          _ -> {:error, "the token is shorter than 16 characters"}
        end

      {:error, :enoent} ->
        create_token(path)

      {:error, reason} ->
        {:error, :file.format_error(reason) |> List.to_string()}
    end
  end

  defp create_token(path) do
    token = 32 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
    tmp = path <> ".tmp"

    # Created private, then renamed, so it is never readable by others.
    with :ok <- File.write(tmp, "", [:exclusive]),
         :ok <- File.chmod(tmp, 0o600),
         :ok <- File.write(tmp, token <> "\n"),
         :ok <- File.rename(tmp, path) do
      {:ok, token}
    else
      {:error, reason} ->
        _ = File.rm(tmp)
        {:error, :file.format_error(reason) |> List.to_string()}
    end
  end
end
