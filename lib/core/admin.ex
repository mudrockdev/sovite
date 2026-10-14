defmodule Sovite.Core.Admin do
  @moduledoc """
  The admin HTTP API, for `sovitectl` and monitoring, served by
  `Sovite.HTTP` on `admin.address` and `admin.port` (`127.0.0.1:9025`
  by default), with TLS from the certificate store when `admin.tls` is
  set.

  Requests must come from `admin.allowed_networks` (loopback by
  default), and carry the token from `admin.token_file`:

      curl -H "Authorization: Bearer $(cat /var/lib/sovite/admin.token)" http://127.0.0.1:9025/api/status

  The token file is created with a random token, readable only by the
  user Sovite runs as, if it does not exist. `/metrics` needs the token
  too, unless `admin.public_metrics` is set.

  | Request | |
  |---|---|
  | `GET /api/status` | Version, uptime, listeners, queue sizes (`Sovite.Core.Control.status/1`) |
  | `GET /api/queue` | Queued messages; `?queue=deferred` for one queue, `?limit=n` (`Sovite.Core.QueueInfo.list/2`) |
  | `GET /api/queue/ID` | One message (`Sovite.Core.QueueInfo.show/2`) |
  | `POST /api/queue/flush` | Retry every deferred message |
  | `POST /api/queue/ID/retry`, `hold`, `release`, `delete`, `requeue` | See `Sovite.Core.QueueManager` |
  | `GET /api/config` | The running settings, secrets hidden (`Sovite.Core.Config.Settings`) |
  | `POST /api/config/reload` | Reload the config file |
  | `GET /api/route?address=A&sender=S` | How `A` is routed (`Sovite.Core.RouteInfo`) |
  | `GET /api/trace?id=ID` | A message's log lines (`Sovite.Core.Trace`), with `[log] directory` |
  | `GET /metrics` | Prometheus metrics (`Sovite.Core.Metrics`), with `metrics.enabled` |

  Responses are JSON (`/metrics` is the Prometheus text format). Errors
  are `{"error": "..."}` with `400`, `401`, `403`, `404`, `409`, or
  `422`.

  With `admin.web_root`, other `GET` requests serve the files in that
  directory, such as a built status UI; they need no token, since the
  pages call the API with it.
  """

  alias Sovite.Core.Config.Settings
  alias Sovite.Core.{Control, LogReader, QueueInfo, QueueManager, RouteInfo, Routing, Trace}
  alias Sovite.HTTP
  alias Sovite.HTTP.Request
  alias Sovite.Metrics.Prometheus

  @actions %{
    "retry" => :retry,
    "hold" => :hold,
    "release" => :release,
    "delete" => :delete,
    "requeue" => :requeue
  }

  @security_headers [
    {"x-content-type-options", "nosniff"},
    {"x-frame-options", "DENY"},
    {"referrer-policy", "no-referrer"}
  ]

  @content_types %{
    ".html" => "text/html; charset=utf-8",
    ".js" => "text/javascript; charset=utf-8",
    ".css" => "text/css; charset=utf-8",
    ".json" => "application/json",
    ".svg" => "image/svg+xml",
    ".png" => "image/png",
    ".ico" => "image/x-icon",
    ".webp" => "image/webp",
    ".woff2" => "font/woff2",
    ".txt" => "text/plain; charset=utf-8"
  }

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

  ## Handler

  @doc false
  # What the handler needs from the running configuration.
  def opts(config, runtime, token) do
    %{
      token_hash: :crypto.hash(:sha256, token),
      allowed_networks: config.admin.allowed_networks,
      public_metrics: config.admin.public_metrics,
      web_root: config.admin.web_root,
      control: runtime.control,
      queue_manager: runtime.queue_manager,
      metrics: runtime.metrics,
      directory: config.queue.directory,
      routing: Routing.new(config, runtime.repo),
      log: config.log,
      settings: Settings.list(config.raw)
    }
  end

  @doc "The `Sovite.HTTP.Server` handler for `opts/3`."
  @spec handler(map()) :: (Request.t() -> HTTP.response())
  def handler(opts), do: &handle(&1, opts)

  @doc false
  def handle(%Request{} = request, opts) do
    {status, headers, body} = route(request, opts)
    {status, headers ++ @security_headers, body}
  end

  defp route(request, opts) do
    cond do
      not Sovite.Net.in_networks?(request.remote_ip, opts.allowed_networks) ->
        HTTP.error(403, "not allowed from this address")

      api?(request) ->
        if public?(request, opts) or authorized?(request, opts),
          do: api(request.method, request.segments, request, opts),
          else: unauthorized()

      request.method in ["GET", "HEAD"] and opts.web_root != nil ->
        static(request, opts.web_root)

      true ->
        HTTP.error(404, "not found")
    end
  end

  defp public?(request, opts), do: metrics?(request) and opts.public_metrics

  defp unauthorized do
    {401, [{"www-authenticate", ~s(Bearer realm="sovite")} | json_headers()],
     JSON.encode!(%{error: "a valid token is needed"})}
  end

  defp api?(%{segments: ["api" | _]}), do: true
  defp api?(request), do: metrics?(request)

  defp metrics?(%{segments: ["metrics"]}), do: true
  defp metrics?(_request), do: false

  defp authorized?(request, opts) do
    case Request.bearer_token(request) do
      nil -> false
      token -> :crypto.hash_equals(:crypto.hash(:sha256, token), opts.token_hash)
    end
  end

  defp json_headers, do: [{"content-type", "application/json"}, {"cache-control", "no-store"}]

  defp ok(body), do: json(200, body)
  defp json(status, body), do: {status, json_headers(), JSON.encode!(body)}

  ## API

  defp api("GET", ["metrics"], _request, %{metrics: nil}),
    do: HTTP.error(404, "metrics are disabled")

  defp api("GET", ["metrics"], _request, opts) do
    body = opts.metrics |> Sovite.Metrics.collect() |> Prometheus.format()
    {200, [{"content-type", Prometheus.content_type()}, {"cache-control", "no-store"}], body}
  end

  defp api("GET", ["api", "status"], _request, opts), do: ok(Control.status(opts.control))

  defp api("GET", ["api", "queue"], request, opts) do
    with {:ok, queues} <- queues(request.query["queue"]),
         {:ok, limit} <- limit(request.query["limit"]) do
      ok(%{messages: QueueInfo.list(opts.directory, queues: queues, limit: limit)})
    else
      {:error, message} -> HTTP.error(400, message)
    end
  end

  defp api("POST", ["api", "queue", "flush"], _request, opts) do
    :ok = QueueManager.flush(opts.queue_manager)
    ok(%{ok: true})
  end

  defp api("GET", ["api", "queue", id], _request, opts) do
    case QueueInfo.show(opts.directory, id) do
      {:ok, details} -> ok(details)
      {:error, :not_found} -> HTTP.error(404, "no such message")
      {:error, reason} -> HTTP.error(409, "cannot read the message: #{inspect(reason)}")
    end
  end

  defp api("POST", ["api", "queue", id, action], _request, opts)
       when is_map_key(@actions, action) do
    case apply(QueueManager, Map.fetch!(@actions, action), [opts.queue_manager, id]) do
      :ok -> ok(%{ok: true})
      {:error, :not_found} -> HTTP.error(404, "no such message")
    end
  end

  defp api("GET", ["api", "config"], _request, opts) do
    ok(%{settings: for({key, value, default} <- opts.settings, do: [key, value, default])})
  end

  defp api("POST", ["api", "config", "reload"], _request, opts) do
    case Control.reload(opts.control) do
      :ok ->
        ok(%{ok: true})

      {:error, errors} when is_list(errors) ->
        json(422, %{
          error: "invalid configuration",
          errors: Enum.map(errors, &Exception.message/1)
        })

      {:error, {:restart_required, keys}} ->
        json(409, %{error: "these settings need a restart", keys: keys})

      {:error, :no_config_file} ->
        HTTP.error(409, "the server was started without a config file")
    end
  end

  defp api("GET", ["api", "route"], request, opts) do
    case request.query["address"] do
      address when is_binary(address) and address != "" ->
        ok(RouteInfo.resolve(opts.routing, address, request.query["sender"] || ""))

      _ ->
        HTTP.error(400, "address is required")
    end
  end

  defp api("GET", ["api", "trace"], request, opts) do
    cond do
      request.query["id"] in [nil, ""] ->
        HTTP.error(400, "id is required")

      opts.log.directory == nil ->
        HTTP.error(404, "logs are not written to files ([log] directory)")

      true ->
        files = LogReader.files(opts.log.directory, opts.log.file_name)
        trace = Trace.run(request.query["id"], files)

        ok(%{
          queue_ids: trace.queue_ids,
          lines: Enum.map(trace.entries, & &1.line),
          queued:
            for(
              id <- trace.queue_ids,
              {:ok, details} <- [QueueInfo.show(opts.directory, id)],
              do: details
            )
        })
    end
  end

  defp api(method, _segments, _request, _opts) when method not in ["GET", "HEAD", "POST"],
    do: HTTP.error(405, "method not allowed")

  defp api(_method, _segments, _request, _opts), do: HTTP.error(404, "not found")

  defp queues(nil), do: {:ok, QueueInfo.queues()}

  defp queues(name) do
    case Enum.find(QueueInfo.queues(), &(Atom.to_string(&1) == name)) do
      nil -> {:error, "unknown queue #{inspect(name)}"}
      queue -> {:ok, [queue]}
    end
  end

  defp limit(nil), do: {:ok, nil}

  defp limit(value) do
    case Integer.parse(value) do
      {n, ""} when n > 0 -> {:ok, n}
      _ -> {:error, "limit must be a positive integer"}
    end
  end

  ## Static files

  defp static(request, root) do
    segments = request.segments

    if Enum.any?(segments, &(String.starts_with?(&1, ".") or String.contains?(&1, ["\\", <<0>>]))) do
      HTTP.error(404, "not found")
    else
      path = Path.join([root | segments])

      path =
        cond do
          File.regular?(path) -> path
          File.regular?(Path.join(path, "index.html")) -> Path.join(path, "index.html")
          File.regular?(path <> ".html") -> path <> ".html"
          # Pages a single-page app routes itself.
          true -> Path.join(root, "index.html")
        end

      case File.read(path) do
        {:ok, body} ->
          type = Map.get(@content_types, Path.extname(path), "application/octet-stream")
          {200, [{"content-type", type}], body}

        {:error, _} ->
          HTTP.error(404, "not found")
      end
    end
  end
end
