defmodule Sovite.Core.Web.API do
  @moduledoc """
  The admin API, under `/api` on the web server (`Sovite.Core.Web`),
  for `sovitectl`, monitoring, and the UI. Every request needs the token
  from `admin.token_file`:

      curl -H "Authorization: Bearer $(cat /var/lib/sovite/admin.token)" http://127.0.0.1:9025/api/status

  | Request | |
  |---|---|
  | `GET /api/status` | Version, uptime, listeners, queue sizes (`Sovite.Core.Control.status/1`) |
  | `GET /api/queue` | Queued messages; `?queue=deferred` for one queue, `?limit=n` (`Sovite.Core.MTA.QueueInfo.list/2`) |
  | `GET /api/queue/ID` | One message (`Sovite.Core.MTA.QueueInfo.show/2`) |
  | `POST /api/queue/flush` | Retry every deferred message |
  | `POST /api/queue/ID/retry`, `hold`, `release`, `delete`, `requeue` | See `Sovite.Core.MTA.QueueManager` |
  | `GET /api/config` | The running settings, secrets hidden (`Sovite.Core.Config.Settings`) |
  | `POST /api/config/reload` | Reload the config file |
  | `GET /api/route?address=A&sender=S` | How `A` is routed (`Sovite.Core.MTA.RouteInfo`) |
  | `GET /api/trace?id=ID` | A message's log lines (`Sovite.Core.MTA.Trace`), with `[log] directory` |
  | `GET /api/cluster` | The cluster's nodes and the copies of their queues (`Sovite.Core.Cluster`) |
  | `POST /api/cluster/config` | Send `{"content": TOML}` to every node as the shared configuration |
  | `POST /api/cluster/join` | Join the cluster of `{"peer": "name@host:port"}` |
  | `POST /api/cluster/leave` | Hand the queue to the other nodes, and leave the cluster |
  | `GET /api/ip_pools` | The IP pools: messages sent today from each address, and today's limits (`Sovite.Core.MTA.IPPools`) |
  | `GET /metrics` | Prometheus metrics (`Sovite.Core.Metrics`), with `metrics.enabled` |

  Responses are JSON (`/metrics` is the Prometheus text format). Errors
  are `{"error": "..."}` with `400`, `401`, `403`, `404`, `405`, `409`,
  `422`, or `429`.
  """

  use Plug.Router

  alias Sovite.Core.Config.Settings
  alias Sovite.Core.MTA.Cluster.Queue
  alias Sovite.Core.Web.Security

  alias Sovite.Core.{Cluster, Config, Control, LogReader}
  alias Sovite.Core.MTA.{IPPools, QueueInfo, QueueManager, RouteInfo, Routing, Trace}

  alias Sovite.Metrics.Prometheus

  @actions %{
    "retry" => :retry,
    "hold" => :hold,
    "release" => :release,
    "delete" => :delete,
    "requeue" => :requeue
  }

  plug(Security, :same_origin)
  plug(Security, {:authenticate, :api})
  plug(:mta_part)
  plug(:fetch_query_params)
  plug(:match)
  plug(:dispatch)

  get "/status" do
    ok(conn, Control.status(web(conn).control))
  end

  get "/queue" do
    with {:ok, queues} <- queues(conn.query_params["queue"]),
         {:ok, limit} <- limit(conn.query_params["limit"]) do
      ok(conn, %{messages: QueueInfo.list(directory(conn), queues: queues, limit: limit)})
    else
      {:error, message} -> Security.error(conn, 400, message)
    end
  end

  post "/queue/flush" do
    :ok = QueueManager.flush(web(conn).queue_manager)
    ok(conn, %{ok: true})
  end

  get "/queue/:id" do
    case QueueInfo.show(directory(conn), id) do
      {:ok, details} -> ok(conn, details)
      {:error, :not_found} -> Security.error(conn, 404, "no such message")
      {:error, reason} -> Security.error(conn, 409, "cannot read the message: #{inspect(reason)}")
    end
  end

  post "/queue/:id/:action" when is_map_key(@actions, action) do
    case apply(QueueManager, Map.fetch!(@actions, action), [web(conn).queue_manager, id]) do
      :ok -> ok(conn, %{ok: true})
      {:error, :not_found} -> Security.error(conn, 404, "no such message")
    end
  end

  get "/config" do
    settings =
      for {key, value, default} <- Settings.list(config(conn).raw), do: [key, value, default]

    ok(conn, %{settings: settings})
  end

  post "/config/reload" do
    case Control.reload(web(conn).control) do
      :ok ->
        ok(conn, %{ok: true})

      {:error, errors} when is_list(errors) ->
        json(conn, 422, %{
          error: "invalid configuration",
          errors: Enum.map(errors, &Exception.message/1)
        })

      {:error, {:restart_required, keys}} ->
        json(conn, 409, %{error: "these settings need a restart", keys: keys})

      {:error, :no_config_file} ->
        Security.error(conn, 409, "the server was started without a config file")
    end
  end

  get "/route" do
    case conn.query_params["address"] do
      address when is_binary(address) and address != "" ->
        routing = Routing.new(config(conn), web(conn).repo)
        sender = conn.query_params["sender"] || ""
        ok(conn, RouteInfo.resolve(routing, address, if(is_binary(sender), do: sender, else: "")))

      _ ->
        Security.error(conn, 400, "address is required")
    end
  end

  get "/cluster" do
    if cluster?(conn) do
      status = Cluster.status(remote: true)
      queue = if web(conn).queue_manager, do: Queue.status(), else: %{}
      ok(conn, Map.merge(status, %{enabled: true, queue: queue}))
    else
      ok(conn, %{enabled: false})
    end
  end

  post "/cluster/config" do
    with :ok <- need_cluster(conn),
         {:ok, %{"content" => content}} when is_binary(content) <- body(conn) do
      case Cluster.push_config(content) do
        {:ok, version} -> ok(conn, %{ok: true, version: version})
        {:error, errors} -> json(conn, 422, %{error: "invalid configuration", errors: errors})
      end
    else
      {:error, status, message} -> Security.error(conn, status, message)
      _ -> Security.error(conn, 400, ~s(expected {"content": "..."}))
    end
  end

  post "/cluster/join" do
    with :ok <- need_cluster(conn),
         {:ok, %{"peer" => peer}} when is_binary(peer) <- body(conn) do
      case Cluster.join(peer) do
        :ok -> ok(conn, %{ok: true})
        {:error, message} -> Security.error(conn, 422, message)
      end
    else
      {:error, status, message} -> Security.error(conn, status, message)
      _ -> Security.error(conn, 400, ~s(expected {"peer": "name@host:port"}))
    end
  end

  post "/cluster/leave" do
    with :ok <- need_cluster(conn),
         {:ok, result} <- Cluster.leave() do
      ok(conn, Map.put(result, :ok, true))
    else
      {:error, :no_peers} -> Security.error(conn, 409, "no other node is connected")
      {:error, status, message} -> Security.error(conn, status, message)
    end
  end

  get "/ip_pools" do
    if config(conn).ip_pool == [],
      do: ok(conn, %{pools: []}),
      else: ok(conn, %{pools: IPPools.status(IPPools)})
  end

  get "/trace" do
    log = config(conn).log

    case conn.query_params["id"] do
      id when not is_binary(id) or id == "" ->
        Security.error(conn, 400, "id is required")

      _id when log.directory == nil ->
        Security.error(conn, 404, "logs are not written to files ([log] directory)")

      id ->
        trace = Trace.run(id, LogReader.files(log.directory, log.file_name))

        ok(conn, %{
          queue_ids: trace.queue_ids,
          lines: Enum.map(trace.entries, & &1.line),
          queued:
            for(
              id <- trace.queue_ids,
              {:ok, details} <- [QueueInfo.show(directory(conn), id)],
              do: details
            )
        })
    end
  end

  match _ do
    if conn.method in ["GET", "HEAD", "POST"],
      do: Security.error(conn, 404, "not found"),
      else: Security.error(conn, 405, "method not allowed")
  end

  @doc false
  # GET /metrics, once authenticated.
  def metrics(conn) do
    case web(conn).metrics do
      nil ->
        Security.error(conn, 404, "metrics are disabled")

      metrics ->
        conn
        |> put_resp_header("content-type", Prometheus.content_type())
        |> put_resp_header("cache-control", "no-store")
        |> send_resp(200, metrics |> Sovite.Metrics.collect() |> Prometheus.format())
    end
  end

  defp cluster?(conn), do: config(conn).cluster.enabled and Process.whereis(Cluster) != nil

  defp need_cluster(conn) do
    if cluster?(conn), do: :ok, else: {:error, 409, "the cluster is not enabled"}
  end

  # A JSON request body, of up to 1 MB.
  defp body(conn) do
    case read_body(conn, length: 1_048_576) do
      {:ok, body, _conn} -> JSON.decode(body)
      _ -> {:error, 413, "the request body is too large"}
    end
  end

  # The MTA's routes answer only on nodes that run it ([stack]).
  @mta_routes ~w(queue route trace ip_pools)

  defp mta_part(%{path_info: [route | _]} = conn, _opts) when route in @mta_routes do
    if web(conn).queue_manager,
      do: conn,
      else: Security.error(conn, 404, "the MTA is off on this node ([stack] mta = false)")
  end

  defp mta_part(conn, _opts), do: conn

  defp web(conn), do: conn.assigns.web
  defp config(conn), do: Config.get(web(conn).instance)
  defp directory(conn), do: config(conn).queue.directory

  defp ok(conn, body), do: json(conn, 200, body)

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> put_resp_header("cache-control", "no-store")
    |> send_resp(status, JSON.encode!(body))
  end

  defp queues(nil), do: {:ok, QueueInfo.queues()}

  defp queues(name) do
    case Enum.find(QueueInfo.queues(), &(Atom.to_string(&1) == name)) do
      nil -> {:error, "unknown queue #{inspect(name)}"}
      queue -> {:ok, [queue]}
    end
  end

  defp limit(nil), do: {:ok, nil}

  defp limit(value) when is_binary(value) do
    case Integer.parse(value) do
      {n, ""} when n > 0 -> {:ok, n}
      _ -> {:error, "limit must be a positive integer"}
    end
  end

  defp limit(_value), do: {:error, "limit must be a positive integer"}
end
