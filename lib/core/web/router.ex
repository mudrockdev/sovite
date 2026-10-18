defmodule Sovite.Core.Web.Router do
  @moduledoc false
  # The web server's top router (see Sovite.Core.Web): client check and
  # security headers for every request, then the API, the metrics, and
  # the UI.

  use Plug.Router, copy_opts_to_assign: :web
  use Plug.ErrorHandler

  alias Plug.Conn.Status
  alias Sovite.Core.Web.{API, Pages, Security}

  plug(:telemetry)
  plug(Security, :allowed_client)
  plug(Security, :headers)
  plug(:match)
  plug(:dispatch)

  # Built once, with the instance whose web root it serves.
  @impl Plug
  def init(opts) do
    static =
      Plug.Static.init(
        at: "/",
        from: {Pages, :web_root, [opts.instance]},
        gzip: true,
        brotli: true
      )

    Map.put(opts, :static, static)
  end

  forward("/api", to: API)

  get "/metrics" do
    case Security.call(conn, {:authenticate, :metrics}) do
      %{halted: true} = conn -> conn
      conn -> API.metrics(conn)
    end
  end

  match _ do
    if conn.method in ["GET", "HEAD"],
      do: Pages.serve(conn),
      else: Security.error(conn, 405, "method not allowed")
  end

  @impl Plug.ErrorHandler
  def handle_errors(conn, %{kind: kind, reason: reason}) do
    status = if conn.status in 400..499, do: conn.status, else: 500

    if status == 500 do
      :telemetry.execute([:sovite, :web, :request, :exception], %{}, %{
        method: conn.method,
        path: conn.request_path,
        kind: kind,
        reason: reason
      })
    end

    Security.error(conn, status, Status.reason_phrase(status))
  end

  defp telemetry(conn, _opts) do
    started = System.monotonic_time()

    register_before_send(conn, fn conn ->
      :telemetry.execute(
        [:sovite, :web, :request, :stop],
        %{duration: System.monotonic_time() - started},
        %{
          method: conn.method,
          path: conn.request_path,
          status: conn.status,
          remote_ip: Sovite.Net.normalize(conn.remote_ip)
        }
      )

      conn
    end)
  end
end
