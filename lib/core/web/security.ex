defmodule Sovite.Core.Web.Security do
  @moduledoc false
  # The web server's protections (see "Security" in Sovite.Core.Web), as
  # a plug: `plug Security, :allowed_client`, `:headers`, `:same_origin`,
  # and `{:authenticate, :api | :metrics}`. They read the instance's
  # current config, so reloads apply to the next request.

  @behaviour Plug

  import Plug.Conn

  alias Sovite.Abuse.Penalty
  alias Sovite.Core.Config

  # The UI's pages get their own policy, with the hashes of their inline
  # scripts (Sovite.Core.Web.Pages).
  @api_policy "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

  @headers [
    {"x-content-type-options", "nosniff"},
    {"x-frame-options", "DENY"},
    {"referrer-policy", "no-referrer"},
    {"cross-origin-opener-policy", "same-origin"},
    {"cross-origin-resource-policy", "same-origin"},
    {"permissions-policy",
     "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"},
    {"content-security-policy", @api_policy}
  ]

  @impl true
  def init(check), do: check

  @impl true
  def call(conn, :allowed_client) do
    %{admin: admin} = config(conn)

    if Sovite.Net.in_networks?(Sovite.Net.normalize(conn.remote_ip), admin.allowed_networks),
      do: conn,
      else: error(conn, 403, "not allowed from this address")
  end

  def call(conn, :headers) do
    conn = merge_resp_headers(conn, @headers)

    if conn.assigns.web.https,
      do: put_resp_header(conn, "strict-transport-security", "max-age=31536000"),
      else: conn
  end

  # Browsers say where a request comes from: one from another site must
  # not change anything here.
  def call(conn, :same_origin) do
    if conn.method in ["GET", "HEAD"] or same_origin?(conn),
      do: conn,
      else: error(conn, 403, "cross-site requests are not allowed")
  end

  def call(conn, {:authenticate, kind}) do
    web = conn.assigns.web
    ip = Sovite.Net.normalize(conn.remote_ip)

    cond do
      kind == :metrics and config(conn).admin.public_metrics -> conn
      Penalty.banned?(web.penalty, ip) -> error(conn, 429, "too many failed logins")
      true -> check_token(conn, web, ip)
    end
  end

  defp check_token(conn, web, ip) do
    case bearer_token(conn) do
      nil ->
        unauthorized(conn)

      token ->
        if :crypto.hash_equals(:crypto.hash(:sha256, token), web.token_hash) do
          conn
        else
          failed_login(web, ip)
          unauthorized(conn)
        end
    end
  end

  defp failed_login(web, ip) do
    :telemetry.execute([:sovite, :auth, :failure], %{}, %{
      session_id: nil,
      remote_ip: ip,
      mechanism: "TOKEN",
      username: nil,
      reason: :invalid_token
    })

    _ = Penalty.failure(web.penalty, ip)
    :ok
  end

  defp unauthorized(conn) do
    conn
    |> put_resp_header("www-authenticate", ~s(Bearer realm="sovite"))
    |> error(401, "a valid token is needed")
  end

  defp bearer_token(conn) do
    with [value | _] <- get_req_header(conn, "authorization"),
         [scheme, token] <- String.split(value, " ", parts: 2, trim: true),
         "bearer" <- String.downcase(scheme, :ascii) do
      String.trim(token)
    else
      _ -> nil
    end
  end

  defp same_origin?(conn) do
    site = conn |> get_req_header("sec-fetch-site") |> List.first()

    origin_ok =
      case get_req_header(conn, "origin") do
        [] -> true
        [origin | _] -> origin == "#{conn.scheme}://#{host(conn)}"
      end

    site in [nil, "same-origin", "none"] and origin_ok
  end

  defp host(conn) do
    case get_req_header(conn, "host") do
      [host | _] -> host
      [] -> conn.host
    end
  end

  defp config(conn), do: Config.get(conn.assigns.web.instance)

  @doc "Sends a JSON error and halts."
  def error(conn, status, message) do
    conn
    |> put_resp_content_type("application/json")
    |> put_resp_header("cache-control", "no-store")
    |> send_resp(status, JSON.encode!(%{error: message}))
    |> halt()
  end
end
