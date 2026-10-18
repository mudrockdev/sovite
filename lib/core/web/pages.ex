defmodule Sovite.Core.Web.Pages do
  @moduledoc false
  # Serves the UI (see Sovite.Core.Web). Its pages are HTML files from a
  # static build: a request for a page that does not exist gets
  # index.html, for the paths the app routes itself. Each page gets a
  # Content-Security-Policy that allows its inline scripts by their
  # SHA-256 hash (SvelteKit starts the app from one), and nothing else
  # inline. Other files are served by Plug.Static.

  import Plug.Conn

  alias Sovite.Core.Config
  alias Sovite.Core.Web.Security

  @inline_script ~r/<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)<\/script>/s

  @doc "Serves a GET or HEAD request for the UI."
  def serve(conn) do
    case decode(conn.path_info) do
      {:ok, segments} ->
        cond do
          Enum.any?(segments, &unsafe?/1) -> Security.error(conn, 404, "not found")
          page?(segments) -> page(conn, segments)
          true -> asset(conn)
        end

      :error ->
        Security.error(conn, 400, "invalid path")
    end
  end

  # Path segments come percent-encoded.
  defp decode(segments) do
    segments = Enum.map(segments, &URI.decode/1)
    if Enum.all?(segments, &String.valid?/1), do: {:ok, segments}, else: :error
  rescue
    ArgumentError -> :error
  end

  # Hidden files, and anything Plug.Static would refuse too.
  defp unsafe?(segment),
    do: String.starts_with?(segment, ".") or String.contains?(segment, ["/", "\\", <<0>>, ":"])

  defp page?([]), do: true
  defp page?(segments), do: Path.extname(List.last(segments)) in ["", ".html"]

  defp asset(conn) do
    case Plug.Static.call(conn, conn.assigns.web.static) do
      %{halted: true} = conn -> conn
      conn -> Security.error(conn, 404, "not found")
    end
  end

  defp page(conn, segments) do
    root = web_root(conn.assigns.web.instance)
    path = Path.join([root | segments])

    candidates =
      if Path.extname(path) == ".html",
        do: [path],
        else: [Path.join(path, "index.html"), path <> ".html", Path.join(root, "index.html")]

    case Enum.find_value(candidates, &read/1) do
      nil -> Security.error(conn, 404, "not found")
      html -> send_page(conn, html)
    end
  end

  defp read(path) do
    case File.read(path) do
      {:ok, html} -> html
      {:error, _} -> nil
    end
  end

  defp send_page(conn, html) do
    conn
    |> put_resp_content_type("text/html")
    |> put_resp_header("cache-control", "no-cache")
    |> put_resp_header("content-security-policy", policy(html))
    |> send_resp(200, html)
  end

  @doc false
  # The UI files of a running instance; Plug.Static calls it too.
  def web_root(instance) do
    case Config.get(instance) do
      %{admin: %{web_root: root}} when is_binary(root) -> root
      _ -> Application.app_dir(:sovite, "priv/web")
    end
  end

  @doc false
  # The policy of a page: its own files only, its inline scripts by
  # hash. Styles may be inline: Svelte sets style attributes.
  def policy(html) do
    hashes =
      for [_, script] <- Regex.scan(@inline_script, html), script != "" do
        "'sha256-#{:crypto.hash(:sha256, script) |> Base.encode64()}'"
      end

    Enum.join(
      [
        "default-src 'self'",
        Enum.join(["script-src 'self'" | Enum.uniq(hashes)], " "),
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'"
      ],
      "; "
    )
  end
end
