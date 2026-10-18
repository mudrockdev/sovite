defmodule Sovite.Core.CLI.API do
  @moduledoc false
  # A client of the admin API (Sovite.Core.Web.API), for the sovitectl
  # commands that act on the running MTA. The address and the token
  # come from the config file.

  alias Sovite.Core.Web

  @timeout 60_000

  @doc """
  Sends a request. Returns `{:ok, status, body}` with the decoded JSON
  body, or `{:error, text}`.
  """
  def request(config, method, path, body \\ %{}) do
    admin = config.admin

    with true <- admin.enabled || {:error, "the admin API is disabled ([admin] enabled = false)"},
         {:ok, token} <- read_token(admin.token_file) do
      {:ok, _} = Application.ensure_all_started(:inets)
      {:ok, _} = Application.ensure_all_started(:ssl)

      scheme = if admin.tls, do: "https", else: "http"
      host = host(admin.address)
      url = ~c"#{scheme}://#{host}:#{admin.port}#{path}"
      headers = [{~c"authorization", ~c"Bearer " ++ String.to_charlist(token)}]

      request =
        if method == :post,
          do: {url, headers, ~c"application/json", JSON.encode!(body)},
          else: {url, headers}

      http_opts = [timeout: @timeout, connect_timeout: 5_000, ssl: ssl_opts(config)]

      case :httpc.request(method, request, http_opts, body_format: :binary) do
        {:ok, {{_version, status, _reason}, _headers, body}} ->
          {:ok, status, decode(body)}

        {:error, {:failed_connect, _}} ->
          {:error, "sovite is not running, or not on #{host}:#{admin.port}"}

        {:error, reason} ->
          {:error, "admin API request failed: #{inspect(reason)}"}
      end
    end
  end

  # The CLI runs on the same host: an admin listener on a local
  # address is not verified, as its certificate names the mail server.
  defp ssl_opts(config) do
    if loopback?(config.admin.address),
      do: [verify: :verify_none],
      else:
        Sovite.TLS.client_options(
          verify: :peer,
          hostname: config.server.hostname
        )
  end

  defp loopback?({127, _, _, _}), do: true
  defp loopback?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  defp loopback?(_ip), do: false

  # The token is created by the server, so it must already exist.
  defp read_token(path) do
    if File.exists?(path),
      do: Web.token(path) |> token_error(path),
      else: {:error, "#{path} does not exist: is sovite running?"}
  end

  defp token_error({:ok, token}, _path), do: {:ok, token}
  defp token_error({:error, text}, path), do: {:error, "cannot read #{path}: #{text}"}

  defp host({0, 0, 0, 0}), do: "127.0.0.1"
  defp host({0, 0, 0, 0, 0, 0, 0, 0}), do: "[::1]"
  defp host(ip) when tuple_size(ip) == 8, do: "[#{:inet.ntoa(ip)}]"
  defp host(ip), do: List.to_string(:inet.ntoa(ip))

  defp decode(body) do
    case JSON.decode(body) do
      {:ok, decoded} -> decoded
      {:error, _} -> body
    end
  end
end
