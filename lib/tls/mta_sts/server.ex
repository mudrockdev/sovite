defmodule Sovite.TLS.MTASTS.Server do
  @moduledoc """
  Serves MTA-STS policies (RFC 8461 §3.3): a `Sovite.Listener` handler
  for `https://mta-sts.<domain>/.well-known/mta-sts.txt`, with TLS on
  the accepted connection.

      {Sovite.Listener,
       port: 443,
       handler: Sovite.TLS.MTASTS.Server,
       handler_opts: [
         tls: fn -> Sovite.TLS.server_options(certs_keys: certs_keys, sni_fun: sni_fun) end,
         policy: fn domain -> Map.fetch(policies, domain) end
       ]}

  The domain comes from the `Host:` header, lower-cased and without a
  port, which must be `mta-sts.<domain>`. `GET` and `HEAD` of the policy
  path get `200` with the policy as `text/plain`; other paths and
  unknown domains get `404`, and other methods `405`. Each connection
  serves one request. Requests larger than 8 KiB, or not received within
  10 seconds of the connection, are dropped.

  ## Options

    * `:tls` - a 0-arity function returning the `:ssl` server options,
      such as `Sovite.TLS.server_options/1` gives. It is called for each
      connection, so certificates can be reloaded. If it returns `nil`,
      the connection is closed. Required.
    * `:policy` - a 1-arity function given the domain, returning
      `{:ok, text}` with the policy body (see
      `Sovite.TLS.MTASTS.policy_text/3`) or `:error`. Required.

  ## Telemetry

    * `[:sovite, :tls, :mta_sts, :served]` - `%{}`, `%{domain, status}`.
      `domain` is `nil` if the request named none.
  """

  @behaviour Sovite.Listener.Handler

  @path "/.well-known/mta-sts.txt"
  @max_request 8192
  @timeout 10_000

  @reasons %{200 => "OK", 400 => "Bad Request", 404 => "Not Found", 405 => "Method Not Allowed"}

  @impl true
  def start_link(info, opts), do: {:ok, spawn_link(fn -> serve(info, opts) end)}

  defp serve(info, opts) do
    deadline = System.monotonic_time(:millisecond) + @timeout

    with {:ok, _info} <- Sovite.Listener.handshake(info),
         ssl_opts when is_list(ssl_opts) <- Keyword.fetch!(opts, :tls).(),
         {:ok, socket} <- handshake(info.socket, ssl_opts, deadline) do
      with {:ok, request} <- read(socket, "", deadline) do
        {status, domain, response} = respond(request, Keyword.fetch!(opts, :policy))
        _ = :ssl.send(socket, response)

        :telemetry.execute([:sovite, :tls, :mta_sts, :served], %{}, %{
          domain: domain,
          status: status
        })
      end

      :ssl.close(socket)
    end

    :gen_tcp.close(info.socket)
  end

  defp handshake(socket, ssl_opts, deadline) do
    :ssl.handshake(socket, ssl_opts ++ [mode: :binary, active: false], remaining(deadline))
  catch
    :exit, reason -> {:error, reason}
  end

  defp read(socket, acc, deadline) do
    cond do
      String.contains?(acc, "\r\n\r\n") or String.contains?(acc, "\n\n") ->
        {:ok, acc}

      byte_size(acc) > @max_request ->
        :error

      true ->
        case :ssl.recv(socket, 0, remaining(deadline)) do
          {:ok, data} -> read(socket, acc <> data, deadline)
          {:error, _} -> :error
        end
    end
  end

  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)

  defp respond(request, policy) do
    [head | _] = :binary.split(request, ["\r\n\r\n", "\n\n"])
    [line | header_lines] = String.split(head, ["\r\n", "\n"])

    case String.split(line, " ") do
      [method, target, "HTTP/1." <> _] ->
        domain = domain(header_lines)
        {status, body} = lookup(method, target, domain, policy)
        {status, domain, response(status, method, body)}

      _ ->
        {400, nil, response(400, "GET", "Bad Request\n")}
    end
  end

  defp lookup(method, @path, domain, policy) when method in ["GET", "HEAD"] do
    with domain when is_binary(domain) <- domain,
         {:ok, text} <- policy.(domain) do
      {200, text}
    else
      _ -> {404, "Not Found\n"}
    end
  end

  defp lookup(_method, @path, _domain, _policy), do: {405, "Method Not Allowed\n"}
  defp lookup(_method, _target, _domain, _policy), do: {404, "Not Found\n"}

  # The Host header names mta-sts.<domain>, perhaps with a port.
  defp domain(header_lines) do
    case Enum.find_value(header_lines, &host/1) do
      nil -> nil
      host -> host |> :binary.split(":") |> hd() |> policy_domain()
    end
  end

  defp host(line) do
    case :binary.split(line, ":") do
      [name, value] ->
        if String.downcase(String.trim(name), :ascii) == "host", do: String.trim(value)

      _ ->
        nil
    end
  end

  defp policy_domain(host) do
    case host |> String.downcase(:ascii) |> String.trim_trailing(".") do
      "mta-sts." <> domain -> if Sovite.Validators.domain?(domain), do: domain
      _ -> nil
    end
  end

  defp response(status, method, body) do
    allow = if status == 405, do: ["Allow: GET, HEAD\r\n"], else: []
    content = if method == "HEAD", do: "", else: body

    [
      "HTTP/1.1 #{status} #{Map.fetch!(@reasons, status)}\r\n",
      "Content-Type: text/plain\r\n",
      "Content-Length: #{byte_size(body)}\r\n",
      allow,
      "Connection: close\r\n\r\n",
      content
    ]
  end
end
