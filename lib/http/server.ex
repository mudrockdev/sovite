defmodule Sovite.HTTP.Server do
  @moduledoc """
  The `Sovite.Listener` handler of `Sovite.HTTP`. Each connection serves
  one request, then closes (`Connection: close`).

  Requests use the origin form (`GET /path?query HTTP/1.1`). Bodies need
  a `Content-Length`: chunked requests get `501`. `Expect:
  100-continue` is answered before the body is read. `HEAD` gets the
  headers the handler returns for `GET`, without the body.

  Malformed requests get `400`, a header section over `:max_header`
  bytes or 100 fields `431`, and a body over `:max_body` bytes `413`. A
  request not received within `:timeout` of the connection is dropped.
  A handler that raises gives `500`.

  ## Options

    * `:handler` - a 1-arity function given the `Sovite.HTTP.Request`,
      returning a `t:Sovite.HTTP.response/0`. Required.
    * `:tls` - a 0-arity function returning `:ssl` server options, called
      for each connection, so certificates can be reloaded. If it returns
      `nil`, the connection is closed. Defaults to `nil`: plain HTTP.
    * `:max_header` - bytes. Defaults to 16 KiB.
    * `:max_body` - bytes. Defaults to 1 MiB.
    * `:timeout` - milliseconds. Defaults to 10 seconds.

  ## Telemetry

    * `[:sovite, :http, :request, :stop]` - `%{duration}`,
      `%{listener, remote_ip, method, path, status}`. `method` and `path`
      are `nil` for requests that could not be parsed.
    * `[:sovite, :http, :request, :exception]` - `%{duration}`,
      `%{listener, remote_ip, method, path, kind, reason}`: the handler
      raised or exited.
  """

  @behaviour Sovite.Listener.Handler

  alias Sovite.HTTP
  alias Sovite.HTTP.Request

  @max_fields 100

  @impl true
  def start_link(info, opts), do: {:ok, spawn_link(fn -> serve(info, opts) end)}

  defp serve(info, opts) do
    started = System.monotonic_time()
    deadline = System.monotonic_time(:millisecond) + Keyword.get(opts, :timeout, 10_000)

    with {:ok, info} <- Sovite.Listener.handshake(info),
         {:ok, transport} <- transport(info.socket, Keyword.get(opts, :tls), deadline) do
      {request, response} =
        case read_request(transport, info, opts, deadline) do
          {:ok, request} -> {request, call(opts, request, info, started)}
          {:error, status} -> {nil, status && HTTP.text(status, HTTP.reason(status) <> "\n")}
        end

      if response do
        _ = send_data(transport, encode(response, request))
        stop_event(info, request, elem(response, 0), started)
      end

      close(transport)
    end

    :gen_tcp.close(info.socket)
  end

  defp transport(socket, nil, _deadline), do: {:ok, {:gen_tcp, socket}}

  defp transport(socket, tls, deadline) when is_function(tls, 0) do
    with ssl_opts when is_list(ssl_opts) <- tls.(),
         {:ok, ssl} <-
           :ssl.handshake(socket, ssl_opts ++ [mode: :binary, active: false], remaining(deadline)) do
      {:ok, {:ssl, ssl}}
    else
      _ -> :error
    end
  catch
    :exit, _reason -> :error
  end

  defp call(opts, request, info, started) do
    case Keyword.fetch!(opts, :handler).(request) do
      {status, headers, _body} = response
      when is_integer(status) and status in 100..599 and is_list(headers) ->
        response

      other ->
        raise "HTTP handler returned #{inspect(other)}"
    end
  catch
    kind, reason ->
      :telemetry.execute(
        [:sovite, :http, :request, :exception],
        %{duration: System.monotonic_time() - started},
        Map.merge(metadata(info, request), %{kind: kind, reason: reason})
      )

      HTTP.text(500, "Internal Server Error\n")
  end

  defp stop_event(info, request, status, started) do
    :telemetry.execute(
      [:sovite, :http, :request, :stop],
      %{duration: System.monotonic_time() - started},
      Map.put(metadata(info, request), :status, status)
    )
  end

  defp metadata(info, request) do
    %{
      listener: info.listener,
      remote_ip: info.remote_ip,
      method: request && request.method,
      path: request && request.path
    }
  end

  ## Reading

  # {:error, nil} drops the connection without a response.
  defp read_request(transport, info, opts, deadline) do
    max_header = Keyword.get(opts, :max_header, 16 * 1024)

    with {:ok, head, rest} <- read_head(transport, "", max_header, deadline),
         {:ok, request} <- parse_head(head),
         {:ok, length} <- content_length(request, Keyword.get(opts, :max_body, 1024 * 1024)),
         :ok <- continue(transport, request, length, rest),
         {:ok, body} <- read_body(transport, rest, length, deadline) do
      {:ok, %{request | body: body, remote_ip: info.remote_ip}}
    end
  end

  defp read_head(transport, acc, max, deadline) do
    case :binary.match(acc, "\r\n\r\n") do
      {index, 4} when index <= max ->
        <<head::binary-size(^index), _::binary-size(4), rest::binary>> = acc
        {:ok, head, rest}

      _ when byte_size(acc) > max + 4 ->
        {:error, 431}

      _ ->
        case recv(transport, deadline) do
          {:ok, data} -> read_head(transport, acc <> data, max, deadline)
          {:error, _} -> {:error, nil}
        end
    end
  end

  defp read_body(_transport, rest, length, _deadline) when byte_size(rest) >= length,
    do: {:ok, binary_part(rest, 0, length)}

  defp read_body(transport, rest, length, deadline) do
    case recv(transport, deadline) do
      {:ok, data} -> read_body(transport, rest <> data, length, deadline)
      {:error, _} -> {:error, nil}
    end
  end

  defp parse_head(head) do
    [line | field_lines] = String.split(head, "\r\n")

    with [method, target, "HTTP/1." <> minor] when minor in ["0", "1"] <-
           String.split(line, " "),
         true <- String.match?(method, ~r/\A[A-Z]{1,16}\z/),
         {:ok, path, query} <- parse_target(target),
         {:ok, headers} <- parse_fields(field_lines) do
      {:ok,
       %Request{
         method: method,
         path: path,
         segments: String.split(path, "/", trim: true),
         query: query,
         headers: headers
       }}
    else
      {:error, status} -> {:error, status}
      _ -> {:error, 400}
    end
  end

  defp parse_target("/" <> _ = target) do
    {path, query} =
      case :binary.split(target, "?") do
        [path] -> {path, ""}
        [path, query] -> {path, query}
      end

    path = URI.decode(path)

    if String.valid?(path) and not String.contains?(path, <<0>>),
      do: {:ok, path, URI.decode_query(query)},
      else: :error
  rescue
    ArgumentError -> :error
  end

  defp parse_target(_target), do: :error

  defp parse_fields(lines) when length(lines) > @max_fields, do: {:error, 431}

  defp parse_fields(lines) do
    Enum.reduce_while(lines, {:ok, []}, fn line, {:ok, acc} ->
      with [name, value] <- :binary.split(line, ":"),
           true <- String.match?(name, ~r/\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\z/) do
        {:cont, {:ok, [{String.downcase(name, :ascii), String.trim(value)} | acc]}}
      else
        # Including obsolete line folding (RFC 9112 §5.2).
        _ -> {:halt, {:error, 400}}
      end
    end)
    |> case do
      {:ok, headers} -> {:ok, Enum.reverse(headers)}
      error -> error
    end
  end

  defp content_length(request, max) do
    lengths = for {"content-length", value} <- request.headers, do: value

    cond do
      Request.header(request, "transfer-encoding") != nil ->
        {:error, 501}

      lengths == [] ->
        {:ok, 0}

      Enum.uniq(lengths) != [hd(lengths)] or not String.match?(hd(lengths), ~r/\A[0-9]{1,15}\z/) ->
        {:error, 400}

      String.to_integer(hd(lengths)) > max ->
        {:error, 413}

      true ->
        {:ok, String.to_integer(hd(lengths))}
    end
  end

  defp continue(transport, request, length, rest) do
    expect = Request.header(request, "expect")

    if expect != nil and String.downcase(expect, :ascii) == "100-continue" and
         byte_size(rest) < length do
      _ = send_data(transport, "HTTP/1.1 100 Continue\r\n\r\n")
    end

    :ok
  end

  ## Writing

  defp encode({status, headers, body}, request) do
    length = IO.iodata_length(body)
    body = if request && request.method == "HEAD", do: "", else: body

    [
      "HTTP/1.1 #{status} #{HTTP.reason(status)}\r\n",
      Enum.map(headers, fn {name, value} -> [name, ": ", value, "\r\n"] end),
      "content-length: #{length}\r\n",
      "connection: close\r\n\r\n",
      body
    ]
  end

  defp recv({:gen_tcp, socket}, deadline), do: :gen_tcp.recv(socket, 0, remaining(deadline))
  defp recv({:ssl, socket}, deadline), do: :ssl.recv(socket, 0, remaining(deadline))

  defp send_data({:gen_tcp, socket}, data), do: :gen_tcp.send(socket, data)
  defp send_data({:ssl, socket}, data), do: :ssl.send(socket, data)

  defp close({:gen_tcp, _socket}), do: :ok
  defp close({:ssl, socket}), do: :ssl.close(socket)

  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)
end
