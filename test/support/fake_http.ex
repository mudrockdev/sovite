defmodule Sovite.Test.FakeHTTP do
  @moduledoc """
  A minimal HTTP/1.1 server for tests. Each request is passed to the
  handler function as `%{method, path, headers, body}` (header names
  lower-cased); it returns `{status, headers, body}`. One request per
  connection.

      {:ok, http} = FakeHTTP.start_link(fn %{path: "/x"} -> {200, [], "ok"} end)
      url = FakeHTTP.url(http, "/x")
  """

  use GenServer

  def start_link(handler, opts \\ []), do: GenServer.start_link(__MODULE__, {handler, opts})

  def port(server), do: GenServer.call(server, :port)
  def url(server, path), do: "http://127.0.0.1:#{port(server)}#{path}"

  @impl true
  def init({handler, opts}) do
    {:ok, listen} =
      :gen_tcp.listen(Keyword.get(opts, :port, 0), [
        :binary,
        ip: {127, 0, 0, 1},
        active: false,
        reuseaddr: true
      ])

    {:ok, port} = :inet.port(listen)
    spawn_link(fn -> accept(listen, handler) end)
    {:ok, %{port: port}}
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, state.port, state}

  defp accept(listen, handler) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        pid = spawn(fn -> receive(do: (:go -> serve(socket, handler))) end)
        :gen_tcp.controlling_process(socket, pid)
        send(pid, :go)
        accept(listen, handler)

      _ ->
        :ok
    end
  end

  defp serve(socket, handler) do
    with {:ok, head, rest} <- read_head(socket, ""),
         [request_line | header_lines] <- String.split(head, "\r\n"),
         [method, path, _version] <- String.split(request_line, " ") do
      headers =
        for line <- header_lines, [name, value] = String.split(line, ":", parts: 2) do
          {String.downcase(name), String.trim(value)}
        end

      length =
        headers |> List.keyfind("content-length", 0, {nil, "0"}) |> elem(1) |> String.to_integer()

      body = read_body(socket, rest, length)

      {status, resp_headers, resp_body} =
        handler.(%{method: method, path: path, headers: headers, body: body})

      head =
        [
          "HTTP/1.1 #{status} X\r\n",
          "content-length: #{byte_size(resp_body)}\r\n",
          "connection: close\r\n"
        ] ++
          Enum.map(resp_headers, fn {k, v} -> "#{k}: #{v}\r\n" end)

      :gen_tcp.send(socket, [head, "\r\n", resp_body])
    end

    :gen_tcp.close(socket)
  end

  defp read_head(socket, acc) do
    case :binary.split(acc, "\r\n\r\n") do
      [head, rest] ->
        {:ok, head, rest}

      [_] ->
        case :gen_tcp.recv(socket, 0, 5_000) do
          {:ok, data} -> read_head(socket, acc <> data)
          error -> error
        end
    end
  end

  defp read_body(_socket, acc, length) when byte_size(acc) >= length, do: acc

  defp read_body(socket, acc, length) do
    {:ok, data} = :gen_tcp.recv(socket, 0, 5_000)
    read_body(socket, acc <> data, length)
  end
end
