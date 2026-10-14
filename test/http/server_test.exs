defmodule Sovite.HTTP.ServerTest do
  use ExUnit.Case, async: true

  alias Sovite.HTTP
  alias Sovite.HTTP.Request
  alias Sovite.Test.{Certs, TelemetryForwarder}

  doctest Sovite.HTTP
  doctest Sovite.HTTP.Request

  defp start(handler, opts \\ []) do
    pid =
      start_supervised!(
        {Sovite.Listener,
         id: "http-#{System.unique_integer([:positive])}",
         port: 0,
         ip: {127, 0, 0, 1},
         handler: Sovite.HTTP.Server,
         handler_opts: [handler: handler] ++ opts}
      )

    {:ok, {_ip, port}} = Sovite.Listener.sockname(pid)
    port
  end

  # Sends raw bytes and returns the whole response.
  defp raw(port, data) do
    {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])
    :ok = :gen_tcp.send(socket, data)
    read_all(socket, "")
  end

  defp read_all(socket, acc) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, data} -> read_all(socket, acc <> data)
      {:error, :closed} -> acc
    end
  end

  defp echo(request) do
    HTTP.json(200, %{
      method: request.method,
      path: request.path,
      segments: request.segments,
      query: request.query,
      body: request.body,
      host: Request.header(request, "host"),
      token: Request.bearer_token(request),
      remote_ip: request.remote_ip |> :inet.ntoa() |> List.to_string()
    })
  end

  defp body(response) do
    [_head, body] = :binary.split(response, "\r\n\r\n")
    body
  end

  test "parses requests and sends the handler's response" do
    port = start(&echo/1)

    response =
      raw(
        port,
        "POST /api/queue/a%20b?limit=5&queue=hold HTTP/1.1\r\nHost: localhost\r\n" <>
          "Authorization: Bearer tok\r\nContent-Length: 4\r\n\r\nbody"
      )

    assert response =~ "HTTP/1.1 200 OK\r\n"
    assert response =~ "content-type: application/json\r\n"
    assert response =~ "connection: close\r\n"

    assert JSON.decode!(body(response)) == %{
             "method" => "POST",
             "path" => "/api/queue/a b",
             "segments" => ["api", "queue", "a b"],
             "query" => %{"limit" => "5", "queue" => "hold"},
             "body" => "body",
             "host" => "localhost",
             "token" => "tok",
             "remote_ip" => "127.0.0.1"
           }
  end

  test "HEAD gets the headers without the body" do
    port = start(fn _request -> HTTP.text(200, "hello") end)
    response = raw(port, "HEAD / HTTP/1.1\r\n\r\n")
    assert response =~ "content-length: 5\r\n"
    assert body(response) == ""
  end

  test "answers Expect: 100-continue before reading the body" do
    port = start(&echo/1)
    {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])

    :ok =
      :gen_tcp.send(
        socket,
        "PUT /x HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n"
      )

    assert {:ok, "HTTP/1.1 100 Continue\r\n\r\n"} = :gen_tcp.recv(socket, 0, 5_000)
    :ok = :gen_tcp.send(socket, "ok")
    assert JSON.decode!(body(read_all(socket, "")))["body"] == "ok"
  end

  test "refuses malformed and oversized requests" do
    port = start(&echo/1, max_header: 200, max_body: 10)

    assert raw(port, "GET nope HTTP/1.1\r\n\r\n") =~ "HTTP/1.1 400 "
    assert raw(port, "GET / HTTP/2\r\n\r\n") =~ "HTTP/1.1 400 "
    assert raw(port, "GET /%00 HTTP/1.1\r\n\r\n") =~ "HTTP/1.1 400 "
    assert raw(port, "GET /%FF HTTP/1.1\r\n\r\n") =~ "HTTP/1.1 400 "
    assert raw(port, "GET / HTTP/1.1\r\nBad Header\r\n\r\n") =~ "HTTP/1.1 400 "
    assert raw(port, "GET / HTTP/1.1\r\nX: a\r\n folded\r\n\r\n") =~ "HTTP/1.1 400 "
    assert raw(port, "GET / HTTP/1.1\r\nContent-Length: x\r\n\r\n") =~ "HTTP/1.1 400 "

    assert raw(port, "GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n") =~
             "HTTP/1.1 400 "

    assert raw(port, "POST / HTTP/1.1\r\nContent-Length: 11\r\n\r\n") =~ "HTTP/1.1 413 "
    assert raw(port, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n") =~ "HTTP/1.1 501 "

    assert raw(port, "GET / HTTP/1.1\r\nX: #{String.duplicate("a", 300)}\r\n\r\n") =~
             "HTTP/1.1 431 "

    fields = Enum.map_join(1..101, "", &"X-#{&1}: a\r\n")
    port = start(&echo/1)
    assert raw(port, "GET / HTTP/1.1\r\n#{fields}\r\n") =~ "HTTP/1.1 431 "
  end

  test "a handler that raises gives 500, with telemetry" do
    TelemetryForwarder.attach([[:sovite, :http, :request, :exception]])
    port = start(fn _request -> raise "boom" end)

    assert raw(port, "GET /crash HTTP/1.1\r\n\r\n") =~ "HTTP/1.1 500 "

    assert_receive {:telemetry, [:sovite, :http, :request, :exception], %{duration: _},
                    %{path: "/crash", kind: :error}}
  end

  test "reports each request" do
    TelemetryForwarder.attach([[:sovite, :http, :request, :stop]])
    port = start(fn _request -> HTTP.error(404, "nope") end)
    assert raw(port, "GET /reported HTTP/1.1\r\n\r\n") =~ ~s(HTTP/1.1 404 Not Found)

    assert_receive {:telemetry, [:sovite, :http, :request, :stop], %{duration: _},
                    %{method: "GET", path: "/reported", status: 404}}
  end

  test "drops a request that never ends" do
    port = start(&echo/1, timeout: 100)
    assert raw(port, "GET / HTTP/1.1\r\n") == ""
  end

  test "serves TLS" do
    server = Certs.issue(Certs.ca(), names: ["localhost"])
    tls = fn -> Sovite.TLS.server_options(certs_keys: [Certs.certs_keys(server)]) end
    port = start(fn _request -> HTTP.text(200, "secure") end, tls: tls)

    {:ok, socket} =
      :ssl.connect(~c"127.0.0.1", port, [:binary, active: false, verify: :verify_none], 5_000)

    :ok = :ssl.send(socket, "GET / HTTP/1.1\r\n\r\n")
    {:ok, data} = :ssl.recv(socket, 0, 5_000)
    assert data =~ "HTTP/1.1 200 OK"
  end

  test "reason phrases" do
    assert HTTP.reason(431) == "Request Header Fields Too Large"
    assert HTTP.reason(599) == "Unknown"
  end
end
