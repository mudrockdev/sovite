defmodule Sovite.AdminAPIFuzzTest do
  # Fuzzing of the admin API (/api, used by sovitectl and the web UI) on
  # a running server: any method, path, query, body, and token gets an
  # answer that is not a server error, and the server keeps running.
  # Not async: the server stores its config globally.
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Sovite.Test.{FakeDNS, Fuzz}

  @moduletag :fuzz
  # `mix fuzz` runs each property many times.
  @moduletag timeout: :infinity
  @moduletag :tmp_dir
  @moduletag :capture_log

  @paths [
    "/api/status",
    "/api/queue?queue=deferred&limit=10",
    "/api/queue/flush",
    "/api/queue/8CxRLslJ8LAQIg",
    "/api/queue/8CxRLslJ8LAQIg/hold",
    "/api/queue/8CxRLslJ8LAQIg/delete",
    "/api/config",
    "/api/config/reload",
    "/api/route?address=alice@example.com&sender=bob@example.net",
    "/api/cluster",
    "/api/cluster/config",
    "/api/cluster/join",
    "/api/ip_pools",
    "/api/trace?id=8CxRLslJ8LAQIg",
    "/api/metrics",
    "/api/nothing"
  ]

  @bodies [
    "",
    ~s({"content": "[server]\\nhostname = \\"x\\""}),
    ~s({"peer": "node@host:4370"}),
    ~s([1, 2, {"a": null}]),
    "not json"
  ]

  setup %{tmp_dir: dir} do
    # The server configures logging globally: put it back, as the
    # operations tests do.
    level = Logger.level()
    handler = :logger.get_handler_config(:default)

    on_exit(fn ->
      Logger.configure(level: level)
      Sovite.Core.Telemetry.detach_logger()

      with {:ok, %{formatter: formatter}} <- handler do
        :logger.update_handler_config(:default, :formatter, formatter)
      end
    end)

    {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)

    path = Path.join(dir, "sovite.toml")

    File.write!(path, """
    [server]
    hostname = "mx.example.org"
    shutdown_timeout = "2s"
    [queue]
    directory = "#{Path.join(dir, "queue")}"
    [database]
    path = "#{Path.join(dir, "sovite.db")}"
    [dns]
    dnssec = "off"
    [domains]
    local = ["example.com"]
    [admin]
    port = #{port}
    token_file = "#{Path.join(dir, "admin.token")}"
    [log]
    directory = "#{Path.join(dir, "log")}"
    [[listener]]
    address = "127.0.0.1"
    port = 0
    # Wrong tokens must not get the fuzzer banned.
    [auth]
    max_failures = 100000
    """)

    start_supervised!(
      {Sovite.Core.Supervisor,
       config_path: path, name: nil, queue_manager: [resolver: FakeDNS.resolver(%{})]}
    )

    token = dir |> Path.join("admin.token") |> File.read!() |> String.trim()
    %{port: port, token: token}
  end

  property "every request gets an answer that is not a server error", %{port: port, token: token} do
    segment =
      Fuzz.input(["8CxRLslJ8LAQIg", "hold", "../../etc/passwd", "%2F", "x"], ["%", "/", "."])

    check all(
            method <- member_of([:get, :post, :put, :delete, :head, :options]),
            path <-
              one_of([
                member_of(@paths),
                map({member_of(@paths), segment}, fn {p, s} ->
                  p <> "/" <> URI.encode(s, &URI.char_unreserved?/1)
                end)
              ]),
            query <-
              one_of([
                constant(""),
                map(
                  Fuzz.input(["a=b&limit=x&queue=nope&id="], ["&", "=", "%"]),
                  &("?" <> URI.encode(&1, fn c -> URI.char_unreserved?(c) or c in ~c"&=" end))
                )
              ]),
            body <- Fuzz.input(@bodies, ["\"", "{", "}", ":"]),
            auth <- member_of([:token, :token, :token, :none, :wrong]),
            max_runs: Fuzz.runs()
          ) do
      status =
        Fuzz.quick(fn -> request(port, method, path <> query, body, auth, token) end, 10_000)

      assert status < 500 or status == 503, "#{method} #{path}#{query}: #{status}"
    end

    assert request(port, :get, "/api/status", "", :token, token) == 200
  end

  defp request(port, method, path, body, auth, token) do
    headers =
      case auth do
        :token -> [{~c"authorization", ~c"Bearer " ++ String.to_charlist(token)}]
        :wrong -> [{~c"authorization", ~c"Bearer wrong-token-wrong-token"}]
        :none -> []
      end

    url = ~c"http://127.0.0.1:#{port}#{path}"

    request =
      if method in [:post, :put],
        do: {url, headers, ~c"application/json", body},
        else: {url, headers}

    case :httpc.request(method, request, [timeout: 5_000], body_format: :binary) do
      {:ok, {{_, status, _}, _headers, _body}} -> status
      {:error, reason} -> flunk("no answer: #{inspect(reason)}")
    end
  end
end
