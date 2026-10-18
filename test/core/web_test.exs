defmodule Sovite.Core.WebTest do
  # The web server's router, with Plug.Test. Stores a running config.
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias Sovite.Core.{Config, Web}
  alias Sovite.Core.Web.{Pages, Router}
  alias Sovite.Test.TelemetryForwarder

  @moduletag :tmp_dir

  @token "test-token-test-token"
  @local {127, 0, 0, 1}
  @inline "\n  window.start();\n"

  setup %{tmp_dir: dir} do
    web = Path.join(dir, "web")
    File.mkdir_p!(Path.join(web, "_app"))
    File.mkdir_p!(Path.join(web, "about"))
    File.write!(Path.join(web, "index.html"), "<h1>status</h1><script>#{@inline}</script>")
    File.write!(Path.join(web, "about/index.html"), "<h1>about</h1>")
    File.write!(Path.join(web, "_app/app.js"), "1")
    File.write!(Path.join(web, ".secret"), "x")

    penalty = :"web-test-penalty-#{System.unique_integer([:positive])}"

    start_supervised!(
      {Sovite.Abuse.Penalty, name: penalty, max_failures: 2, window: 60_000, ban_time: 60_000}
    )

    instance = make_ref()
    on_exit(fn -> Config.erase(instance) end)

    %{web: web, dir: dir, penalty: penalty, instance: instance}
  end

  defp configure(context, admin \\ "") do
    {:ok, config} =
      Config.parse("""
      [queue]
      directory = "#{Path.join(context.dir, "queue")}"
      [admin]
      web_root = "#{context.web}"
      #{admin}
      """)

    Config.put(config, context.instance)
    context
  end

  defp request(context, method, path, opts \\ []) do
    router_opts =
      Router.init(%{
        instance: context.instance,
        control: nil,
        queue_manager: nil,
        metrics: nil,
        repo: nil,
        penalty: context.penalty,
        token_hash: :crypto.hash(:sha256, @token),
        https: Keyword.get(opts, :https, false)
      })

    conn =
      Enum.reduce(
        Keyword.get(opts, :headers, []),
        conn(method, path) |> Map.put(:remote_ip, Keyword.get(opts, :ip, @local)),
        fn {name, value}, conn -> put_req_header(conn, name, value) end
      )

    Router.call(conn, router_opts)
  end

  defp header(conn, name), do: conn |> get_resp_header(name) |> List.first()

  describe "the UI" do
    setup :configure

    test "serves pages with a policy that allows their inline scripts only", context do
      conn = request(context, :get, "/")
      assert conn.status == 200
      assert conn.resp_body =~ "<h1>status</h1>"
      assert header(conn, "content-type") =~ "text/html"
      assert header(conn, "cache-control") == "no-cache"

      policy = header(conn, "content-security-policy")
      hash = :crypto.hash(:sha256, @inline) |> Base.encode64()
      assert policy =~ "script-src 'self' 'sha256-#{hash}'"
      assert policy =~ "frame-ancestors 'none'"
      refute policy =~ "unsafe-eval"

      assert header(conn, "x-frame-options") == "DENY"
      assert header(conn, "x-content-type-options") == "nosniff"
      assert header(conn, "referrer-policy") == "no-referrer"
      assert header(conn, "cross-origin-opener-policy") == "same-origin"
      assert header(conn, "permissions-policy") =~ "camera=()"
      assert header(conn, "strict-transport-security") == nil
    end

    test "serves files, nested pages, and index.html for app routes", context do
      conn = request(context, :get, "/_app/app.js")
      assert {conn.status, conn.resp_body} == {200, "1"}
      assert header(conn, "content-type") =~ "javascript"

      assert request(context, :get, "/about").resp_body == "<h1>about</h1>"
      assert request(context, :get, "/queue/8CrIr95AD2x90M").resp_body =~ "<h1>status</h1>"
    end

    test "refuses hidden and missing files", context do
      assert request(context, :get, "/.secret").status == 404
      assert request(context, :get, "/_app/missing.js").status == 404
      assert request(context, :get, "/../etc/passwd").status in [400, 404]
      assert request(context, :get, "/a%5C..%5Cb.js").status in [400, 404]
      assert request(context, :put, "/").status == 405
    end

    test "sends HSTS over TLS", context do
      assert request(context, :get, "/", https: true) |> header("strict-transport-security") =~
               "max-age="
    end

    test "answers only allowed clients", context do
      conn = request(context, :get, "/", ip: {192, 0, 2, 1})
      assert conn.status == 403
      assert request(context, :get, "/", ip: {0, 0, 0, 0, 0, 0, 0, 1}).status == 200
      # IPv4-mapped addresses are IPv4.
      assert request(context, :get, "/", ip: {0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 1}).status == 200
    end

    test "a missing build is a 404", context do
      File.rm_rf!(context.web)
      assert request(context, :get, "/").status == 404
    end
  end

  describe "the API" do
    setup :configure

    test "needs the token", context do
      conn = request(context, :get, "/api/status")
      assert conn.status == 401
      assert header(conn, "www-authenticate") =~ "Bearer"
      assert header(conn, "cache-control") == "no-store"
      assert header(conn, "content-security-policy") =~ "default-src 'none'"
      assert JSON.decode!(conn.resp_body) == %{"error" => "a valid token is needed"}

      assert request(context, :get, "/metrics").status == 401
    end

    test "wrong tokens are failed logins, and ban the client", context do
      TelemetryForwarder.attach([[:sovite, :auth, :failure]])
      wrong = [headers: [{"authorization", "Bearer wrong-token-wrong-token"}]]
      right = [headers: [{"authorization", "Bearer " <> @token}]]

      assert request(context, :get, "/api/status", wrong).status == 401

      assert_receive {:telemetry, [:sovite, :auth, :failure], _,
                      %{mechanism: "TOKEN", reason: :invalid_token, remote_ip: @local}}

      assert request(context, :get, "/api/status", wrong).status == 401
      # Banned now, even with the right token.
      assert request(context, :get, "/api/nothing", right).status == 429
      # Other clients are not.
      assert request(context, :get, "/api/nothing", [ip: {127, 0, 0, 2}] ++ right).status == 404
    end

    test "refuses cross-site requests that change something", context do
      auth = {"authorization", "Bearer " <> @token}

      for headers <- [
            [auth, {"origin", "https://evil.example"}],
            [auth, {"sec-fetch-site", "cross-site"}],
            [auth, {"sec-fetch-site", "same-site"}]
          ] do
        assert request(context, :post, "/api/queue/flush", headers: headers).status == 403
      end

      # Same origin, or not from a browser: on to the API.
      same = [auth, {"origin", "http://www.example.com"}, {"sec-fetch-site", "same-origin"}]
      assert request(context, :post, "/api/nothing", headers: same).status == 404
      assert request(context, :post, "/api/nothing", headers: [auth]).status == 404
      assert request(context, :delete, "/api/status", headers: [auth]).status == 405
    end

    test "public metrics need no token", context do
      configure(context, "public_metrics = true")
      # No metrics process in this test.
      assert request(context, :get, "/metrics").status == 404
    end
  end

  test "page policies hash every inline script, not external ones" do
    html = ~s[<script src="/a.js"></script><script type="module">a()</script><script>b()</script>]
    policy = Pages.policy(html)

    for script <- ["a()", "b()"],
        do: assert(policy =~ "'sha256-#{:crypto.hash(:sha256, script) |> Base.encode64()}'")

    assert length(Regex.scan(~r/'sha256-/, policy)) == 2
  end

  test "the token file", %{dir: dir} do
    path = Path.join(dir, "token")
    assert {:ok, token} = Web.token(path)
    assert byte_size(token) >= 32
    assert Bitwise.band(File.stat!(path).mode, 0o777) == 0o600
    assert Web.token(path) == {:ok, token}

    File.write!(path, "short\n")
    assert {:error, _} = Web.token(path)
    assert {:error, _} = Web.token(Path.join([dir, "missing", "token"]))
  end
end
