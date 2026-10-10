defmodule Sovite.TLS.MTASTSTest do
  use ExUnit.Case, async: true

  alias Sovite.Test.{Certs, FakeDNS}
  alias Sovite.TLS.MTASTS
  alias Sovite.TLS.MTASTS.Policy

  doctest MTASTS

  setup_all do
    ca = Certs.ca()

    %{
      ca: ca,
      cert: Certs.issue(ca, names: ["mta-sts.example.com"]),
      other: Certs.issue(ca, names: ["mta-sts.example.org"])
    }
  end

  @policy "version: STSv1\r\nmode: enforce\r\nmx: mx1.example.com\r\nmx: *.example.net\r\nmax_age: 86400\r\n"

  describe "parse_record/1" do
    test "returns the id of the one STSv1 record" do
      assert MTASTS.parse_record(["v=STSv1; id=20260101T000000"]) == {:ok, "20260101T000000"}
      assert MTASTS.parse_record(["v=STSv1;id=abc;"]) == {:ok, "abc"}
      assert MTASTS.parse_record(["v=STSv1 ;\tid=abc ; "]) == {:ok, "abc"}
      assert MTASTS.parse_record(["v=spf1 -all", "v=STSv1; id=1"]) == {:ok, "1"}
    end

    test "ignores unknown fields" do
      assert MTASTS.parse_record(["v=STSv1; ext_1=a.b-c; id=x1; other=!"]) == {:ok, "x1"}
    end

    test "needs exactly one record" do
      assert MTASTS.parse_record([]) == {:error, :no_record}
      assert MTASTS.parse_record(["v=spf1 -all", "V=STSV1; id=1"]) == {:error, :no_record}

      assert MTASTS.parse_record(["v=STSv1; id=1", "v=STSv1; id=2"]) ==
               {:error, :multiple_records}
    end

    test "rejects invalid records" do
      for txt <- [
            "v=STSv1",
            "v=STSv1;",
            "v=STSv1; ext=1",
            "v=STSv1; id=",
            "v=STSv1; id=has-dash",
            "v=STSv1; id=" <> String.duplicate("a", 33),
            "v=STSv1; id=1; id=2",
            "v=STSv1; id=1; v=STSv1",
            "v=STSv1; id=1;; ext=2",
            "v=STSv1; id=1; garbage",
            "v=STSv1; id = 1",
            "v=STSv10; id=1",
            "v=STSv1 id=1"
          ] do
        assert MTASTS.parse_record([txt]) == {:error, :invalid_record}, txt
      end
    end

    test "accepts the longest id" do
      id = String.duplicate("a", 32)
      assert MTASTS.parse_record(["v=STSv1; id=" <> id]) == {:ok, id}
    end
  end

  describe "discover/2" do
    test "looks up _mta-sts.<domain>" do
      resolver = FakeDNS.resolver(%{{"_mta-sts.example.com", :txt} => ["v=STSv1; id=abc"]})
      assert MTASTS.discover(resolver, "example.com") == {:ok, "abc"}
      assert MTASTS.discover(resolver, "example.com.") == {:ok, "abc"}
    end

    test "treats NXDOMAIN and NODATA as no record" do
      resolver = FakeDNS.resolver(%{{"_mta-sts.example.com", :a} => [{192, 0, 2, 1}]})
      assert MTASTS.discover(resolver, "example.com") == {:error, :no_record}
      assert MTASTS.discover(resolver, "example.org") == {:error, :no_record}
    end

    test "reports other DNS errors" do
      resolver = FakeDNS.resolver(%{{"_mta-sts.example.com", :txt} => {:error, :servfail}})
      assert MTASTS.discover(resolver, "example.com") == {:error, {:dns, :servfail}}
    end

    test "passes on record errors" do
      resolver =
        FakeDNS.resolver(%{
          {"_mta-sts.example.com", :txt} => ["v=STSv1; id=1", "v=STSv1; id=2"],
          {"_mta-sts.example.org", :txt} => ["v=STSv1; id=-"]
        })

      assert MTASTS.discover(resolver, "example.com") == {:error, :multiple_records}
      assert MTASTS.discover(resolver, "example.org") == {:error, :invalid_record}
    end
  end

  describe "parse_policy/1" do
    test "parses every mode" do
      assert {:ok, policy} = MTASTS.parse_policy(@policy)

      assert policy == %Policy{
               mode: :enforce,
               mx: ["mx1.example.com", "*.example.net"],
               max_age: 86_400,
               text: @policy
             }

      assert {:ok, %Policy{mode: :testing}} =
               MTASTS.parse_policy(
                 "version: STSv1\nmode: testing\nmx: mx.example.com\nmax_age: 0"
               )

      assert {:ok, %Policy{mode: :none, mx: []}} =
               MTASTS.parse_policy("version: STSv1\nmode: none\nmax_age: 0\n")
    end

    test "accepts LF and CRLF, whitespace, blank lines, unknown keys, and any order" do
      text =
        "\nmax_age:604800  \r\n  mx :  MX.Example.COM\t\n\nfuture_key: some value\n" <>
          "mode: testing\r\nversion: STSv1\n"

      assert {:ok, policy} = MTASTS.parse_policy(text)
      assert {policy.mode, policy.mx, policy.max_age} == {:testing, ["mx.example.com"], 604_800}
    end

    test "keeps the first of a repeated key other than mx" do
      text =
        "version: STSv1\nmode: testing\nmode: enforce\nmx: a.example\nmax_age: 1\nmax_age: 2\n"

      assert {:ok, %Policy{mode: :testing, max_age: 1}} = MTASTS.parse_policy(text)
    end

    test "caps max_age at 31557600" do
      text = "version: STSv1\nmode: none\nmax_age: 9999999999\n"
      assert {:ok, %Policy{max_age: 31_557_600}} = MTASTS.parse_policy(text)
      text = "version: STSv1\nmode: none\nmax_age: 31557600\n"
      assert {:ok, %Policy{max_age: 31_557_600}} = MTASTS.parse_policy(text)
    end

    test "requires version, mode, max_age, and mx" do
      assert MTASTS.parse_policy("mode: enforce\nmx: a.example\nmax_age: 1") ==
               {:error, :missing_version}

      assert MTASTS.parse_policy("version: STSv1\nmx: a.example\nmax_age: 1") ==
               {:error, :missing_mode}

      assert MTASTS.parse_policy("version: STSv1\nmode: enforce\nmx: a.example") ==
               {:error, :missing_max_age}

      assert MTASTS.parse_policy("version: STSv1\nmode: enforce\nmax_age: 1") ==
               {:error, :missing_mx}

      assert MTASTS.parse_policy("version: STSv1\nmode: testing\nmax_age: 1") ==
               {:error, :missing_mx}

      assert MTASTS.parse_policy("") == {:error, :missing_version}
    end

    test "rejects invalid values" do
      base = "mx: a.example\nmax_age: 1\n"

      assert MTASTS.parse_policy("version: STSv2\nmode: enforce\n" <> base) ==
               {:error, {:invalid_version, "STSv2"}}

      assert MTASTS.parse_policy("version: STSv1\nmode: Enforce\n" <> base) ==
               {:error, {:invalid_mode, "Enforce"}}

      assert MTASTS.parse_policy("version: STSv1\nmode: reject\n" <> base) ==
               {:error, {:invalid_mode, "reject"}}

      for age <- ["-1", "1.5", "", "12345678901", "1d"] do
        text = "version: STSv1\nmode: none\nmax_age: #{age}\n"
        assert MTASTS.parse_policy(text) == {:error, {:invalid_max_age, age}}
      end
    end

    test "rejects invalid mx patterns" do
      for mx <- [
            "*",
            "*.",
            "a.*.example",
            "**.example",
            "bad_host.example",
            "192.0.2.1",
            "",
            ".a.example",
            "a..example"
          ] do
        text = "version: STSv1\nmode: enforce\nmx: ok.example\nmx: #{mx}\nmax_age: 1\n"
        assert MTASTS.parse_policy(text) == {:error, {:invalid_mx, mx}}, mx
      end
    end

    test "rejects lines that are not key: value" do
      assert MTASTS.parse_policy("version: STSv1\nmode enforce\n") == {:error, {:invalid_line, 2}}
      assert MTASTS.parse_policy("version: STSv1\n: x\n") == {:error, {:invalid_line, 2}}
      assert MTASTS.parse_policy(<<"version: STSv1\n", 0xFF>>) == {:error, :invalid_encoding}
    end
  end

  describe "match?/2" do
    setup do
      %{
        policy: %Policy{
          mode: :enforce,
          mx: ["mx.example.com", "*.example.net"],
          max_age: 1,
          text: ""
        }
      }
    end

    test "matches exact names case-insensitively, ignoring a trailing dot", %{policy: policy} do
      assert MTASTS.match?(policy, "mx.example.com")
      assert MTASTS.match?(policy, "MX.Example.COM.")
      refute MTASTS.match?(policy, "mx2.example.com")
      refute MTASTS.match?(policy, "a.mx.example.com")
      refute MTASTS.match?(policy, "example.com")
    end

    test "a wildcard matches exactly one leftmost label", %{policy: policy} do
      assert MTASTS.match?(policy, "mx1.example.net")
      assert MTASTS.match?(policy, "MX1.EXAMPLE.NET.")
      refute MTASTS.match?(policy, "example.net")
      refute MTASTS.match?(policy, "a.b.example.net")
      refute MTASTS.match?(policy, ".example.net")
      refute MTASTS.match?(policy, "mx1.example.net.evil")
      refute MTASTS.match?(policy, "mx1example.net")
    end

    test "matches nothing without patterns" do
      refute MTASTS.match?(%Policy{mode: :none, mx: [], max_age: 0, text: ""}, "mx.example.com")
    end
  end

  describe "policy_text/3 and policy_id/1" do
    test "build a policy that parses back" do
      text = MTASTS.policy_text(:enforce, ["mx1.example.com", "*.example.net"], 604_800)
      assert String.starts_with?(text, "version: STSv1\r\n")
      assert {:ok, policy} = MTASTS.parse_policy(text)

      assert policy == %Policy{
               mode: :enforce,
               mx: ["mx1.example.com", "*.example.net"],
               max_age: 604_800,
               text: text
             }

      assert {:ok, %Policy{mode: :none, mx: []}} =
               MTASTS.parse_policy(MTASTS.policy_text(:none, [], 86_400))
    end

    test "the id is stable, changes with the policy, and fits the record" do
      text = MTASTS.policy_text(:testing, ["mx.example.com"], 86_400)
      id = MTASTS.policy_id(text)
      assert id == MTASTS.policy_id(MTASTS.policy_text(:testing, ["mx.example.com"], 86_400))
      assert id =~ ~r/\A[0-9a-f]{20}\z/
      assert id == binary_part(Base.encode16(:crypto.hash(:sha256, text), case: :lower), 0, 20)
      assert id != MTASTS.policy_id(MTASTS.policy_text(:enforce, ["mx.example.com"], 86_400))
      assert MTASTS.parse_record(["v=STSv1; id=" <> id]) == {:ok, id}
    end
  end

  describe "fetch/2" do
    # Serves one TLS connection with `cert`: sends the request head and
    # the SNI name to the test, then answers with `response`, iodata or a
    # function of the socket.
    defp serve(cert, response) do
      {:ok, listen} =
        :ssl.listen(
          0,
          Sovite.TLS.server_options(certs_keys: [Certs.certs_keys(cert)]) ++
            [reuseaddr: true, ip: {127, 0, 0, 1}, mode: :binary, active: false]
        )

      {:ok, {_, port}} = :ssl.sockname(listen)
      test = self()

      spawn_link(fn ->
        {:ok, socket} = :ssl.transport_accept(listen)

        with {:ok, socket} <- :ssl.handshake(socket, 5_000), do: answer(socket, test, response)

        Process.sleep(:infinity)
      end)

      port
    end

    defp answer(socket, test, response) do
      {:ok, [sni_hostname: sni]} = :ssl.connection_information(socket, [:sni_hostname])
      send(test, {:request, read_head(socket, ""), sni})
      if is_function(response), do: response.(socket), else: :ssl.send(socket, response)
      :ssl.close(socket)
    end

    defp read_head(socket, acc) do
      if String.contains?(acc, "\r\n\r\n") do
        acc
      else
        {:ok, data} = :ssl.recv(socket, 0, 5_000)
        read_head(socket, acc <> data)
      end
    end

    defp fetch(port, ca, opts \\ []) do
      MTASTS.fetch(
        "example.com",
        Keyword.merge(
          [connect_to: {{127, 0, 0, 1}, port}, cacerts: [ca.cert], timeout: 5_000],
          opts
        )
      )
    end

    defp ok(body, content_type \\ "text/plain") do
      "HTTP/1.1 200 OK\r\nContent-Type: #{content_type}\r\nContent-Length: #{byte_size(body)}\r\n\r\n" <>
        body
    end

    test "fetches and parses the policy", %{ca: ca, cert: cert} do
      port = serve(cert, ok(@policy, "text/plain; charset=utf-8"))

      assert {:ok, %Policy{mode: :enforce, max_age: 86_400, text: @policy}} = fetch(port, ca)
      assert_received {:request, request, ~c"mta-sts.example.com"}
      assert String.starts_with?(request, "GET /.well-known/mta-sts.txt HTTP/1.1\r\n")
      assert request =~ "\r\nHost: mta-sts.example.com\r\n"
      assert request =~ "\r\nConnection: close\r\n"
      assert request =~ "\r\nUser-Agent: sovite\r\n"
    end

    test "accepts a domain with a trailing dot or capitals", %{ca: ca, cert: cert} do
      port = serve(cert, ok(@policy))

      assert {:ok, _} =
               MTASTS.fetch("Example.COM.",
                 connect_to: {{127, 0, 0, 1}, port},
                 cacerts: [ca.cert]
               )
    end

    test "connects to a host name and port", %{ca: ca, cert: cert} do
      port = serve(cert, ok(@policy))
      assert {:ok, _} = fetch(port, ca, connect_to: ~c"localhost", port: port)
    end

    test "reads chunked bodies", %{ca: ca, cert: cert} do
      {a, b} = String.split_at(@policy, 20)

      port =
        serve(cert, fn socket ->
          :ssl.send(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
          )

          :ssl.send(socket, Integer.to_string(byte_size(a), 16) <> ";ext=1\r\n" <> a <> "\r\n")
          Process.sleep(20)
          :ssl.send(socket, Integer.to_string(byte_size(b), 16) <> "\r\n" <> b)
          Process.sleep(20)
          :ssl.send(socket, "\r\n0\r\n\r\n")
        end)

      assert {:ok, %Policy{text: @policy}} = fetch(port, ca)
    end

    test "reads bodies until the connection closes", %{ca: ca, cert: cert} do
      port =
        serve(cert, fn socket ->
          :ssl.send(socket, "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n")
          Process.sleep(20)
          :ssl.send(socket, @policy)
        end)

      assert {:ok, %Policy{text: @policy}} = fetch(port, ca)
    end

    test "requires text/plain", %{ca: ca, cert: cert} do
      port = serve(cert, ok(@policy, "text/html"))
      assert fetch(port, ca) == {:error, :invalid_content_type}

      port = serve(cert, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
      assert fetch(port, ca) == {:error, :invalid_content_type}
    end

    test "does not follow redirects", %{ca: ca, cert: cert} do
      response =
        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://elsewhere.example/\r\n" <>
          "Content-Type: text/plain\r\nContent-Length: 0\r\n\r\n"

      port = serve(cert, response)
      assert fetch(port, ca) == {:error, {:http_status, 301}}

      port = serve(cert, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
      assert fetch(port, ca) == {:error, {:http_status, 404}}
    end

    test "limits the body size", %{ca: ca, cert: cert} do
      port =
        serve(
          cert,
          "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 65537\r\n\r\n"
        )

      assert fetch(port, ca) == {:error, :too_large}

      port = serve(cert, ok(@policy))
      assert fetch(port, ca, max_size: 10) == {:error, :too_large}

      port = serve(cert, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" <> @policy)
      assert fetch(port, ca, max_size: 10) == {:error, :too_large}

      chunked =
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" <>
          "8\r\n12345678\r\n8\r\n12345678\r\n0\r\n\r\n"

      port = serve(cert, chunked)
      assert fetch(port, ca, max_size: 10) == {:error, :too_large}
    end

    test "rejects a certificate for another name", %{ca: ca, other: other} do
      port = serve(other, ok(@policy))
      assert {:error, {:tls, _}} = fetch(port, ca)
    end

    test "rejects an untrusted certificate", %{cert: cert} do
      port = serve(cert, ok(@policy))
      assert {:error, {:tls, _}} = fetch(port, Certs.ca())
    end

    test "gives up at the deadline", %{ca: ca, cert: cert} do
      # TLS completes, but no response comes.
      port = serve(cert, fn _socket -> Process.sleep(:infinity) end)
      assert fetch(port, ca, timeout: 200) == {:error, :timeout}

      # A TCP server that never starts TLS.
      {:ok, listen} = :gen_tcp.listen(0, ip: {127, 0, 0, 1}, active: false)
      {:ok, port} = :inet.port(listen)

      spawn_link(fn ->
        {:ok, _socket} = :gen_tcp.accept(listen)
        Process.sleep(:infinity)
      end)

      started = System.monotonic_time(:millisecond)
      assert fetch(port, ca, timeout: 200) == {:error, :timeout}
      assert System.monotonic_time(:millisecond) - started < 2_000
    end

    test "reports connection failures", %{ca: ca} do
      {:ok, listen} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
      {:ok, port} = :inet.port(listen)
      :gen_tcp.close(listen)

      assert fetch(port, ca) == {:error, {:connect, :econnrefused}}
      assert MTASTS.fetch("not a domain") == {:error, :invalid_domain}
      assert MTASTS.fetch("example.com\r\nX: y") == {:error, :invalid_domain}
    end

    test "rejects invalid policies", %{ca: ca, cert: cert} do
      port = serve(cert, ok("version: STSv1\nmode: enforce\nmax_age: 1\n"))
      assert fetch(port, ca) == {:error, {:invalid_policy, :missing_mx}}
    end

    test "rejects malformed responses", %{ca: ca, cert: cert} do
      cases = [
        {"HTTP/2 200\r\n\r\n", :status_line},
        {"SMTP 220 hello\r\n\r\n", :status_line},
        {"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nbroken header\r\n\r\n", :header},
        {"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: x\r\n\r\n",
         :content_length},
        {"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: gzip\r\n\r\n",
         :transfer_encoding},
        {"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\nshort",
         :truncated},
        {"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
         :chunk},
        {"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabc\r\n",
         :chunk},
        {"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab",
         :truncated},
        {"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" <>
           String.duplicate("0", 2000), :chunk},
        {"HTTP/1.1 200 OK\r\n" <> String.duplicate("X-Pad: 0123456789\r\n", 1000),
         :headers_too_large},
        {"HTTP/1.1 200 OK\r\n", :truncated}
      ]

      for {response, detail} <- cases do
        port = serve(cert, response)
        assert fetch(port, ca) == {:error, {:invalid_response, detail}}, inspect(response)
      end
    end

    test "validates options" do
      assert_raise ArgumentError, fn -> MTASTS.fetch("example.com", unknown: 1) end
    end
  end
end
