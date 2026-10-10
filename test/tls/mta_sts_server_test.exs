defmodule Sovite.TLS.MTASTS.ServerTest do
  use ExUnit.Case, async: true

  alias Sovite.Test.{Certs, TelemetryForwarder}
  alias Sovite.TLS.MTASTS

  @text MTASTS.policy_text(:enforce, ["mx.example.com"], 86_400)

  setup_all do
    ca = Certs.ca()
    %{ca: ca, cert: Certs.issue(ca, names: ["mta-sts.example.com", "mta-sts.example.org"])}
  end

  setup %{cert: cert} do
    TelemetryForwarder.attach([[:sovite, :tls, :mta_sts, :served]])

    %{
      port:
        start_server(fn -> Sovite.TLS.server_options(certs_keys: [Certs.certs_keys(cert)]) end)
    }
  end

  defp start_server(tls) do
    policy = fn
      "example.com" -> {:ok, @text}
      _ -> :error
    end

    listener =
      start_supervised!(
        {Sovite.Listener,
         ip: {127, 0, 0, 1},
         port: 0,
         handler: MTASTS.Server,
         handler_opts: [tls: tls, policy: policy]},
        id: make_ref()
      )

    {:ok, {_, port}} = Sovite.Listener.sockname(listener)
    port
  end

  # Sends `request` over TLS and returns everything the server sends
  # before it closes the connection.
  defp request(port, ca, request) do
    opts =
      Sovite.TLS.client_options(
        verify: :peer,
        hostname: "mta-sts.example.com",
        cacerts: [ca.cert]
      )

    {:ok, socket} =
      :ssl.connect({127, 0, 0, 1}, port, opts ++ [mode: :binary, active: false], 5_000)

    :ok = :ssl.send(socket, request)
    receive_all(socket, "")
  end

  defp receive_all(socket, acc) do
    case :ssl.recv(socket, 0, 5_000) do
      {:ok, data} -> receive_all(socket, acc <> data)
      {:error, :closed} -> acc
    end
  end

  defp get(host, path \\ "/.well-known/mta-sts.txt", method \\ "GET"),
    do: "#{method} #{path} HTTP/1.1\r\nHost: #{host}\r\nConnection: close\r\n\r\n"

  test "serves the policy that fetch/2 reads", %{port: port, ca: ca} do
    assert {:ok, policy} =
             MTASTS.fetch("example.com", connect_to: {{127, 0, 0, 1}, port}, cacerts: [ca.cert])

    assert policy.text == @text
    assert policy.mode == :enforce
    assert_receive {:telemetry, _, %{}, %{domain: "example.com", status: 200}}
  end

  test "answers GET and HEAD with 200", %{port: port, ca: ca} do
    response = request(port, ca, get("MTA-STS.Example.com:443"))
    assert String.starts_with?(response, "HTTP/1.1 200 OK\r\n")
    assert response =~ "\r\nContent-Type: text/plain\r\n"
    assert response =~ "\r\nContent-Length: #{byte_size(@text)}\r\n"
    assert response =~ "\r\nConnection: close\r\n"
    assert String.ends_with?(response, "\r\n\r\n" <> @text)

    response = request(port, ca, get("mta-sts.example.com.", "/.well-known/mta-sts.txt", "HEAD"))
    assert String.starts_with?(response, "HTTP/1.1 200 OK\r\n")
    assert response =~ "\r\nContent-Length: #{byte_size(@text)}\r\n"
    assert String.ends_with?(response, "\r\n\r\n")
  end

  test "answers unknown domains and paths with 404", %{port: port, ca: ca} do
    assert {:error, {:http_status, 404}} =
             MTASTS.fetch("example.org", connect_to: {{127, 0, 0, 1}, port}, cacerts: [ca.cert])

    assert_receive {:telemetry, _, %{}, %{domain: "example.org", status: 404}}

    for request <- [
          get("mta-sts.example.com", "/"),
          get("mta-sts.example.com", "/.well-known/mta-sts.txt?x=1"),
          get("example.com"),
          get("mta-sts."),
          get("[::1]:443"),
          "GET /.well-known/mta-sts.txt HTTP/1.1\r\n\r\n"
        ] do
      assert "HTTP/1.1 404 Not Found\r\n" <> _ = request(port, ca, request)
    end
  end

  test "answers other methods with 405", %{port: port, ca: ca} do
    response = request(port, ca, get("mta-sts.example.com", "/.well-known/mta-sts.txt", "POST"))
    assert String.starts_with?(response, "HTTP/1.1 405 Method Not Allowed\r\n")
    assert response =~ "\r\nAllow: GET, HEAD\r\n"
    assert_receive {:telemetry, _, %{}, %{domain: "example.com", status: 405}}
  end

  test "answers malformed requests with 400", %{port: port, ca: ca} do
    assert "HTTP/1.1 400 Bad Request\r\n" <> _ = request(port, ca, "hello\n\n")
    assert_receive {:telemetry, _, %{}, %{domain: nil, status: 400}}
  end

  test "drops requests that are too large", %{port: port, ca: ca} do
    padding = String.duplicate("X-Pad: 0123456789\r\n", 1000)
    assert request(port, ca, "GET /.well-known/mta-sts.txt HTTP/1.1\r\n" <> padding) == ""
  end

  test "closes the connection without TLS options", %{ca: ca} do
    port = start_server(fn -> nil end)

    opts =
      Sovite.TLS.client_options(
        verify: :peer,
        hostname: "mta-sts.example.com",
        cacerts: [ca.cert]
      )

    assert {:error, _} = :ssl.connect({127, 0, 0, 1}, port, opts, 5_000)
  end
end
