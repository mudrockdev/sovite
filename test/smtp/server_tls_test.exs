defmodule Sovite.SMTP.ServerTLSTest do
  # STARTTLS and implicit TLS over real sockets.
  use ExUnit.Case, async: true

  alias Sovite.SMTP.Server
  alias Sovite.Test.{Certs, SMTPClient, TelemetryForwarder}

  defmodule Handler do
    @moduledoc false
    @behaviour Sovite.SMTP.Server.Handler

    @impl true
    def init(connection, test) do
      send(test, {:init, connection})
      {:ok, %{test: test, data: []}}
    end

    @impl true
    def handle_helo(_kind, name, state) do
      send(state.test, {:helo, name})
      {:ok, state}
    end

    @impl true
    def handle_mail(_sender, _params, state), do: {:ok, state}
    @impl true
    def handle_rcpt(_recipient, state), do: {:ok, state}
    @impl true
    def handle_data(_transaction, state), do: {:ok, %{state | data: []}}
    @impl true
    def handle_data_chunk(chunk, state), do: {:ok, %{state | data: [state.data, chunk]}}

    @impl true
    def handle_data_end(transaction, state) do
      send(state.test, {:message, transaction, IO.iodata_to_binary(state.data)})
      {:ok, state}
    end

    @impl true
    def handle_data_abort(_reason, state), do: state

    @impl true
    def handle_tls(info, state) do
      send(state.test, {:tls, info})
      state
    end

    @impl true
    def auth_mechanisms(_state), do: ["PLAIN"]

    @impl true
    def handle_auth("PLAIN", <<0, "alice", 0, "secret">>, state), do: {:ok, "alice", state}

    def handle_auth("PLAIN", _response, state),
      do:
        {:error, Sovite.SMTP.Reply.new(535, "5.7.8", "Authentication credentials invalid"), state}
  end

  setup_all do
    ca = Certs.ca()
    server = Certs.issue(ca, names: ["mx.test"])
    ssl = Sovite.TLS.server_options(certs_keys: [Certs.certs_keys(server)])
    client = Sovite.TLS.client_options(verify: :peer, hostname: "mx.test", cacerts: [ca.cert])
    %{server_ssl: ssl, client_ssl: client}
  end

  defp start_server(context, opts \\ []) do
    opts =
      Keyword.merge(
        [
          ip: {127, 0, 0, 1},
          port: 0,
          hostname: "mx.test",
          handler: {Handler, self()},
          tls: context.server_ssl
        ],
        opts
      )

    server = start_supervised!({Server, opts})
    {:ok, {_ip, port}} = Sovite.Listener.sockname(server)
    port
  end

  defp connect(port) do
    {:ok, client} = SMTPClient.connect(port)
    on_exit(fn -> SMTPClient.close(client) end)
    {:ok, {220, _}} = SMTPClient.read_reply(client)
    client
  end

  defp ehlo(client) do
    {:ok, {250, lines}} = SMTPClient.command(client, "EHLO client.test")
    lines
  end

  test "upgrades with STARTTLS and starts the session over", context do
    TelemetryForwarder.attach([[:sovite, :smtp, :server, :tls, :stop]])
    port = start_server(context)
    client = connect(port)

    assert "STARTTLS" in ehlo(client)
    {:ok, client} = SMTPClient.starttls(client, context.client_ssl)

    assert_receive {:tls, %{protocol: "TLSv1.3", sni: "mx.test", cipher: "TLS_" <> _}}

    assert_receive {:telemetry, _, %{duration: _},
                    %{protocol: "TLSv1.3", sni: "mx.test", error: nil, remote_ip: {127, 0, 0, 1}}}

    # The EHLO name from before TLS is forgotten.
    assert {:ok, {503, ["5.5.1 Send HELO/EHLO first"]}} =
             SMTPClient.command(client, "MAIL FROM:<a@x.test>")

    refute "STARTTLS" in ehlo(client)
    assert {:ok, {503, _}} = SMTPClient.command(client, "STARTTLS")

    assert {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<a@x.test>")
    assert {:ok, {250, _}} = SMTPClient.command(client, "RCPT TO:<b@y.test>")
    assert {:ok, {354, _}} = SMTPClient.command(client, "DATA")
    assert {:ok, {250, _}} = SMTPClient.send_data(client, "Subject: t\r\n\r\nhi\r\n")
    assert_receive {:message, %{sender: "a@x.test"}, "Subject: t\r\n\r\nhi\r\n"}
  end

  test "discards commands pipelined after STARTTLS", context do
    port = start_server(context)
    client = connect(port)
    ehlo(client)

    :ok = SMTPClient.send_raw(client, "STARTTLS\r\nMAIL FROM:<evil@x.test>\r\n")
    assert {:ok, {220, _}} = SMTPClient.read_reply(client)
    {:ok, client} = SMTPClient.upgrade(client, context.client_ssl)
    ehlo(client)

    assert {:ok, {503, ["5.5.1 Need MAIL command"]}} =
             SMTPClient.command(client, "RCPT TO:<b@y.test>")
  end

  test "requires TLS before mail and authentication", context do
    port = start_server(context, require_tls: true, auth: true)
    client = connect(port)
    lines = ehlo(client)
    refute Enum.any?(lines, &String.starts_with?(&1, "AUTH"))

    assert {:ok, {530, ["5.7.0 Must issue a STARTTLS command first"]}} =
             SMTPClient.command(client, "MAIL FROM:<a@x.test>")

    assert {:ok, {530, _}} = SMTPClient.command(client, "AUTH PLAIN AGFsaWNlAHNlY3JldA==")

    {:ok, client} = SMTPClient.starttls(client, context.client_ssl)
    assert "AUTH PLAIN" in ehlo(client)
    assert {:ok, {235, _}} = SMTPClient.command(client, "AUTH PLAIN AGFsaWNlAHNlY3JldA==")
    assert {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<alice@x.test>")
  end

  test "serves implicit TLS", context do
    port = start_server(context, implicit_tls: true, auth: true, auth_required: true)
    {:ok, client} = SMTPClient.connect_tls(port, context.client_ssl)
    on_exit(fn -> SMTPClient.close(client) end)

    assert {:ok, {220, _}} = SMTPClient.read_reply(client)
    assert_receive {:init, %{tls: %{protocol: "TLSv1.3"}}}

    lines = ehlo(client)
    refute "STARTTLS" in lines
    assert "AUTH PLAIN" in lines

    assert {:ok, {530, ["5.7.0 Authentication required"]}} =
             SMTPClient.command(client, "MAIL FROM:<a@x.test>")

    assert {:ok, {535, _}} = SMTPClient.command(client, "AUTH PLAIN AGFsaWNlAHdyb25n")
    assert {:ok, {235, _}} = SMTPClient.command(client, "AUTH PLAIN AGFsaWNlAHNlY3JldA==")
    assert {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<a@x.test>")
  end

  test "refuses TLS versions below 1.2", context do
    port = start_server(context, implicit_tls: true)

    assert {:error, _} =
             SMTPClient.connect_tls(port,
               verify: :verify_none,
               versions: [:"tlsv1.1"],
               log_level: :none
             )
  end

  test "closes the connection after a failed handshake", context do
    TelemetryForwarder.attach([[:sovite, :smtp, :server, :tls, :stop]])
    port = start_server(context)
    client = connect(port)
    ehlo(client)

    assert {:ok, {220, _}} = SMTPClient.command(client, "STARTTLS")
    :ok = SMTPClient.send_raw(client, "this is not a TLS record\r\n")
    # The server answers with a TLS alert record, then closes.
    assert {:error, {:malformed_reply, <<21, _::binary>>}} = SMTPClient.read_reply(client)
    assert {:error, :closed} = SMTPClient.read_reply(client)
    assert_receive {:telemetry, _, _, %{error: error, protocol: nil}} when error != nil
  end

  test "offers no TLS when the options function returns nil", context do
    port = start_server(context, tls: fn -> nil end)
    client = connect(port)
    refute "STARTTLS" in ehlo(client)
    assert {:ok, {502, _}} = SMTPClient.command(client, "STARTTLS")

    port = start_server(context, tls: fn -> nil end, implicit_tls: true, id: "implicit")
    {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2000)
  end
end
