defmodule Sovite.SMTP.ClientTLSTest do
  use ExUnit.Case, async: true

  alias Sovite.SASL
  alias Sovite.SMTP.{Client, Reply}
  alias Sovite.Test.{Certs, FakeMTA}

  setup_all do
    ca = Certs.ca()
    cert = Certs.issue(ca, names: ["mx.test"])
    %{ca: ca, server_tls: Sovite.TLS.server_options(certs_keys: [Certs.certs_keys(cert)])}
  end

  defp start_mta(opts) do
    start_supervised!({FakeMTA, Keyword.put(opts, :owner, self())}, id: make_ref())
  end

  defp connect(mta, opts \\ []) do
    Client.connect(
      {127, 0, 0, 1},
      FakeMTA.port(mta),
      Keyword.merge([helo: "mx.example.org"], opts)
    )
  end

  defp verify(context, host \\ "mx.test"),
    do: Sovite.TLS.client_options(verify: :peer, hostname: host, cacerts: [context.ca.cert])

  test "upgrades with STARTTLS, says EHLO again, and delivers", context do
    mta = start_mta(tls: context.server_tls)
    {:ok, client} = connect(mta)
    assert Map.has_key?(Client.extensions(client), "STARTTLS")
    assert Client.tls(client) == nil

    assert {:ok, client} = Client.starttls(client, verify(context))
    assert %{protocol: "TLSv1.3"} = Client.tls(client)
    refute Map.has_key?(Client.extensions(client), "STARTTLS")
    assert_receive {:fake_mta, _, {:tls, %{sni: "mx.test"}}}

    assert {:ok, _client, [{"b@y.test", :data_end, %Reply{code: 250}}]} =
             Client.deliver(client, "a@x.test", ["b@y.test"], ["hi\r\n"])

    assert_receive {:fake_mta, _,
                    {:message, %{helo: "mx.example.org", tls: %{protocol: "TLSv1.3"}}}}
  end

  test "reports a server without STARTTLS, or one that refuses it", context do
    {:ok, client} = connect(start_mta([]))
    assert {:error, ^client, :not_offered} = Client.starttls(client, verify(context))

    mta =
      start_mta(tls: context.server_tls, responses: %{starttls: "454 4.7.0 TLS not available"})

    {:ok, client} = connect(mta)

    assert {:error, client, {:refused, %Reply{code: 454}}} =
             Client.starttls(client, verify(context))

    # Still usable in plaintext.
    assert {:ok, _, [{_, :data_end, %Reply{code: 250}}]} =
             Client.deliver(client, "a@x.test", ["b@y.test"], ["x\r\n"])
  end

  test "fails the handshake on a certificate for another name", context do
    mta = start_mta(tls: context.server_tls)
    {:ok, client} = connect(mta)

    assert {:error, {:starttls, {:tls, _reason}}} =
             Client.starttls(client, verify(context, "other.test"))
  end

  test "connects with implicit TLS", context do
    mta = start_mta(tls: context.server_tls, implicit_tls: true)
    assert {:ok, client} = connect(mta, tls: verify(context))
    assert %{protocol: "TLSv1.3"} = Client.tls(client)
    assert {:ok, _, _} = Client.deliver(client, "a@x.test", ["b@y.test"], ["x\r\n"])
    assert_receive {:fake_mta, _, {:message, %{tls: %{}}}}

    assert {:error, {:tls, {:tls, _}}} = connect(mta, tls: verify(context, "other.test"))
  end

  test "sends REQUIRETLS only over TLS to a server that offers it", context do
    extensions = ["PIPELINING", "REQUIRETLS"]
    mta = start_mta(tls: context.server_tls, extensions: extensions)
    {:ok, client} = connect(mta)

    assert {:error, client, :requiretls_not_supported} =
             Client.deliver(client, "a@x.test", ["b@y.test"], ["x\r\n"], requiretls: true)

    {:ok, client} = Client.starttls(client, verify(context))

    assert {:ok, _, _} =
             Client.deliver(client, "a@x.test", ["b@y.test"], ["x\r\n"], requiretls: true)

    assert_receive {:fake_mta, _, {:message, %{mail_args: "FROM:<a@x.test> REQUIRETLS"}}}

    mta = start_mta(tls: context.server_tls, implicit_tls: true)
    {:ok, client} = connect(mta, tls: verify(context))

    assert {:error, _, :requiretls_not_supported} =
             Client.deliver(client, "a@x.test", ["b@y.test"], ["x\r\n"], requiretls: true)
  end

  test "authenticates with the best common mechanism", context do
    mta = start_mta(tls: context.server_tls, auth: %{"alice" => "secret"})
    {:ok, client} = connect(mta)
    {:ok, client} = Client.starttls(client, verify(context))

    assert {:ok, client} = Client.authenticate(client, %{username: "alice", password: "secret"})
    assert {:ok, _, _} = Client.deliver(client, "a@x.test", ["b@y.test"], ["x\r\n"])
    assert_receive {:fake_mta, _, {:message, %{auth: "alice"}}}

    {:ok, client} = connect(mta)

    assert {:ok, _} =
             Client.authenticate(client, %{username: "alice", password: "secret"}, ["LOGIN"])

    {:ok, client} = connect(mta)

    assert {:error, _client, {:rejected, %Reply{code: 535}}} =
             Client.authenticate(client, %{username: "alice", password: "wrong"})

    {:ok, client} = connect(mta)

    assert {:error, _, :no_mechanism} =
             Client.authenticate(client, %{username: "a", password: "b"}, ["SCRAM-SHA-256"])
  end

  test "authenticates with SCRAM-SHA-256 against a Sovite server" do
    defmodule ScramHandler do
      @moduledoc false
      @behaviour Sovite.SMTP.Server.Handler
      @opts [backend: {Sovite.SASL.Backend.Static, file: nil}]
      def init(_connection, users), do: {:ok, %{users: users, sasl: nil}}
      def handle_helo(_kind, _name, state), do: {:ok, state}
      def handle_mail(_s, _p, state), do: {:ok, state}
      def handle_rcpt(_r, state), do: {:ok, state}
      def handle_data(_t, state), do: {:ok, state}
      def handle_data_chunk(_c, state), do: {:ok, state}
      def handle_data_end(_t, state), do: {:ok, state}
      def handle_data_abort(_r, state), do: state
      def auth_mechanisms(_state), do: ["SCRAM-SHA-256"]

      def handle_auth(mech, initial, state),
        do: result(SASL.Server.start(mech, initial, opts(state)), state)

      def handle_auth_response(response, state),
        do: result(SASL.Server.step(state.sasl, response), state)

      defp opts(state),
        do: Keyword.put(@opts, :backend, {Sovite.SASL.Backend.Static, file: state.users})

      defp result({:ok, identity}, state), do: {:ok, identity, state}
      defp result({:challenge, data, sasl}, state), do: {:challenge, data, %{state | sasl: sasl}}
      defp result({:error, _, _}, state), do: {:error, Reply.new(535, "5.7.8", "no"), state}
    end

    dir = System.tmp_dir!() |> Path.join("sovite-scram-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    users = Path.join(dir, "users")
    File.write!(users, "alice:#{SASL.Password.hash("secret")}\n")
    on_exit(fn -> File.rm_rf(dir) end)

    server =
      start_supervised!(
        {Sovite.SMTP.Server,
         ip: {127, 0, 0, 1},
         port: 0,
         hostname: "mx.test",
         handler: {ScramHandler, users},
         auth: true,
         plaintext_auth: true}
      )

    {:ok, {_, port}} = Sovite.Listener.sockname(server)
    {:ok, client} = Client.connect({127, 0, 0, 1}, port, helo: "c.test")
    assert {:ok, _} = Client.authenticate(client, %{username: "alice", password: "secret"})

    {:ok, client} = Client.connect({127, 0, 0, 1}, port, helo: "c.test")

    assert {:error, _, {:rejected, %Reply{code: 535}}} =
             Client.authenticate(client, %{username: "alice", password: "x"})
  end
end
