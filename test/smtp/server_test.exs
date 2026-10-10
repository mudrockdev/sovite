defmodule Sovite.SMTP.ServerTest do
  use ExUnit.Case, async: true

  alias Sovite.SMTP.Server
  alias Sovite.Test.SMTPClient

  defmodule Handler do
    @moduledoc false
    # Accepts everything and sends each message to the test process.
    @behaviour Sovite.SMTP.Server.Handler

    @impl true
    def init(connection, test), do: {:ok, %{test: test, connection: connection, data: []}}
    @impl true
    def handle_helo(_kind, _name, state), do: {:ok, state}
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
    def handle_data_abort(reason, state) do
      send(state.test, {:abort, reason})
      state
    end

    @impl true
    def terminate(reason, state), do: send(state.test, {:terminate, reason, state.connection})
  end

  defp start_server(opts \\ []) do
    opts =
      Keyword.merge(
        [ip: {127, 0, 0, 1}, port: 0, hostname: "mx.test", handler: {Handler, self()}],
        opts
      )

    server = start_supervised!({Server, opts})
    {:ok, {_ip, port}} = Sovite.Listener.sockname(server)
    {server, port}
  end

  defp connect(port) do
    {:ok, client} = SMTPClient.connect(port)
    on_exit(fn -> SMTPClient.close(client) end)
    client
  end

  test "receives a message over TCP" do
    {_server, port} = start_server()
    client = connect(port)

    assert {:ok, {250, ["2.0.0 Ok"]}} =
             SMTPClient.send_message(
               client,
               "a@x.test",
               ["b@y.test"],
               "Subject: t\r\n\r\n.dot\r\n"
             )

    assert_receive {:message, %{sender: "a@x.test", recipients: ["b@y.test"]},
                    "Subject: t\r\n\r\n.dot\r\n"}

    assert {:ok, {221, _}} = SMTPClient.command(client, "QUIT")
    assert_receive {:terminate, :normal, %{remote_ip: {127, 0, 0, 1}, local_port: ^port}}
  end

  test "the session sees the client named by a PROXY protocol header" do
    {_server, port} = start_server(proxy_protocol: true)
    client = connect(port)

    # The header and the first command arrive together.
    :ok = SMTPClient.send_raw(client, "PROXY TCP6 2001:db8::1 2001:db8::25 1234 25\r\nQUIT\r\n")
    assert {:ok, {220, _}} = SMTPClient.read_reply(client)
    assert {:ok, {221, _}} = SMTPClient.read_reply(client)

    assert_receive {:terminate, :normal, connection}

    assert %{
             remote_ip: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1},
             remote_port: 1234,
             local_ip: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x25},
             local_port: 25
           } = connection
  end

  test "answers a whole pipelined transaction sent in one write" do
    {_server, port} = start_server()
    client = connect(port)
    {:ok, {220, _}} = SMTPClient.read_reply(client)

    :ok =
      SMTPClient.send_raw(client, [
        "EHLO c.test\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@y.test>\r\nRCPT TO:<c@y.test>\r\nDATA\r\n"
      ])

    replies = for _ <- 1..5, do: SMTPClient.read_reply(client)
    assert Enum.map(replies, fn {:ok, {code, _}} -> code end) == [250, 250, 250, 250, 354]

    :ok = SMTPClient.send_raw(client, "body\r\n.\r\nQUIT\r\n")
    assert {:ok, {250, _}} = SMTPClient.read_reply(client)
    assert {:ok, {221, _}} = SMTPClient.read_reply(client)
    assert_receive {:message, %{recipients: ["b@y.test", "c@y.test"]}, "body\r\n"}
  end

  test "handles input split into single bytes" do
    {_server, port} = start_server()
    client = connect(port)
    {:ok, {220, _}} = SMTPClient.read_reply(client)

    for <<byte <- "EHLO c.test\r\nMAIL FROM:<>\r\nRCPT TO:<b@y.test>\r\nDATA\r\n">> do
      :ok = SMTPClient.send_raw(client, <<byte>>)
    end

    for code <- [250, 250, 250, 354],
        do: assert({:ok, {^code, _}} = SMTPClient.read_reply(client))

    for <<byte <- "a\r\n..b\r\n.\r\n">>, do: :ok = SMTPClient.send_raw(client, <<byte>>)
    assert {:ok, {250, _}} = SMTPClient.read_reply(client)
    assert_receive {:message, _, "a\r\n.b\r\n"}
  end

  test "closes idle sessions with 421" do
    {_server, port} = start_server(command_timeout: 100)
    client = connect(port)
    {:ok, {220, _}} = SMTPClient.read_reply(client)

    assert {:ok, {421, ["4.4.2 mx.test Error: timeout exceeded"]}} = SMTPClient.read_reply(client)
    assert {:error, :closed} = SMTPClient.read_reply(client)
  end

  test "times out a stalled DATA and aborts the message" do
    {_server, port} = start_server(data_timeout: 100)
    client = connect(port)
    {:ok, {220, _}} = SMTPClient.read_reply(client)
    {:ok, {250, _}} = SMTPClient.command(client, "EHLO c.test")
    {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<>")
    {:ok, {250, _}} = SMTPClient.command(client, "RCPT TO:<b@y.test>")
    {:ok, {354, _}} = SMTPClient.command(client, "DATA")
    :ok = SMTPClient.send_raw(client, "partial line")

    assert {:ok, {421, _}} = SMTPClient.read_reply(client)
    assert_receive {:abort, :timeout}
  end

  test "refuses connections over the per-IP limit with 421" do
    {server, port} = start_server(max_connections_per_ip: 1)
    first = connect(port)
    {:ok, {220, _}} = SMTPClient.read_reply(first)

    second = connect(port)

    assert {:ok, {421, ["4.7.0 mx.test Error: too many connections"]}} =
             SMTPClient.read_reply(second)

    assert {:error, :closed} = SMTPClient.read_reply(second)
    assert Sovite.Listener.connection_count(server) == 1
  end

  test "sends 421 to open sessions on shutdown" do
    {_server, port} = start_server()
    client = connect(port)
    {:ok, {220, _}} = SMTPClient.read_reply(client)
    {:ok, {250, _}} = SMTPClient.command(client, "EHLO c.test")

    stop_supervised!({Sovite.Listener, {{127, 0, 0, 1}, 0}})

    assert {:ok, {421, ["4.3.2 mx.test Service shutting down"]}} = SMTPClient.read_reply(client)
    assert_receive {:terminate, :shutdown, _}
  end

  test "aborts the message when the client disconnects during DATA" do
    {_server, port} = start_server()
    client = connect(port)
    {:ok, {220, _}} = SMTPClient.read_reply(client)
    {:ok, {250, _}} = SMTPClient.command(client, "EHLO c.test")
    {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<>")
    {:ok, {250, _}} = SMTPClient.command(client, "RCPT TO:<b@y.test>")
    {:ok, {354, _}} = SMTPClient.command(client, "DATA")
    :ok = SMTPClient.send_raw(client, "half a message\r\n")
    SMTPClient.close(client)

    assert_receive {:abort, :closed}
    assert_receive {:terminate, :normal, _}
  end

  test "emits session telemetry" do
    ref = make_ref()
    id = {__MODULE__, ref}

    events = [
      [:sovite, :smtp, :server, :session, :start],
      [:sovite, :smtp, :server, :session, :stop]
    ]

    :telemetry.attach_many(id, events, &__MODULE__.forward_event/4, {self(), ref})
    on_exit(fn -> :telemetry.detach(id) end)

    {_server, port} = start_server()
    client = connect(port)
    {:ok, {220, _}} = SMTPClient.read_reply(client)
    {:ok, {221, _}} = SMTPClient.command(client, "QUIT")

    assert_receive {^ref, [_, _, _, _, :start], %{system_time: _},
                    %{session_id: id, remote_ip: {127, 0, 0, 1}}}

    assert_receive {^ref, [_, _, _, _, :stop], %{duration: _}, %{session_id: ^id}}
  end

  def forward_event(event, measurements, metadata, {pid, ref}),
    do: send(pid, {ref, event, measurements, metadata})
end
