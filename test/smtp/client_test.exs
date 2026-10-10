defmodule Sovite.SMTP.ClientTest do
  use ExUnit.Case, async: true

  alias Sovite.SMTP.{Client, Reply}
  alias Sovite.Test.FakeMTA

  @body "Subject: hi\r\n\r\n.leading dot\r\nbody\r\n"

  defp start_mta(opts \\ []) do
    start_supervised!({FakeMTA, Keyword.put(opts, :owner, self())}, id: make_ref())
  end

  defp connect(mta, opts \\ []) do
    Client.connect(
      {127, 0, 0, 1},
      FakeMTA.port(mta),
      Keyword.merge([helo: "mx.example.org"], opts)
    )
  end

  defp connect!(mta, opts \\ []) do
    {:ok, client} = connect(mta, opts)
    client
  end

  defp outcomes(results),
    do: Enum.map(results, fn {rcpt, stage, reply} -> {rcpt, stage, reply.code} end)

  # A TCP server that runs `fun` on the first accepted socket.
  defp raw_server(fun) do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false])
    {:ok, port} = :inet.port(listen)

    pid =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listen)
        fun.(socket)
        Process.sleep(:infinity)
      end)

    on_exit(fn -> Process.exit(pid, :kill) end)
    port
  end

  describe "connect/3" do
    test "reads the greeting and the EHLO extensions" do
      mta = start_mta(extensions: ["PIPELINING", "SIZE 1000", "8BITMIME", "AUTH PLAIN LOGIN"])
      client = connect!(mta)

      assert Client.server_name(client) == "fake-mta.test"

      assert Client.extensions(client) == %{
               "PIPELINING" => "",
               "SIZE" => "1000",
               "8BITMIME" => "",
               "AUTH" => "PLAIN LOGIN"
             }

      assert {{127, 0, 0, 1}, _port} = Client.peer(client)
      assert Client.quit(client) == :ok
    end

    test "falls back to HELO when EHLO is rejected" do
      mta = start_mta(responses: %{ehlo: "502 5.5.1 EHLO not supported"})
      client = connect!(mta)

      assert Client.extensions(client) == %{}

      assert {:ok, _client, [{"b@example.net", :data_end, %Reply{code: 250}}]} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body])

      assert_receive {:fake_mta, ^mta, {:message, %{helo: "mx.example.org"}}}
    end

    test "fails on a rejected greeting, EHLO, or HELO" do
      mta = start_mta(responses: %{greeting: "554 5.7.1 go away"})
      assert {:error, {:greeting, %Reply{code: 554, enhanced: "5.7.1"}}} = connect(mta)

      mta = start_mta(responses: %{ehlo: "421 4.3.2 shutting down"})
      assert {:error, {:ehlo, %Reply{code: 421}}} = connect(mta)

      mta = start_mta(responses: %{ehlo: "500 no", helo: "550 no"})
      assert {:error, {:helo, %Reply{code: 550}}} = connect(mta)
    end

    test "reports connection errors" do
      {:ok, listen} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
      {:ok, port} = :inet.port(listen)
      :gen_tcp.close(listen)

      assert Client.connect({127, 0, 0, 1}, port, helo: "x.test") ==
               {:error, {:connect, :econnrefused}}
    end

    test "times out waiting for the greeting" do
      port = raw_server(fn _socket -> :ok end)

      assert Client.connect({127, 0, 0, 1}, port, helo: "x.test", greeting_timeout: 100) ==
               {:error, {:greeting, :timeout}}
    end

    test "does not buffer an endless reply line" do
      port =
        raw_server(fn socket ->
          :gen_tcp.send(socket, "220 " <> String.duplicate("x", 10_000))
        end)

      assert Client.connect({127, 0, 0, 1}, port, helo: "x.test") ==
               {:error, {:greeting, :line_too_long}}
    end

    test "rejects a malformed reply" do
      port = raw_server(fn socket -> :gen_tcp.send(socket, "HTTP/1.1 400 Bad Request\r\n") end)

      assert Client.connect({127, 0, 0, 1}, port, helo: "x.test") ==
               {:error, {:greeting, :malformed}}
    end
  end

  describe "deliver/5 with PIPELINING" do
    test "delivers a message with dot-stuffing and SIZE/BODY parameters" do
      mta = start_mta()
      client = connect!(mta)

      assert {:ok, client, results} =
               Client.deliver(
                 client,
                 "a@example.org",
                 ["b@example.net", "c@example.net"],
                 [@body],
                 size: byte_size(@body),
                 body_type: :"8bitmime"
               )

      assert outcomes(results) == [
               {"b@example.net", :data_end, 250},
               {"c@example.net", :data_end, 250}
             ]

      assert_receive {:fake_mta, ^mta, {:message, message}}
      assert message.data == @body
      assert message.mail_args == "FROM:<a@example.org> SIZE=#{byte_size(@body)} BODY=8BITMIME"
      assert message.rcpt_to == ["b@example.net", "c@example.net"]
      Client.quit(client)
    end

    test "sends the null sender and streams a body in chunks" do
      mta = start_mta()
      client = connect!(mta)
      body = Stream.map(["Subject: x\r\n", "\r\n", "line one\r\n", ".", "dot\r\n"], & &1)

      assert {:ok, _client, [{_, :data_end, %Reply{code: 250}}]} =
               Client.deliver(client, "", ["b@example.net"], body)

      assert_receive {:fake_mta, ^mta, {:message, message}}
      assert message.mail_from == ""
      assert message.data == "Subject: x\r\n\r\nline one\r\n.dot\r\n"
    end

    test "reports rejected recipients and delivers to the others" do
      rcpt = fn
        "unknown@example.net" -> "550 5.1.1 User unknown"
        "full@example.net" -> "452 4.2.2 Mailbox full"
        _ -> "250 2.1.5 OK"
      end

      mta = start_mta(responses: %{rcpt: rcpt})
      client = connect!(mta)
      recipients = ["unknown@example.net", "ok@example.net", "full@example.net"]

      assert {:ok, _client, results} =
               Client.deliver(client, "a@example.org", recipients, [@body])

      assert outcomes(results) == [
               {"unknown@example.net", :rcpt, 550},
               {"full@example.net", :rcpt, 452},
               {"ok@example.net", :data_end, 250}
             ]

      assert {_, :rcpt, %Reply{enhanced: "5.1.1", lines: ["User unknown"]}} = hd(results)
      assert_receive {:fake_mta, ^mta, {:message, %{rcpt_to: ["ok@example.net"]}}}
    end

    test "resets after every recipient is rejected and stays usable" do
      mta = start_mta(responses: %{rcpt: fn _ -> "550 5.1.1 no" end})
      client = connect!(mta)

      assert {:ok, client, [{"b@example.net", :rcpt, %Reply{code: 550}}]} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body])

      assert {:ok, _client, [{"c@example.net", :rcpt, %Reply{code: 550}}]} =
               Client.deliver(client, "a@example.org", ["c@example.net"], [@body])

      refute_received {:fake_mta, ^mta, {:message, _}}
    end

    test "applies a MAIL rejection to every recipient" do
      mta = start_mta(responses: %{mail: "553 5.7.1 Sender rejected"})
      client = connect!(mta)

      assert {:ok, client, results} =
               Client.deliver(client, "a@example.org", ["b@example.net", "c@example.net"], [@body])

      assert outcomes(results) == [{"b@example.net", :mail, 553}, {"c@example.net", :mail, 553}]
      assert Client.quit(client) == :ok
    end

    test "applies a DATA rejection to the accepted recipients" do
      mta = start_mta(responses: %{data: "554 5.7.0 No thanks"})
      client = connect!(mta)

      assert {:ok, client, [{"b@example.net", :data, %Reply{code: 554}}]} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body])

      # The transaction was reset, so another one works.
      assert {:ok, _client, [{"b@example.net", :data, _}]} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body])
    end

    test "reports the reply to the final dot" do
      mta = start_mta(responses: %{data_end: "451 4.3.0 Try again later"})
      client = connect!(mta)

      assert {:ok, _client, [{"b@example.net", :data_end, %Reply{code: 451, enhanced: "4.3.0"}}]} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body])
    end

    test "carries several transactions over one connection" do
      mta = start_mta()
      client = connect!(mta)

      client =
        Enum.reduce(1..3, client, fn i, client ->
          assert {:ok, client, [{_, :data_end, %Reply{code: 250}}]} =
                   Client.deliver(client, "a@example.org", ["b#{i}@example.net"], [@body])

          client
        end)

      for i <- 1..3 do
        rcpt = "b#{i}@example.net"
        assert_receive {:fake_mta, ^mta, {:message, %{rcpt_to: [^rcpt]}}}
      end

      assert_received {:fake_mta, ^mta, :connected}
      refute_received {:fake_mta, ^mta, :connected}
      Client.quit(client)
    end

    test "reports a connection lost after the final dot" do
      mta = start_mta(responses: %{data_end: :close})
      client = connect!(mta)

      assert Client.deliver(client, "a@example.org", ["b@example.net"], [@body]) ==
               {:error, {:data_end, :closed}}
    end

    test "reports a connection lost before the data" do
      mta = start_mta(responses: %{rcpt: :close})
      client = connect!(mta)

      assert {:error, {stage, :closed}} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body])

      assert stage in [:rcpt, :data]
    end
  end

  describe "deliver/5 without PIPELINING" do
    setup do
      %{mta: start_mta(extensions: ["8BITMIME", "SIZE 100000"])}
    end

    test "sends one command at a time", %{mta: mta} do
      rcpt = fn
        "bad@example.net" -> "550 5.1.1 no"
        _ -> "250 2.1.5 OK"
      end

      mta2 = start_mta(extensions: [], responses: %{rcpt: rcpt})

      for mta <- [mta, mta2] do
        client = connect!(mta)

        assert {:ok, client, results} =
                 Client.deliver(client, "a@example.org", ["b@example.net", "bad@example.net"], [
                   @body
                 ])

        assert {"b@example.net", :data_end, 250} in outcomes(results)
        Client.quit(client)
      end

      assert_receive {:fake_mta, ^mta, {:message, %{data: @body}}}
      assert_receive {:fake_mta, ^mta2, {:message, %{rcpt_to: ["b@example.net"]}}}
    end

    test "stops after a MAIL rejection" do
      mta = start_mta(extensions: [], responses: %{mail: "451 4.7.1 Greylisted"})
      client = connect!(mta)

      assert {:ok, _client, [{"b@example.net", :mail, %Reply{code: 451}}]} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body])
    end

    test "stops when no recipient is accepted" do
      mta = start_mta(extensions: [], responses: %{rcpt: "550 5.1.1 no", data: "354 go"})
      client = connect!(mta)

      assert {:ok, client, [{"b@example.net", :rcpt, %Reply{code: 550}}]} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body])

      assert Client.quit(client) == :ok
    end

    test "applies a DATA rejection", %{mta: _mta} do
      mta = start_mta(extensions: [], responses: %{data: "554 5.7.0 no"})
      client = connect!(mta)

      assert {:ok, _client, [{"b@example.net", :data, %Reply{code: 554}}]} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body])
    end
  end

  describe "deliver/5 refusals" do
    test "a message larger than the server's SIZE" do
      mta = start_mta(extensions: ["SIZE 100"])
      client = connect!(mta)

      assert {:error, client, {:message_too_large, 100}} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body], size: 101)

      # SIZE 0 means no limit.
      mta = start_mta(extensions: ["SIZE 0"])

      assert {:ok, _, _} =
               mta
               |> connect!()
               |> Client.deliver("a@example.org", ["b@example.net"], [@body], size: 10_000)

      assert {:ok, _, _} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body], size: 100)
    end

    test "an 8-bit message to a server without 8BITMIME" do
      mta = start_mta(extensions: ["PIPELINING"])
      client = connect!(mta)

      assert {:error, _client, :eight_bit_not_supported} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body],
                 body_type: :"8bitmime"
               )

      # A 7-bit message goes out without a BODY parameter.
      assert {:ok, _, _} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body],
                 body_type: :"7bit"
               )

      assert_receive {:fake_mta, ^mta, {:message, %{mail_args: "FROM:<a@example.org>"}}}
    end

    test "addresses that could inject commands" do
      mta = start_mta()
      client = connect!(mta)

      for bad <- ["a@example.org>\r\nRSET", "no-at-sign", "a@b@c"] do
        assert {:error, _client, {:invalid_address, ^bad}} =
                 Client.deliver(client, "a@example.org", [bad], [@body])

        assert {:error, _client, {:invalid_address, ^bad}} =
                 Client.deliver(client, bad, ["b@example.net"], [@body])
      end
    end
  end

  describe "deliver/5 with XFORWARD" do
    # Answers like a server that offers XFORWARD NAME ADDR HELO, and
    # sends the test every command line.
    defp xforward_server(test) do
      raw_server(fn socket ->
        :gen_tcp.send(socket, "220 filter.test ESMTP\r\n")
        :ok = :inet.setopts(socket, packet: :line)
        xforward_loop(socket, test)
      end)
    end

    defp xforward_loop(socket, test) do
      {:ok, line} = :gen_tcp.recv(socket, 0, 5_000)
      line = String.trim_trailing(line, "\r\n")
      send(test, {:line, line})

      reply =
        case line do
          "EHLO " <> _ -> "250-filter.test\r\n250-XFORWARD NAME ADDR HELO\r\n250 8BITMIME\r\n"
          "XFORWARD " <> _ -> "250 2.0.0 Ok\r\n"
          "MAIL " <> _ -> "250 2.1.0 Ok\r\n"
          "RCPT " <> _ -> "250 2.1.5 Ok\r\n"
          "DATA" -> "354 Go\r\n"
          "." -> "250 2.0.0 Ok: queued\r\n"
          _ -> nil
        end

      if reply, do: :gen_tcp.send(socket, reply)
      xforward_loop(socket, test)
    end

    test "sends the attributes the server offers before MAIL" do
      port = xforward_server(self())
      {:ok, client} = Client.connect({127, 0, 0, 1}, port, helo: "mx.example.org")

      xforward = %{
        name: "client.example",
        addr: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1},
        port: 4711,
        helo: nil,
        source: "REMOTE"
      }

      assert {:ok, client, [{"b@example.net", :data_end, %Reply{code: 250}}]} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body],
                 xforward: xforward
               )

      assert_receive {:line, "EHLO mx.example.org"}

      assert_receive {:line,
                      "XFORWARD NAME=client.example ADDR=IPV6:2001:db8::1 HELO=[UNAVAILABLE]"}

      assert_receive {:line, "MAIL FROM:<a@example.org>"}

      # IPv4, xtext, and nothing to send for a server without XFORWARD
      # attributes in common.
      assert {:ok, client, _} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body],
                 xforward: %{addr: {192, 0, 2, 1}, helo: "a b"}
               )

      assert_receive {:line, "XFORWARD ADDR=192.0.2.1 HELO=a+20b"}

      assert {:ok, _client, _} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body],
                 xforward: %{ident: "x"}
               )

      assert_receive {:line, "MAIL FROM:<a@example.org>"}
      refute_received {:line, "XFORWARD" <> _}
    end

    test "splits long attribute lists" do
      port = xforward_server(self())
      {:ok, client} = Client.connect({127, 0, 0, 1}, port, helo: "mx.example.org")
      long = String.duplicate("a", 250) <> ".example"

      assert {:ok, _client, _} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body],
                 xforward: %{name: long, helo: long, addr: {192, 0, 2, 1}}
               )

      assert_receive {:line, "XFORWARD NAME=" <> _ = first}
      assert_receive {:line, "XFORWARD HELO=" <> _ = second}
      assert byte_size(first) <= 512 and first =~ " ADDR=192.0.2.1"
      refute second =~ "ADDR"
    end

    test "a server without XFORWARD gets none" do
      mta = start_mta()
      client = connect!(mta)

      assert {:ok, _client, [{_, :data_end, %Reply{code: 250}}]} =
               Client.deliver(client, "a@example.org", ["b@example.net"], [@body],
                 xforward: %{name: "client.example"}
               )
    end
  end
end
