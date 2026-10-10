defmodule Sovite.MilterTest do
  use ExUnit.Case, async: true

  alias Sovite.Milter
  alias Sovite.Milter.Packet
  alias Sovite.Test.{FakeMilter, TelemetryForwarder}

  doctest Milter, only: [parse_address: 1]

  defp start_fake(opts \\ []) do
    start_supervised!({FakeMilter, Keyword.put(opts, :owner, self())}, id: make_ref())
  end

  defp connect!(fake, opts \\ []) do
    {:ok, milter} = Milter.connect(FakeMilter.address(fake), opts)
    assert_receive {:milter, :optneg, _}
    milter
  end

  defp fake_milter(fake_opts \\ [], opts \\ []), do: connect!(start_fake(fake_opts), opts)

  describe "parse_address/1" do
    test "Postfix and Sendmail syntax" do
      assert Milter.parse_address("inet:localhost:11332") == {:ok, {:inet, "localhost", 11_332}}

      assert Milter.parse_address("inet:[::1]:8891") ==
               {:ok, {:inet, {0, 0, 0, 0, 0, 0, 0, 1}, 8891}}

      assert Milter.parse_address("inet6:8891@[::1]") ==
               {:ok, {:inet, {0, 0, 0, 0, 0, 0, 0, 1}, 8891}}

      assert Milter.parse_address("inet6:8891@localhost") == {:ok, {:inet6, "localhost", 8891}}
      assert Milter.parse_address("local:/run/a.sock") == {:ok, {:unix, "/run/a.sock"}}
    end

    test "rejects anything else" do
      for address <- [
            "inet:host",
            "inet:host:0",
            "inet:host:x",
            "inet::25",
            "inet:99999@h",
            "unix:",
            "tcp:a:1",
            ""
          ] do
        assert Milter.parse_address(address) == {:error, :invalid_address}
      end
    end
  end

  describe "connect/2" do
    test "negotiates version 6" do
      fake = start_fake(protocol: [:no_unknown, :skip], actions: [:add_headers, :quarantine])
      {:ok, milter} = Milter.connect(FakeMilter.address(fake), name: "test")

      assert_receive {:milter, :optneg, offered}
      assert offered.version == 6
      assert offered.actions == Packet.actions(0x1FF)
      assert offered.protocol == Packet.protocol(0x1FFFFF)

      assert Milter.info(milter) == %{
               name: "test",
               version: 6,
               actions: [:add_headers, :quarantine],
               protocol: [:no_unknown, :skip],
               macros: %{}
             }

      assert Milter.quit(milter) == :ok
      assert_receive {:milter, :quit, nil}
    end

    test "offers only the allowed actions" do
      milter = fake_milter([], actions: [:add_headers, :change_headers])
      assert Milter.info(milter).actions == [:add_headers, :change_headers]
    end

    test "accepts older versions without what they do not know" do
      fake =
        start_fake(
          version: 2,
          protocol: [:no_helo, :no_unknown, :skip, :no_header_reply],
          macros: %{connect: ["j"]}
        )

      milter = connect!(fake)
      info = Milter.info(milter)
      assert info.version == 2
      assert info.protocol == [:no_helo]
      assert :change_sender not in info.actions
      assert :quarantine in info.actions
      assert info.macros == %{}

      # DATA (version 4) and unknown commands (version 3) are not sent.
      assert {:ok, :continue, milter} = Milter.data(milter, %{"i" => "1"})
      assert {:ok, :continue, milter} = Milter.unknown(milter, "FOO")
      assert {:ok, :continue, _milter} = Milter.mail(milter, "a@example.net")
      assert_receive {:milter, :mail, ["<a@example.net>"]}
      refute_received {:milter, :data, _}
      refute_received {:milter, :unknown, _}
      refute_received {:milter, :macro, _}

      milter = connect!(start_fake(version: 3))
      assert {:ok, :continue, milter} = Milter.unknown(milter, "FOO")
      assert_receive {:milter, :unknown, "FOO"}
      assert {:ok, :continue, _milter} = Milter.data(milter)
      refute_received {:milter, :data, _}
    end

    test "treats newer versions as version 6" do
      assert Milter.info(fake_milter(version: 7)).version == 6
    end

    test "refuses version 1 and broken negotiations" do
      fake = start_fake(version: 1)

      assert Milter.connect(FakeMilter.address(fake)) ==
               {:error, {:protocol, {:unsupported_version, 1}}}

      fake = start_fake(optneg: :continue)

      assert Milter.connect(FakeMilter.address(fake)) ==
               {:error, {:protocol, {:unexpected_response, ?c}}}

      fake = start_fake(optneg: {:bytes, <<5::32, ?O, 6::32>>})
      assert Milter.connect(FakeMilter.address(fake)) == {:error, {:protocol, {:malformed, ?O}}}

      fake = start_fake(optneg: :close)
      assert Milter.connect(FakeMilter.address(fake)) == {:error, :closed}

      fake = start_fake(optneg: :none)

      assert Milter.connect(FakeMilter.address(fake), command_timeout: 50) ==
               {:error, :timeout}
    end

    test "reports connection failures" do
      {:ok, listen} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
      {:ok, port} = :inet.port(listen)
      :gen_tcp.close(listen)

      assert Milter.connect({:inet, "127.0.0.1", port}) == {:error, {:connect, :econnrefused}}

      assert {:error, {:connect, _}} =
               Milter.connect({:unix, "/tmp/sovite-no-such-milter.sock"})
    end

    test "connects over a Unix socket" do
      # Unix socket paths are limited to ~100 bytes: keep it short.
      path = "/tmp/sovite-milter-#{System.unique_integer([:positive])}.sock"
      on_exit(fn -> File.rm(path) end)
      fake = start_fake(path: path)
      assert FakeMilter.address(fake) == {:unix, path}

      milter = connect!(fake)
      assert {:ok, :continue, milter} = Milter.helo(milter, "client.example.net")
      assert_receive {:milter, :helo, "client.example.net"}
      assert Milter.close(milter) == :ok
    end

    test "emits telemetry" do
      TelemetryForwarder.attach([
        [:sovite, :milter, :connect, :start],
        [:sovite, :milter, :connect, :stop]
      ])

      fake = start_fake()
      {:inet, ip, port} = address = FakeMilter.address(fake)
      {:ok, _milter} = Milter.connect(address)
      name = "inet:127.0.0.1:#{port}"

      assert_receive {:telemetry, [:sovite, :milter, :connect, :start], _,
                      %{milter: ^name, address: {:inet, ^ip, ^port}}}

      assert_receive {:telemetry, [:sovite, :milter, :connect, :stop], %{duration: _},
                      %{milter: ^name, result: {:ok, 6}}}

      fake = start_fake(version: 1)
      {:error, _} = Milter.connect(FakeMilter.address(fake), name: "v1")

      assert_receive {:telemetry, [:sovite, :milter, :connect, :stop], _,
                      %{milter: "v1", result: {:error, {:protocol, {:unsupported_version, 1}}}}}
    end
  end

  describe "steps" do
    test "a whole session" do
      milter = fake_milter()

      assert {:ok, :continue, milter} =
               Milter.connect_info(milter, "client.example.net", {{192, 0, 2, 1}, 52_314}, %{
                 "j" => "mx.example.com"
               })

      assert_receive {:milter, :macro, {:connect, [{"j", "mx.example.com"}]}}
      assert_receive {:milter, :connect, {"client.example.net", :inet, 52_314, "192.0.2.1"}}

      assert {:ok, :continue, milter} = Milter.helo(milter, "client.example.net")
      assert_receive {:milter, :helo, "client.example.net"}

      assert {:ok, :continue, milter} =
               Milter.mail(milter, "alice@example.net", ["SIZE=10"], [{"i", "ABC"}])

      assert_receive {:milter, :macro, {:mail, [{"i", "ABC"}]}}
      assert_receive {:milter, :mail, ["<alice@example.net>", "SIZE=10"]}

      assert {:ok, :continue, milter} = Milter.rcpt(milter, "bob@example.com", ["NOTIFY=NEVER"])
      assert_receive {:milter, :rcpt, ["<bob@example.com>", "NOTIFY=NEVER"]}

      assert {:ok, :continue, milter} = Milter.data(milter)
      assert_receive {:milter, :data, nil}

      assert {:ok, :continue, milter} = Milter.header(milter, "Subject", " Hello\r\n world")
      assert_receive {:milter, :header, {"Subject", "Hello\n world"}}
      assert {:ok, :continue, milter} = Milter.header(milter, "X-Empty", "")
      assert_receive {:milter, :header, {"X-Empty", ""}}

      assert {:ok, :continue, milter} = Milter.end_of_headers(milter)
      assert_receive {:milter, :end_of_headers, nil}

      assert {:ok, :continue, milter} = Milter.body(milter, ["Hi Bob.\r\n", "Bye.\r\n"])
      assert_receive {:milter, :body, "Hi Bob.\r\nBye.\r\n"}
      assert {:ok, :continue, milter} = Milter.body(milter, "")

      assert {:ok, :accept, [], milter} = Milter.end_of_message(milter, %{"i" => "ABC"})
      assert_receive {:milter, :macro, {:end_of_message, [{"i", "ABC"}]}}
      assert_receive {:milter, :end_of_message, nil}

      # The next transaction, abandoned.
      assert {:ok, :continue, milter} = Milter.mail(milter, "")
      assert_receive {:milter, :mail, ["<>"]}
      assert {:ok, milter} = Milter.abort(milter)
      assert_receive {:milter, :abort, nil}

      assert {:ok, :continue, milter} = Milter.unknown(milter, "FOO bar")
      assert_receive {:milter, :unknown, "FOO bar"}

      assert Milter.quit(milter) == :ok
      assert_receive {:milter, :quit, nil}
    end

    test "client families" do
      milter = fake_milter()

      assert {:ok, :continue, milter} =
               Milter.connect_info(
                 milter,
                 "[2001:db8::1]",
                 {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, 25}
               )

      assert_receive {:milter, :connect, {"[2001:db8::1]", :inet6, 25, "2001:db8::1"}}

      assert {:ok, :continue, milter} = Milter.connect_info(milter, "localhost", {:unix, "/s"})
      assert_receive {:milter, :connect, {"localhost", :unix, 0, "/s"}}

      assert {:ok, :continue, _milter} = Milter.connect_info(milter, "unknown", :unknown)
      assert_receive {:milter, :connect, {"unknown", :unknown, nil, nil}}
    end

    test "keeps the leading space of header values when negotiated" do
      milter =
        fake_milter(
          protocol: [:header_leading_space],
          modifications: [{:add_header, "X-A", " 1"}, {:insert_header, 0, "X-B", "\t2\n\t3"}]
        )

      assert {:ok, :continue, milter} = Milter.header(milter, "Subject", " Hello")
      assert_receive {:milter, :header, {"Subject", " Hello"}}

      assert {:ok, :accept, modifications, _milter} = Milter.end_of_message(milter)

      assert modifications == [
               {:add_header, "X-A", " 1"},
               {:insert_header, 0, "X-B", "\t2\r\n\t3"}
             ]
    end

    test "skips the steps the milter declined, but sends their macros" do
      milter =
        fake_milter(
          protocol: [
            :no_connect,
            :no_helo,
            :no_mail,
            :no_rcpt,
            :no_data,
            :no_headers,
            :no_end_of_headers,
            :no_body,
            :no_unknown
          ]
        )

      assert {:ok, :continue, milter} =
               Milter.connect_info(milter, "h", {{192, 0, 2, 1}, 1}, %{"j" => "mx"})

      assert_receive {:milter, :macro, {:connect, [{"j", "mx"}]}}
      assert {:ok, :continue, milter} = Milter.helo(milter, "h")
      assert {:ok, :continue, milter} = Milter.mail(milter, "a@example.net")
      assert {:ok, :continue, milter} = Milter.rcpt(milter, "b@example.com")
      assert {:ok, :continue, milter} = Milter.data(milter)
      assert {:ok, :continue, milter} = Milter.header(milter, "Subject", " x")
      assert {:ok, :continue, milter} = Milter.end_of_headers(milter)
      assert {:ok, :continue, milter} = Milter.body(milter, "x\r\n")
      assert {:ok, :continue, milter} = Milter.unknown(milter, "FOO")
      assert {:ok, :accept, [], _milter} = Milter.end_of_message(milter)

      assert_receive {:milter, :end_of_message, nil}

      for command <- [:connect, :helo, :mail, :rcpt, :data, :header, :end_of_headers, :body] do
        refute_received {:milter, ^command, _}
      end
    end

    test "does not wait for replies the milter will not send" do
      milter =
        fake_milter(
          protocol: [
            :no_connect_reply,
            :no_helo_reply,
            :no_mail_reply,
            :no_rcpt_reply,
            :no_data_reply,
            :no_header_reply,
            :no_end_of_headers_reply,
            :no_body_reply,
            :no_unknown_reply
          ],
          modifications: [{:add_header, "X-A", "1"}]
        )

      assert {:ok, :continue, milter} = Milter.connect_info(milter, "h", {{192, 0, 2, 1}, 1})
      assert {:ok, :continue, milter} = Milter.helo(milter, "h")
      assert {:ok, :continue, milter} = Milter.mail(milter, "a@example.net")
      assert {:ok, :continue, milter} = Milter.rcpt(milter, "b@example.com")
      assert {:ok, :continue, milter} = Milter.data(milter)
      assert {:ok, :continue, milter} = Milter.header(milter, "Subject", " x")
      assert {:ok, :continue, milter} = Milter.end_of_headers(milter)
      assert {:ok, :continue, milter} = Milter.body(milter, :binary.copy("x", 70_000))
      assert {:ok, :continue, milter} = Milter.unknown(milter, "FOO")
      assert {:ok, :accept, [{:add_header, "X-A", " 1"}], _milter} = Milter.end_of_message(milter)

      for command <- [
            :connect,
            :helo,
            :mail,
            :rcpt,
            :data,
            :header,
            :end_of_headers,
            :body,
            :body
          ] do
        assert_receive {:milter, ^command, _}
      end
    end

    test "sends only the macros the milter asked for" do
      milter =
        fake_milter(
          macros: %{
            connect: ["{client_addr}", "j", "{missing}", "daemon_name"],
            mail: ["{mail_addr}"],
            rcpt: []
          }
        )

      assert Milter.info(milter).macros == %{
               connect: ["{client_addr}", "j", "{missing}", "daemon_name"],
               mail: ["{mail_addr}"],
               rcpt: []
             }

      macros = %{
        "j" => "mx",
        "client_addr" => "192.0.2.1",
        "{daemon_name}" => "smtpd",
        "{mail_addr}" => "a@example.net",
        "i" => "ABC"
      }

      {:ok, :continue, milter} = Milter.connect_info(milter, "h", {{192, 0, 2, 1}, 1}, macros)

      assert_receive {:milter, :macro,
                      {:connect,
                       [{"{client_addr}", "192.0.2.1"}, {"j", "mx"}, {"daemon_name", "smtpd"}]}}

      {:ok, :continue, milter} = Milter.mail(milter, "a@example.net", [], macros)
      assert_receive {:milter, :macro, {:mail, [{"{mail_addr}", "a@example.net"}]}}

      # Asked for none at RCPT; all of them at DATA, where it did not ask.
      {:ok, :continue, milter} = Milter.rcpt(milter, "b@example.com", [], macros)
      assert_receive {:milter, :rcpt, _}
      refute_received {:milter, :macro, {:rcpt, _}}

      {:ok, :continue, _milter} = Milter.data(milter, [{"i", "ABC"}, {"j", "mx"}])
      assert_receive {:milter, :macro, {:data, [{"i", "ABC"}, {"j", "mx"}]}}
    end
  end

  describe "replies" do
    test "a message accepted early skips the rest of the transaction" do
      milter = fake_milter(replies: %{mail: :accept})

      assert {:ok, :accept, milter} = Milter.mail(milter, "a@example.net")
      assert {:ok, :accept, milter} = Milter.rcpt(milter, "b@example.com")
      assert {:ok, :accept, milter} = Milter.data(milter)
      assert {:ok, :accept, milter} = Milter.header(milter, "Subject", " x")
      assert {:ok, :accept, milter} = Milter.end_of_headers(milter)
      assert {:ok, :accept, milter} = Milter.body(milter, "x")
      assert {:ok, :accept, [], milter} = Milter.end_of_message(milter)

      assert_receive {:milter, :mail, _}
      refute_received {:milter, _, _}

      # The next transaction is filtered again.
      assert {:ok, :accept, milter} = Milter.mail(milter, "a@example.net")
      assert {:ok, milter} = Milter.abort(milter)
      assert_receive {:milter, :abort, nil}
      assert {:ok, :continue, _milter} = Milter.helo(milter, "h")
    end

    test "a recipient's rejection is about that recipient" do
      replies = %{
        rcpt: fn
          ["<bad@example.com>" | _] -> :reject
          ["<later@example.com>" | _] -> :tempfail
          ["<code@example.com>" | _] -> {:reply_code, "550 5.1.1 No such user"}
          ["<trash@example.com>" | _] -> :discard
          _ -> :continue
        end
      }

      milter = fake_milter(replies: replies)
      {:ok, :continue, milter} = Milter.mail(milter, "a@example.net")
      assert {:ok, :reject, milter} = Milter.rcpt(milter, "bad@example.com")
      assert {:ok, :tempfail, milter} = Milter.rcpt(milter, "later@example.com")

      assert {:ok, {:reply, 550, "5.1.1", "No such user"}, milter} =
               Milter.rcpt(milter, "code@example.com")

      assert {:ok, :continue, milter} = Milter.rcpt(milter, "good@example.com")
      assert {:ok, :discard, milter} = Milter.rcpt(milter, "trash@example.com")
      assert {:ok, :discard, milter} = Milter.rcpt(milter, "good@example.com")
      assert {:ok, :discard, [], _milter} = Milter.end_of_message(milter)
    end

    test "a rejection during the message ends it" do
      milter =
        fake_milter(
          replies: %{header: fn {name, _} -> if name == "X-Bad", do: :reject, else: :default end}
        )

      {:ok, :continue, milter} = Milter.mail(milter, "a@example.net")
      assert {:ok, :continue, milter} = Milter.header(milter, "Subject", " x")
      assert {:ok, :reject, milter} = Milter.header(milter, "X-Bad", " x")
      assert {:ok, :reject, milter} = Milter.header(milter, "X-Other", " x")
      assert {:ok, milter} = Milter.abort(milter)
      assert {:ok, :continue, _milter} = Milter.mail(milter, "a@example.net")
    end

    test "a final reply at the connection steps ends the session" do
      for {step, reply} <- [connect: :reject, connect: :tempfail, helo: :accept] do
        milter = fake_milter(replies: %{step => reply})
        {:ok, first, milter} = Milter.connect_info(milter, "h", {{192, 0, 2, 1}, 1})

        {:ok, ^reply, milter} =
          if first == reply, do: {:ok, reply, milter}, else: Milter.helo(milter, "h")

        assert {:ok, ^reply, milter} = Milter.helo(milter, "h")
        assert {:ok, ^reply, milter} = Milter.mail(milter, "a@example.net")
        assert {:ok, ^reply, milter} = Milter.unknown(milter, "FOO")
        assert {:ok, milter} = Milter.abort(milter)
        assert {:ok, ^reply, [], milter} = Milter.end_of_message(milter)
        assert {:ok, ^reply, _milter} = Milter.rcpt(milter, "b@example.com")
      end

      refute_received {:milter, :abort, _}
      refute_received {:milter, :mail, _}
    end

    test "shutdown and connection failure end the session" do
      for response <- [:shutdown, :connection_failure] do
        milter = fake_milter(replies: %{mail: response})
        assert {:ok, :shutdown, milter} = Milter.mail(milter, "a@example.net")
        assert {:ok, :shutdown, _milter} = Milter.helo(milter, "h")
      end
    end

    test "an unknown command's reply does not change the session" do
      milter = fake_milter(replies: %{unknown: :reject})
      assert {:ok, :reject, milter} = Milter.unknown(milter, "FOO")
      assert {:ok, :continue, _milter} = Milter.helo(milter, "h")
    end

    test "reply codes" do
      codes = [
        {"451 4.7.1 Try again later", {:reply, 451, "4.7.1", "Try again later"}},
        {"554 Go away", {:reply, 554, nil, "Go away"}},
        {"550 5.7.1 Line\r\n", {:reply, 550, "5.7.1", "Line"}},
        {"550-5.7.1 First\r\n550-5.7.1 Second\r\n550 5.7.1 Third",
         {:reply, 550, "5.7.1", ["First", "Second", "Third"]}}
      ]

      for {text, reply} <- codes do
        milter = fake_milter(replies: %{helo: {:reply_code, text}})
        assert {:ok, ^reply, _milter} = Milter.helo(milter, "h")
      end

      for text <- ["250 2.0.0 Ok", "garbage", "550-5.7.1 a\r\n551 5.7.1 b", ""] do
        milter = fake_milter(replies: %{helo: {:reply_code, text}})
        assert Milter.helo(milter, "h") == {:error, {:protocol, {:malformed_reply_code, text}}}
      end
    end
  end

  describe "body/2" do
    test "sends chunks of at most 65535 bytes" do
      milter = fake_milter()
      body = :binary.copy("x", 65_535 * 2 + 10)
      assert {:ok, :continue, _milter} = Milter.body(milter, body)

      assert_receive {:milter, :body, first}
      assert_receive {:milter, :body, second}
      assert_receive {:milter, :body, third}
      assert {byte_size(first), byte_size(second), byte_size(third)} == {65_535, 65_535, 10}
    end

    test "stops sending the body after SMFIR_SKIP" do
      milter = fake_milter(protocol: [:skip], replies: %{body: :skip})
      {:ok, :continue, milter} = Milter.mail(milter, "a@example.net")
      assert {:ok, :continue, milter} = Milter.body(milter, :binary.copy("x", 65_536))
      assert {:ok, :continue, milter} = Milter.body(milter, "more")
      assert {:ok, :accept, [], milter} = Milter.end_of_message(milter)

      assert_receive {:milter, :body, _}
      assert_receive {:milter, :end_of_message, nil}
      refute_received {:milter, :body, _}

      # The next message's body is sent again.
      {:ok, :continue, milter} = Milter.mail(milter, "a@example.net")
      assert {:ok, :continue, _milter} = Milter.body(milter, "x")
      assert_receive {:milter, :body, "x"}
    end

    test "stops at a final reply" do
      milter = fake_milter(replies: %{body: :discard})
      {:ok, :continue, milter} = Milter.mail(milter, "a@example.net")
      assert {:ok, :discard, milter} = Milter.body(milter, :binary.copy("x", 65_536))
      assert {:ok, :discard, _milter} = Milter.body(milter, "more")
      assert_receive {:milter, :body, _}
      refute_received {:milter, :body, _}
    end

    test "SMFIR_SKIP is only for the body" do
      milter = fake_milter(replies: %{helo: :skip})
      assert Milter.helo(milter, "h") == {:error, {:protocol, {:unexpected_response, ?s}}}
    end
  end

  describe "end_of_message/2" do
    test "returns every modification, in order" do
      modifications = [
        {:add_header, "X-Spam", "yes"},
        {:replace_body, "new "},
        {:insert_header, 0, "DKIM-Signature", "v=1;\n\tb=abc"},
        {:change_header, 2, "Subject", "changed"},
        {:delete_header, 1, "X-Old"},
        :progress,
        {:add_recipient, "<carol@example.com>"},
        {:add_recipient_with_args, "<dave@example.com>", "NOTIFY=NEVER ORCPT=rfc822;d@x"},
        {:add_recipient_with_args, "erin@example.com", nil},
        {:delete_recipient, "<bob@example.com>"},
        {:replace_body, "body\r\n"},
        {:change_sender, "<>", nil},
        {:change_sender, "<b@example.net>", "SIZE=10"},
        {:quarantine, "suspicious"}
      ]

      milter = fake_milter(modifications: modifications)

      assert {:ok, :accept, result, _milter} = Milter.end_of_message(milter)

      assert result == [
               {:add_header, "X-Spam", " yes"},
               {:replace_body, ["new ", "body\r\n"]},
               {:insert_header, 0, "DKIM-Signature", " v=1;\r\n\tb=abc"},
               {:change_header, 2, "Subject", " changed"},
               {:delete_header, 1, "X-Old"},
               {:add_recipient, "carol@example.com", []},
               {:add_recipient, "dave@example.com", ["NOTIFY=NEVER", "ORCPT=rfc822;d@x"]},
               {:add_recipient, "erin@example.com", []},
               {:delete_recipient, "bob@example.com"},
               {:change_sender, "", []},
               {:change_sender, "b@example.net", ["SIZE=10"]},
               {:quarantine, "suspicious"}
             ]
    end

    test "decides by the whole session, like Rspamd" do
      replies = %{
        end_of_message: fn _data, session ->
          verdict = if hd(session.mail) == "<spam@example.net>", do: :reject, else: :continue
          [{:add_header, "X-Spam", if(verdict == :reject, do: "yes", else: "no")}, verdict]
        end
      }

      milter = fake_milter(replies: replies)
      {:ok, :continue, milter} = Milter.mail(milter, "spam@example.net")

      assert {:ok, :reject, [{:add_header, "X-Spam", " yes"}], milter} =
               Milter.end_of_message(milter)

      {:ok, :continue, milter} = Milter.mail(milter, "ham@example.net")
      assert {:ok, :continue, [{:add_header, "X-Spam", " no"}], _} = Milter.end_of_message(milter)
    end

    test "refuses modifications that were not negotiated" do
      milter = fake_milter([modifications: [{:quarantine, "x"}]], actions: [:add_headers])

      assert Milter.end_of_message(milter) ==
               {:error, {:protocol, {:action_not_negotiated, :quarantine}}}

      milter = fake_milter(actions: [:add_headers], modifications: [{:change_sender, "<a>", nil}])

      assert Milter.end_of_message(milter) ==
               {:error, {:protocol, {:action_not_negotiated, :change_sender}}}
    end

    test "refuses responses that do not belong" do
      milter = fake_milter(replies: %{end_of_message: [:skip]})
      assert Milter.end_of_message(milter) == {:error, {:protocol, {:unexpected_response, ?s}}}

      milter = fake_milter(replies: %{end_of_message: [{:set_macros, 0, "j"}]})
      assert Milter.end_of_message(milter) == {:error, {:protocol, {:unexpected_response, ?l}}}

      milter = fake_milter(replies: %{end_of_message: [{:bytes, <<2::32, ?h, 0>>}]})
      assert Milter.end_of_message(milter) == {:error, {:protocol, {:malformed, ?h}}}
    end
  end

  describe "errors" do
    test "a modification before the end of the message" do
      milter = fake_milter(replies: %{helo: {:add_header, "X", "y"}})
      assert Milter.helo(milter, "h") == {:error, {:protocol, {:unexpected_response, ?h}}}
    end

    test "unknown, empty, and oversized packets" do
      milter = fake_milter(replies: %{helo: {:bytes, <<1::32, ?Z>>}})
      assert Milter.helo(milter, "h") == {:error, {:protocol, {:unknown_command, ?Z}}}

      milter = fake_milter(replies: %{helo: {:bytes, <<0::32>>}})
      assert Milter.helo(milter, "h") == {:error, {:protocol, :empty_packet}}

      milter = fake_milter([replies: %{helo: {:bytes, <<1000::32>>}}], max_packet_size: 100)
      assert Milter.helo(milter, "h") == {:error, {:protocol, {:packet_too_large, 1000}}}
    end

    test "timeouts" do
      milter = fake_milter([replies: %{helo: [{:delay, 300}, :continue]}], command_timeout: 50)
      assert Milter.helo(milter, "h") == {:error, :timeout}

      milter = fake_milter([replies: %{body: [{:delay, 300}, :continue]}], content_timeout: 50)
      assert Milter.body(milter, "x") == {:error, :timeout}
    end

    # Each gap (400ms) is well within the timeout, and all of them
    # together (1.2s) are not: only the progress reports keep it waiting.
    test "progress reports extend the timeout" do
      replies = %{
        helo: [
          :progress,
          {:delay, 400},
          :progress,
          {:delay, 400},
          :progress,
          {:delay, 400},
          :continue
        ],
        end_of_message: [
          {:add_header, "X", "1"},
          {:delay, 400},
          :progress,
          {:delay, 400},
          :progress,
          {:delay, 400},
          :accept
        ]
      }

      milter = fake_milter([replies: replies], command_timeout: 1_000, content_timeout: 1_000)
      assert {:ok, :continue, milter} = Milter.helo(milter, "h")
      assert {:ok, :accept, [{:add_header, "X", " 1"}], _milter} = Milter.end_of_message(milter)
    end

    test "a closed connection" do
      milter = fake_milter(replies: %{helo: :close})
      assert Milter.helo(milter, "h") == {:error, :closed}

      milter = fake_milter(replies: %{helo: :close})
      assert {:error, :closed} = Milter.helo(milter, "h")
      assert {:error, _} = Milter.abort(milter)
      assert Milter.quit(milter) == :ok
    end

    test "emit telemetry, as do replies" do
      TelemetryForwarder.attach([[:sovite, :milter, :reply], [:sovite, :milter, :error]])
      name = "telemetry-#{System.unique_integer([:positive])}"

      milter =
        fake_milter([replies: %{rcpt: :close}, modifications: [{:add_header, "X", "1"}]],
          name: name
        )

      {:ok, :continue, milter} = Milter.helo(milter, "h")

      assert_receive {:telemetry, [:sovite, :milter, :reply], %{duration: _},
                      %{milter: ^name, stage: :helo, reply: :continue}}

      {:ok, :accept, _, milter} = Milter.end_of_message(milter)

      assert_receive {:telemetry, [:sovite, :milter, :reply], _,
                      %{milter: ^name, stage: :end_of_message, reply: :accept, modifications: 1}}

      {:error, :closed} = Milter.rcpt(milter, "b@example.com")

      assert_receive {:telemetry, [:sovite, :milter, :error], %{},
                      %{milter: ^name, stage: :rcpt, reason: :closed}}
    end
  end
end
