defmodule Sovite.Milter.PacketTest do
  use ExUnit.Case, async: true

  alias Sovite.Milter.Packet

  doctest Packet

  defp round_trip(encoded, decode) do
    binary = IO.iodata_to_binary(encoded)
    assert {:ok, {byte, data}, ""} = Packet.decode(binary, 1_000_000)
    decode.(byte, data)
  end

  describe "commands" do
    test "round-trip" do
      commands = [
        {:optneg, 6, 0x1FF, 0x1FFFFF},
        {:macro, ?C, [{"j", "mx.example.com"}, {"{daemon_name}", "smtpd"}]},
        {:macro, ?E, []},
        {:connect, "client.example.net", :inet, 52_314, "192.0.2.1"},
        {:connect, "[2001:db8::1]", :inet6, 25, "2001:db8::1"},
        {:connect, "localhost", :unix, 0, "/run/client.sock"},
        {:connect, "unknown", :unknown, nil, nil},
        {:helo, "client.example.net"},
        {:mail, ["<alice@example.net>", "SIZE=10", "BODY=8BITMIME"]},
        {:rcpt, ["<bob@example.com>"]},
        :data,
        {:header, "Subject", "Hello\n\tworld"},
        :end_of_headers,
        {:body, "line\r\n"},
        :end_of_message,
        :abort,
        :quit,
        :quit_new_connection,
        {:unknown, "FOO bar"}
      ]

      for command <- commands do
        assert round_trip(Packet.encode_command(command), &Packet.decode_command/2) ==
                 {:ok, command}
      end
    end

    test "the wire format" do
      assert IO.iodata_to_binary(Packet.encode_command({:connect, "h", :inet, 25, "1.2.3.4"})) ==
               <<14::32, ?C, "h", 0, ?4, 25::16, "1.2.3.4", 0>>

      assert IO.iodata_to_binary(Packet.encode_command({:optneg, 6, 1, 2})) ==
               <<13::32, ?O, 6::32, 1::32, 2::32>>

      assert IO.iodata_to_binary(Packet.encode_command({:macro, ?M, [{"i", "ABC"}]})) ==
               <<8::32, ?D, ?M, "i", 0, "ABC", 0>>
    end

    test "rejects malformed data" do
      assert Packet.decode_command(?O, <<6::32>>) == {:error, {:malformed, ?O}}
      assert Packet.decode_command(?D, "") == {:error, {:malformed, ?D}}
      assert Packet.decode_command(?D, <<?C, "j", 0>>) == {:error, {:malformed, ?D}}
      assert Packet.decode_command(?D, <<?C, "j">>) == {:error, {:malformed, ?D}}
      assert Packet.decode_command(?C, "host") == {:error, {:malformed, ?C}}
      assert Packet.decode_command(?C, <<"host", 0, ?X>>) == {:error, {:malformed, ?C}}

      assert Packet.decode_command(?C, <<"host", 0, ?4, 25::16, "1.2.3.4">>) ==
               {:error, {:malformed, ?C}}

      assert Packet.decode_command(?H, "name") == {:error, {:malformed, ?H}}
      assert Packet.decode_command(?M, "") == {:error, {:malformed, ?M}}
      assert Packet.decode_command(?L, <<"Subject", 0>>) == {:error, {:malformed, ?L}}
      assert Packet.decode_command(?Z, "") == {:error, {:unknown_command, ?Z}}
    end
  end

  describe "responses" do
    test "round-trip" do
      responses = [
        {:optneg, 6, 0x1FF, 0x400, []},
        {:optneg, 6, 0x11, 0, [{0, "j {client_addr}"}, {5, ""}]},
        :continue,
        :accept,
        :reject,
        :tempfail,
        :discard,
        :skip,
        :progress,
        :connection_failure,
        :shutdown,
        {:reply_code, "550 5.7.1 No"},
        {:add_recipient, "<carol@example.com>"},
        {:add_recipient_with_args, "<carol@example.com>", "NOTIFY=NEVER"},
        {:add_recipient_with_args, "<carol@example.com>", nil},
        {:delete_recipient, "<bob@example.com>"},
        {:replace_body, "new body\r\n"},
        {:add_header, "X-Spam", "yes"},
        {:insert_header, 0, "DKIM-Signature", "v=1"},
        {:change_header, 2, "Subject", ""},
        {:change_sender, "<>", nil},
        {:change_sender, "<a@example.com>", "SIZE=1"},
        {:quarantine, "virus"},
        {:set_macros, 2, "{mail_addr}"}
      ]

      for response <- responses do
        assert round_trip(Packet.encode_response(response), &Packet.decode_response/2) ==
                 {:ok, response}
      end
    end

    test "an old milter's negotiation without macro requests" do
      assert Packet.decode_response(?O, <<2::32, 1::32, 0::32>>) == {:ok, {:optneg, 2, 1, 0, []}}
    end

    test "rejects malformed data" do
      assert Packet.decode_response(?O, <<6::32, 0::32>>) == {:error, {:malformed, ?O}}

      assert Packet.decode_response(?O, <<6::32, 0::32, 0::32, 1::32, "j">>) ==
               {:error, {:malformed, ?O}}

      assert Packet.decode_response(?O, <<6::32, 0::32, 0::32, 1::16>>) ==
               {:error, {:malformed, ?O}}

      assert Packet.decode_response(?y, "550 no") == {:error, {:malformed, ?y}}
      assert Packet.decode_response(?2, "<a>") == {:error, {:malformed, ?2}}
      assert Packet.decode_response(?h, <<"X", 0>>) == {:error, {:malformed, ?h}}
      assert Packet.decode_response(?i, <<1::16>>) == {:error, {:malformed, ?i}}
      assert Packet.decode_response(?m, <<1::32, "X", 0>>) == {:error, {:malformed, ?m}}
      assert Packet.decode_response(?e, <<"a", 0, "b", 0, "c", 0>>) == {:error, {:malformed, ?e}}
      assert Packet.decode_response(?l, "") == {:error, {:malformed, ?l}}
      assert Packet.decode_response(?Z, "") == {:error, {:unknown_command, ?Z}}
    end
  end

  describe "decode/2" do
    test "waits for whole packets" do
      packet = IO.iodata_to_binary(Packet.encode_response({:add_header, "X", "y"}))

      assert Packet.decode(binary_part(packet, 0, 3), 100) == :more
      assert Packet.decode(binary_part(packet, 0, 8), 100) == :more
      assert Packet.decode(packet <> "next", 100) == {:ok, {?h, <<"X", 0, "y", 0>>}, "next"}
    end

    test "rejects empty and oversized packets as soon as the length is in" do
      assert Packet.decode(<<0::32>>, 100) == {:error, :empty_packet}
      assert Packet.decode(<<101::32>>, 100) == {:error, {:packet_too_large, 101}}
      assert {:ok, {?c, ""}, ""} = Packet.decode(<<1::32, ?c>>, 1)
    end
  end

  test "flags" do
    assert Packet.actions(0x1FF) == [
             :add_headers,
             :change_body,
             :add_recipients,
             :delete_recipients,
             :change_headers,
             :quarantine,
             :change_sender,
             :add_recipients_with_args,
             :set_macros
           ]

    assert Packet.action_mask(Packet.actions(0x1FF)) == 0x1FF
    assert Packet.protocol_mask(Packet.protocol(0x1FFFFF)) == 0x1FFFFF
    assert Packet.protocol(0x100400) == [:skip, :header_leading_space]
    assert Packet.protocol_mask([:no_connect, :no_body_reply]) == 0x80001
  end
end
