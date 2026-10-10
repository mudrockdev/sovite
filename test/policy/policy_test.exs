defmodule Sovite.PolicyTest do
  use ExUnit.Case, async: true

  alias Sovite.Policy

  doctest Sovite.Policy

  defp encode(attrs), do: attrs |> Policy.encode_request() |> IO.iodata_to_binary()

  describe "encode_request/1" do
    test "adds request=smtpd_access_policy first, unless given" do
      assert encode(%{"sender" => "a@example.com"}) ==
               "request=smtpd_access_policy\nsender=a@example.com\n\n"

      assert encode(protocol_state: "RCPT", request: "other") ==
               "protocol_state=RCPT\nrequest=other\n\n"

      assert encode([]) == "request=smtpd_access_policy\n\n"
    end

    test "formats values" do
      assert encode(
               client_address: {192, 0, 2, 7},
               server_address: {8193, 3512, 0, 0, 0, 0, 0, 1},
               size: 0,
               sasl_sender: nil
             ) ==
               "request=smtpd_access_policy\nclient_address=192.0.2.7\n" <>
                 "server_address=2001:db8::1\nsize=0\nsasl_sender=\n\n"
    end

    test "replaces newlines in values and leaves out invalid names" do
      attrs = [
        {"helo_name", "evil\r\nrecipient=x@example.com\n"},
        {"bad name", "x"},
        {"", "x"},
        {"a=b", "x"},
        {"-dash", "x"},
        {"new\nline", "x"},
        {"x-custom.attr_1", "ok"}
      ]

      assert encode(attrs) ==
               "request=smtpd_access_policy\nhelo_name=evil  recipient=x@example.com \n" <>
                 "x-custom.attr_1=ok\n\n"
    end

    test "sends each name once, with its last value" do
      assert encode([{:sender, "a"}, {:recipient, "b"}, {"sender", "c"}]) ==
               "request=smtpd_access_policy\nrecipient=b\nsender=c\n\n"
    end
  end

  test "encode_reply/1 takes text or a term" do
    assert IO.iodata_to_binary(Policy.encode_reply("DUNNO")) == "action=DUNNO\n\n"
    assert IO.iodata_to_binary(Policy.encode_reply("REJECT a\nb")) == "action=REJECT a b\n\n"
    assert IO.iodata_to_binary(Policy.encode_reply(:ok)) == "action=OK\n\n"
  end

  describe "decode/1" do
    test "decodes the first block" do
      assert Policy.decode("a=1\r\nb=\nc==x\n\n") ==
               {:ok, %{"a" => "1", "b" => "", "c" => "=x"}, ""}

      assert Policy.decode("\nnext") == {:ok, %{}, "next"}
      assert Policy.decode("a=1\na=2\n\n") == {:ok, %{"a" => "2"}, ""}
    end

    test "round-trips requests" do
      attrs = [sender: "a@example.com", recipient: "b@example.net", recipient_count: 2]
      {:ok, decoded, ""} = attrs |> encode() |> Policy.decode()

      assert decoded == %{
               "request" => "smtpd_access_policy",
               "sender" => "a@example.com",
               "recipient" => "b@example.net",
               "recipient_count" => "2"
             }
    end

    test "reports incomplete and malformed blocks" do
      assert Policy.decode("") == {:error, :incomplete}
      assert Policy.decode("a=1\n") == {:error, :incomplete}
      assert Policy.decode("a=1\nb") == {:error, :incomplete}
      assert Policy.decode("garbage\n\n") == {:error, :malformed}
      assert Policy.decode("=x\n\n") == {:error, :malformed}
      assert Policy.decode("bad name=x\n\n") == {:error, :malformed}
    end
  end

  test "postfix_attributes/0 lists the Postfix attributes" do
    names = Policy.postfix_attributes()
    assert length(names) == 31
    assert "request" in names and "mail_version" in names and "ccert_pubkey_fingerprint" in names
  end

  test "delegates actions" do
    assert Policy.parse_action("dunno") == {:ok, :dunno}
    assert Policy.encode_action({:defer, "later"}) == "DEFER later"
  end
end
