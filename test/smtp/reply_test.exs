defmodule Sovite.SMTP.ReplyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.SMTP.Reply

  doctest Reply

  describe "decode/2" do
    test "decodes single- and multi-line replies and returns the rest" do
      assert Reply.decode("220 mx.example ESMTP\r\n") ==
               {:ok, %Reply{code: 220, lines: ["mx.example ESMTP"]}, ""}

      assert Reply.decode("250-mx.example\r\n250-PIPELINING\r\n250 SIZE 10\r\n250 next\r\n") ==
               {:ok, %Reply{code: 250, lines: ["mx.example", "PIPELINING", "SIZE 10"]},
                "250 next\r\n"}
    end

    test "waits for the last line" do
      assert Reply.decode("") == :more
      assert Reply.decode("250-mx.example\r\n250 SIZ") == :more
      assert Reply.decode("250 ok") == :more
    end

    test "accepts a code without text and a bare LF" do
      assert Reply.decode("250\r\n") == {:ok, %Reply{code: 250, lines: [""]}, ""}
      assert Reply.decode("250 ok\n") == {:ok, %Reply{code: 250, lines: ["ok"]}, ""}
    end

    test "extracts an enhanced status code of the same class from every line" do
      assert {:ok, reply, ""} =
               Reply.decode(
                 "550-5.1.1 The email account does not exist.\r\n550 5.1.1 Try again\r\n"
               )

      assert reply == %Reply{
               code: 550,
               enhanced: "5.1.1",
               lines: ["The email account does not exist.", "Try again"]
             }

      # A code of another class is text, not an enhanced code.
      assert {:ok, %Reply{enhanced: nil, lines: ["2.0.0 odd"]}, ""} =
               Reply.decode("550 2.0.0 odd\r\n")

      # A different code on a later line stays in the text.
      assert {:ok, %Reply{enhanced: "4.2.0", lines: ["busy", "4.7.1 other"]}, ""} =
               Reply.decode("451-4.2.0 busy\r\n451 4.7.1 other\r\n")
    end

    test "rejects malformed replies" do
      for bad <- [
            "hello\r\n",
            "25 ok\r\n",
            "199 ok\r\n",
            "600 ok\r\n",
            "250_ok\r\n",
            "250-a\r\n251 b\r\n",
            "abc ok\r\n"
          ] do
        assert Reply.decode(bad) == {:error, :malformed}, inspect(bad)
      end
    end

    test "enforces the line length and line count limits" do
      long = "250 " <> String.duplicate("x", 100)
      assert Reply.decode(long, max_line_length: 50) == {:error, :line_too_long}
      assert Reply.decode(long <> "\r\n", max_line_length: 50) == {:error, :line_too_long}

      many = String.duplicate("250-x\r\n", 10)
      assert Reply.decode(many, max_lines: 5) == {:error, :too_many_lines}
    end

    property "decodes whatever encode/1 produces" do
      check all(
              code <- one_of([integer(200..299), integer(400..599)]),
              enhanced <- one_of([constant(nil), constant("#{div(code, 100)}.1.2")]),
              lines <-
                list_of(string([?a..?z, ?\s, ?-], max_length: 40), min_length: 1, max_length: 5),
              rest <- string(:printable, max_length: 10)
            ) do
        reply = Reply.new(code, enhanced, lines)
        encoded = IO.iodata_to_binary(Reply.encode(reply))
        assert Reply.decode(encoded <> rest) == {:ok, reply, rest}
      end
    end
  end

  test "status/1 falls back to the class of the reply code" do
    assert Reply.status(Reply.new(550, "5.7.1", "no")) == "5.7.1"
    assert Reply.status(Reply.new(451, "later")) == "4.0.0"
    assert Reply.status(Reply.new(250, "ok")) == "2.0.0"
  end
end
