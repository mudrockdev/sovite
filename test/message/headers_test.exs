defmodule Sovite.Message.HeadersTest do
  use ExUnit.Case, async: true

  alias Sovite.Message.Headers

  test "splits at the empty line" do
    assert Headers.split("A: 1\r\nB: 2\r\n\r\nbody\r\n") == {:ok, "A: 1\r\nB: 2\r\n", "body\r\n"}
    assert Headers.split("\r\nbody") == {:ok, "", "body"}
    assert Headers.split("A: 1\r\nB: 2\r\n") == :more
  end

  test "keeps folded fields and odd lines byte for byte" do
    header = "Subject: a\r\n long\r\n\tsubject\r\nFrom : x@y\r\nnot a field\r\nX-A:b\r\n"
    fields = Headers.parse(header)

    assert fields == [
             {"subject", "Subject: a\r\n long\r\n\tsubject\r\n"},
             {"from", "From : x@y\r\n"},
             {nil, "not a field\r\n"},
             {"x-a", "X-A:b\r\n"}
           ]

    assert IO.iodata_to_binary(Headers.encode(fields)) == header
  end

  test "finds, deletes, and appends fields case-insensitively" do
    fields = Headers.parse("Return-Path: <a@b>\r\nDATE: now\r\nreturn-path: <c@d>\r\n")
    assert Headers.has?(fields, "date")
    refute Headers.has?(fields, "Message-ID")

    fields = fields |> Headers.delete(["Return-PATH"]) |> Headers.append("Message-ID", "<1@x>")
    assert IO.iodata_to_binary(Headers.encode(fields)) == "DATE: now\r\nMessage-ID: <1@x>\r\n"
  end
end
