defmodule Sovite.Milter.HeadersTest do
  use ExUnit.Case, async: true

  alias Sovite.Message.Headers, as: MessageHeaders
  alias Sovite.Milter.Headers

  doctest Headers

  @header "Received: from a\r\n\tby b\r\nFrom: alice@example.net\r\nReceived: from c\r\n" <>
            "Subject: hi\r\nreceived: from d\r\n"

  defp fields, do: MessageHeaders.parse(@header)

  defp apply_mods(modifications),
    do:
      fields() |> Headers.apply(modifications) |> MessageHeaders.encode() |> IO.iodata_to_binary()

  test "appends added fields" do
    assert apply_mods([{:add_header, "X-Spam", " yes"}, {:add_header, "X-B", " 2"}]) ==
             @header <> "X-Spam: yes\r\nX-B: 2\r\n"

    assert List.last(Headers.apply(fields(), [{:add_header, "X-Spam", " yes"}])) ==
             {"x-spam", "X-Spam: yes\r\n"}
  end

  test "inserts at a position among all fields" do
    assert apply_mods([{:insert_header, 0, "DKIM-Signature", " v=1"}]) ==
             "DKIM-Signature: v=1\r\n" <> @header

    assert apply_mods([{:insert_header, 2, "X-A", " 1"}]) ==
             "Received: from a\r\n\tby b\r\nFrom: alice@example.net\r\nX-A: 1\r\n" <>
               "Received: from c\r\nSubject: hi\r\nreceived: from d\r\n"

    assert apply_mods([{:insert_header, 99, "X-A", " 1"}]) == @header <> "X-A: 1\r\n"
  end

  test "changes the n-th field of a name, case-insensitively" do
    assert apply_mods([{:change_header, 2, "RECEIVED", " from x"}]) ==
             "Received: from a\r\n\tby b\r\nFrom: alice@example.net\r\nRECEIVED: from x\r\n" <>
               "Subject: hi\r\nreceived: from d\r\n"

    assert apply_mods([{:change_header, 0, "Subject", " new"}]) ==
             String.replace(@header, "Subject: hi", "Subject: new")

    assert apply_mods([{:change_header, 1, "X-Missing", " added"}]) ==
             @header <> "X-Missing: added\r\n"

    assert apply_mods([{:change_header, 4, "Received", " added"}]) ==
             @header <> "Received: added\r\n"
  end

  test "deletes the n-th field of a name" do
    assert apply_mods([{:delete_header, 3, "Received"}]) ==
             "Received: from a\r\n\tby b\r\nFrom: alice@example.net\r\nReceived: from c\r\n" <>
               "Subject: hi\r\n"

    assert apply_mods([{:delete_header, 1, "X-Missing"}, {:delete_header, 4, "received"}]) ==
             @header
  end

  test "applies modifications in order, each on the result of the last" do
    assert apply_mods([
             {:delete_header, 1, "Received"},
             {:delete_header, 1, "Received"},
             {:insert_header, 0, "X-Top", " 1"},
             {:add_recipient, "x@example.com", []},
             {:quarantine, "why"}
           ]) == "X-Top: 1\r\nFrom: alice@example.net\r\nSubject: hi\r\nreceived: from d\r\n"
  end

  test "keeps lines that are not fields" do
    fields = [{nil, "garbage\r\n"} | fields()]
    assert Headers.name_value(hd(fields)) == nil

    assert [{nil, "garbage\r\n"}, {"x-a", "X-A: 1\r\n"} | _] =
             Headers.apply(fields, [{:insert_header, 1, "X-A", " 1"}])
  end

  test "splits fields into name and value" do
    assert Headers.name_value({"subject", "Subject : x"}) == {"Subject", " x"}
    assert Headers.name_value({"x-empty", "X-Empty:\r\n"}) == {"X-Empty", ""}
  end
end
