defmodule Sovite.Message.TraceTest do
  use ExUnit.Case, async: true

  alias Sovite.Message.{Headers, Trace}

  doctest Trace

  @header "Received: from a by b; Mon, 1 Jan 2026 00:00:00 +0000\r\n" <>
            "Delivered-To:\r\n Alice@Example.COM\r\n" <>
            "received: from c by d; Mon, 1 Jan 2026 00:00:00 +0000\r\n" <>
            "Subject: Delivered-To: bob@example.com\r\n"

  test "counts hops" do
    assert Trace.hops(Headers.parse(@header)) == 2
    assert Trace.hops([]) == 0
  end

  test "finds a recipient in Delivered-To" do
    fields = Headers.parse(@header)
    assert Trace.delivered_to?(fields, "alice@example.com")
    refute Trace.delivered_to?(fields, "bob@example.com")
  end

  test "the null sender" do
    assert Trace.return_path("") == "Return-Path: <>\r\n"
  end
end
