defmodule Sovite.HeaderChecksTest do
  use ExUnit.Case, async: true

  alias Sovite.HeaderChecks
  alias Sovite.Message.Headers

  doctest HeaderChecks

  @now ~U[2026-10-27 12:00:00Z]

  @good %{
    "Received" =>
      "from client.example (client.example [192.0.2.7]) by mx.example.org; 27 Oct 2026 11:59:00 +0000",
    "Date" => "Tue, 27 Oct 2026 14:58:00 +0300",
    "Message-ID" => "<1@client.example>",
    "From" => "Alice <alice@example.com>",
    "To" => "bob@example.org",
    "Subject" => "hello"
  }

  # A header with the good fields, `changes` set (nil to leave one out,
  # a list for several), in this order.
  defp check(changes \\ %{}, opts \\ []) do
    fields = Map.merge(@good, changes)

    ~w(Received Date Message-ID From Reply-To To Subject)
    |> Enum.flat_map(fn name ->
      for value <- List.wrap(fields[name]), do: "#{name}: #{value}\r\n"
    end)
    |> Enum.join()
    |> Headers.parse()
    |> HeaderChecks.check(Keyword.merge([now: @now], opts))
  end

  defp names(symbols), do: Enum.map(symbols, &elem(&1, 0))

  test "a header as mail programs write it has nothing" do
    assert check() == []
  end

  test "dates" do
    assert names(check(%{"Date" => nil})) == ["MISSING_DATE"]
    assert check(%{"Date" => "soon"}) == [{"INVALID_DATE", ["soon"]}]
    assert names(check(%{"Date" => "27 Oct 2026 15:00 +0000"})) == ["DATE_IN_FUTURE"]
    assert names(check(%{"Date" => "1 Oct 2026 12:00 +0000"})) == ["DATE_IN_PAST"]
    assert check(%{"Date" => "1 Oct 2026 12:00 +0000"}, past: 30 * 86_400) == []
  end

  test "message IDs" do
    assert names(check(%{"Message-ID" => nil})) == ["MISSING_MID"]

    assert check(%{"Message-ID" => "1@client.example"}) == [
             {"INVALID_MSGID", ["1@client.example"]}
           ]

    assert check(%{"Message-ID" => "<1@localhost>"}) == [{"MID_RHS_NOT_FQDN", ["localhost"]}]
    assert check(%{"Message-ID" => "<1@[192.0.2.1]>"}) == [{"MID_RHS_NOT_FQDN", ["[192.0.2.1]"]}]
  end

  test "From: and its display name" do
    assert names(check(%{"From" => nil})) == ["MISSING_FROM"]
    assert names(check(%{"From" => ["a@example.com", "b@example.com"]})) == ["MULTIPLE_FROM"]
    assert names(check(%{"From" => "a@example.com, b@example.com"})) == ["MULTIPLE_FROM"]
    assert names(check(%{"From" => "\"unclosed <a@example.com>"})) == ["INVALID_FROM"]
    assert names(check(%{"From" => "nobody"})) == ["INVALID_FROM"]
    assert names(check(%{"From" => "alice@example.com"})) == ["FROM_NO_DN"]

    assert check(%{"From" => "=?utf-8?Q?PayPal_=3Cservice=40paypal=2Ecom=3E?= <x@evil.example>"}) ==
             [{"SPOOF_DISPLAY_NAME", ["service@paypal.com"]}]

    # The same domain is no spoof.
    assert check(%{"From" => "\"alice@Example.com\" <alice@example.com>"}) == []

    assert check(%{}, envelope_from: "bounces@lists.example") == [
             {"FROM_NEQ_ENVFROM", ["bounces@lists.example"]}
           ]

    assert check(%{}, envelope_from: "Alice@Example.com") == []
    assert check(%{}, envelope_from: "") == []
  end

  test "Reply-To:" do
    assert check(%{"Reply-To" => "Alice <alice@example.com>"}) == []

    assert check(%{"Reply-To" => "x@Elsewhere.example"}) == [
             {"REPLYTO_DOM_NEQ_FROM_DOM", ["elsewhere.example"]}
           ]

    assert check(%{"Reply-To" => "<broken"}) == [{"REPLYTO_UNPARSABLE", ["<broken"]}]
    assert names(check(%{"Reply-To" => "x@elsewhere.example", "From" => nil})) == ["MISSING_FROM"]
  end

  test "missing and repeated fields" do
    assert names(check(%{"To" => nil, "Subject" => nil})) == ["MISSING_TO", "MISSING_SUBJECT"]

    assert check(%{"Subject" => ["a", "b"], "To" => ["x@example.org", "y@example.org"]}) ==
             [{"MULTIPLE_UNIQUE_HEADERS", ["subject", "to"]}]
  end

  test "Received: chains" do
    assert names(check(%{"Received" => nil})) == ["RCVD_COUNT_ZERO"]
    assert names(check(%{"Received" => "from somewhere"})) == ["RCVD_UNPARSABLE"]

    # Newest first: a hop below another dated hours after it.
    unordered = [
      "from b.example by mx.example.org; 27 Oct 2026 11:59:00 +0000",
      "from a.example by b.example; 27 Oct 2026 14:00:00 +0000"
    ]

    assert names(check(%{"Received" => unordered})) == ["RCVD_DATES_UNORDERED"]

    # A server's own hops on top are its own; below another host's, forged.
    chain = [
      "from localhost by mx.example.org; 27 Oct 2026 11:59:00 +0000",
      "from client.example by mx.example.org; 27 Oct 2026 11:58:00 +0000"
    ]

    assert check(%{"Received" => chain}, hostnames: ["MX.example.org"]) == []

    forged =
      chain ++
        [
          "from x by relay.example; 27 Oct 2026 11:00:00 +0000",
          "from y by mx.example.org; 27 Oct 2026 10:00:00 +0000"
        ]

    assert check(%{"Received" => forged}, hostnames: ["mx.example.org"]) ==
             [{"FORGED_RCVD_HOSTNAME", ["mx.example.org"]}]
  end

  test "bytes that are not UTF-8 are read anyway" do
    fields = Headers.parse(<<"From: Caf", 0xE9, " <a@example.com>\r\nDate: ", 0xFF, "\r\n">>)
    symbols = HeaderChecks.check(fields, now: @now)
    assert {"INVALID_DATE", ["�"]} in symbols
    assert Enum.all?(symbols, fn {_name, options} -> Enum.all?(options, &String.valid?/1) end)
  end
end
