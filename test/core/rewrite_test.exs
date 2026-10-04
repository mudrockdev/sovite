defmodule Sovite.Core.RewriteTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.{Rewrite, Routing}
  alias Sovite.Message.Headers
  alias Sovite.Test.FailingTable
  alias Sovite.Test.MemoryTable, as: Memory

  defp routing(fields) do
    struct!(%Routing{local_domains: MapSet.new(["example.com"]), delimiter: "+"}, fields)
  end

  defp table(map), do: [{"address_rewrites", Memory.new(map)}]

  test "rewrites addresses, domains, and local parts" do
    rewrites =
      table(%{
        "alice@example.com" => "Alice.Smith@example.net",
        "@old.example" => "@new.example",
        "root" => "admin",
        "bob@example.com" => "not an address"
      })

    r = routing(recipient_rewrites: rewrites)

    assert Rewrite.recipient(r, "alice@example.com") == {:ok, "Alice.Smith@example.net"}
    # The unmatched extension is kept.
    assert Rewrite.recipient(r, "alice+lists@example.com") ==
             {:ok, "Alice.Smith+lists@example.net"}

    assert Rewrite.recipient(r, "carol@old.example") == {:ok, "carol@new.example"}
    # Bare local parts only match hosted domains.
    assert Rewrite.recipient(r, "root@example.com") == {:ok, "admin@example.com"}
    assert Rewrite.recipient(r, "root@elsewhere.example") == {:ok, "root@elsewhere.example"}
    # A broken value keeps the original.
    assert Rewrite.recipient(r, "bob@example.com") == {:ok, "bob@example.com"}
  end

  test "sender and recipient rewrites are separate" do
    r =
      routing(
        sender_rewrites: table(%{"a@example.com" => "b@example.com"}),
        recipient_rewrites: table(%{"a@example.com" => "r@example.com"})
      )

    assert Rewrite.sender(r, "a@example.com") == {:ok, "b@example.com"}
    assert Rewrite.recipient(r, "a@example.com") == {:ok, "r@example.com"}
    assert Rewrite.sender(r, "") == {:ok, ""}
  end

  test "a failing table is an error" do
    down = [{"down", FailingTable.new()}]
    r = routing(sender_rewrites: down, recipient_rewrites: down)
    assert Rewrite.sender(r, "a@example.com") == {:error, "down"}
    assert Rewrite.recipient(r, "a@example.com") == {:error, "down"}
  end

  test "hides subdomains" do
    r =
      routing(
        hide_subdomains: ["!keep.example.com", "example.com"],
        hide_subdomains_exceptions: MapSet.new(["root"])
      )

    assert Rewrite.sender(r, "alice@host.example.com") == {:ok, "alice@example.com"}
    assert Rewrite.sender(r, "alice@example.com") == {:ok, "alice@example.com"}
    assert Rewrite.sender(r, "alice@a.keep.example.com") == {:ok, "alice@a.keep.example.com"}
    assert Rewrite.sender(r, "root+x@host.example.com") == {:ok, "root+x@host.example.com"}
    assert Rewrite.sender(r, "alice@example.net") == {:ok, "alice@example.net"}
    assert Rewrite.hide_subdomains(r, "postmaster") == "postmaster"
  end

  test "rewrites header addresses" do
    r =
      routing(
        sender_rewrites: table(%{"alice@example.com" => "Alice.Smith@example.com"}),
        recipient_rewrites: table(%{"bob@example.com" => "Bob.Jones@example.com"}),
        hide_subdomains: ["example.com"]
      )

    header =
      "From: Alice <alice@host.example.com>\r\n" <>
        "To: bob@example.com, \"Carol\" <carol@host.example.com>\r\n" <>
        "Subject: alice@example.com stays\r\n"

    rewritten =
      r
      |> Rewrite.header_fields(Headers.parse(header))
      |> Headers.encode()
      |> IO.iodata_to_binary()

    assert rewritten ==
             "From: Alice <alice@example.com>\r\n" <>
               "To: Bob.Jones@example.com, \"Carol\" <carol@example.com>\r\n" <>
               "Subject: alice@example.com stays\r\n"

    assert Rewrite.rewrites_headers?(r)
    refute Rewrite.rewrites_headers?(%{r | rewrite_headers: false})
    refute Rewrite.rewrites_headers?(routing([]))

    # A failing table leaves header addresses alone.
    down = [{"down", FailingTable.new()}]
    r = routing(sender_rewrites: down, recipient_rewrites: down)
    fields = [{"from", "From: a@example.com\r\n"}, {"to", "To: b@example.com\r\n"}]
    assert Rewrite.header_fields(r, fields) == fields
  end
end
