defmodule Sovite.Core.RecipientsTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.{Recipients, Routing}
  alias Sovite.Test.FailingTable
  alias Sovite.Test.MemoryTable, as: Memory

  defp routing(fields \\ []) do
    struct!(
      %Routing{
        hostname: "mx.example.org",
        local_domains: MapSet.new(["example.org"]),
        relay_domains: MapSet.new(["relayed.example"]),
        aliased_domains: MapSet.new(["aliases.example"]),
        hosted_domains: MapSet.new(["hosted.example"]),
        delimiter: "+"
      },
      fields
    )
  end

  defp table(name \\ "t", map), do: [{name, Memory.new(map)}]

  describe "expand" do
    test "follows aliases recursively and keeps self references" do
      r =
        routing(
          aliases:
            table(%{
              "sales@aliases.example" => "team@aliases.example, boss@example.net",
              "team@aliases.example" => "team@aliases.example alice@example.net",
              "@catch.example" => "inbox@example.net",
              "root" => "admin@example.net"
            })
        )

      assert Recipients.expand(r, "sales@aliases.example") ==
               {:ok, ["team@aliases.example", "alice@example.net", "boss@example.net"]}

      assert Recipients.expand(r, "anyone+x@catch.example") == {:ok, ["inbox+x@example.net"]}
      # Bare local parts only match local domains.
      assert Recipients.expand(r, "Root@example.org") == {:ok, ["admin@example.net"]}
      assert Recipients.expand(r, "root@example.net") == {:ok, ["root@example.net"]}
      assert Recipients.expand(r, "nobody@example.net") == {:ok, ["nobody@example.net"]}
    end

    test "limits nesting, size, and bad destinations" do
      deep = Map.new(0..120, fn n -> {"a#{n}@x.example", "a#{n + 1}@x.example"} end)

      assert {:error, :temporary, "aliases nested" <> _} =
               Recipients.expand(routing(aliases: table(deep)), "a0@x.example")

      many = Enum.map_join(1..1001, ", ", &"u#{&1}@x.example")
      r = routing(aliases: table(%{"big@x.example" => many}))
      assert {:error, :temporary, _} = Recipients.expand(r, "big@x.example")

      r = routing(aliases: table(%{"bad@x.example" => "no-domain"}))

      assert {:error, :temporary, "alias for <bad@x.example> has an invalid address" <> _} =
               Recipients.expand(r, "bad@x.example")

      r = routing(aliases: table(%{"empty@x.example" => " , "}))
      assert {:error, :temporary, "empty alias" <> _} = Recipients.expand(r, "empty@x.example")

      r = routing(aliases: [{"down", FailingTable.new()}])
      assert {:error, :temporary, "cannot read table down"} = Recipients.expand(r, "a@x.example")
    end

    test "postmaster of an aliased or hosted domain falls back to the server's postmaster" do
      r = routing(mailboxes: table(%{"alice@hosted.example" => "x"}))

      assert Recipients.expand(r, "postmaster@hosted.example") ==
               {:ok, ["postmaster@mx.example.org"]}

      assert Recipients.expand(r, "abuse@aliases.example") == {:ok, ["postmaster@mx.example.org"]}

      r = routing(mailboxes: table(%{"postmaster@hosted.example" => "x"}))

      assert Recipients.expand(r, "postmaster@hosted.example") ==
               {:ok, ["postmaster@hosted.example"]}
    end
  end

  describe "check" do
    test "local recipients" do
      assert Recipients.check(routing(), "anyone@example.org") == {:ok, :local}

      r = routing(local_recipients: MapSet.new(["alice@example.org"]))
      assert Recipients.check(r, "Alice+tag@example.org") == {:ok, :local}
      assert Recipients.check(r, "postmaster@example.org") == {:ok, :local}

      assert Recipients.check(r, "carol@example.org") ==
               {:reject, "5.1.1",
                "<carol@example.org>: Recipient address rejected: User unknown in local recipient table"}
    end

    test "aliased, hosted, relay, and remote domains" do
      r =
        routing(
          mailboxes: table(%{"alice@hosted.example" => "x", "@open.example" => "x"}),
          hosted_domains: MapSet.new(["hosted.example", "open.example"])
        )

      assert Recipients.check(r, "alice@hosted.example") == {:ok, :hosted}
      assert Recipients.check(r, "anyone@open.example") == {:ok, :hosted}
      assert {:reject, "5.1.1", text} = Recipients.check(r, "bob@hosted.example")
      assert text =~ "mailbox table"
      assert {:reject, "5.1.1", text} = Recipients.check(r, "x@aliases.example")
      assert text =~ "alias table"
      assert Recipients.check(r, "x@relayed.example") == {:ok, :relay}
      assert Recipients.check(r, "x@example.net") == {:ok, :remote}
    end

    test "users who moved, and failing tables" do
      r = routing(moved_users: table(%{"old@example.org" => "new@example.net"}))

      assert Recipients.check(r, "old@example.org") ==
               {:reject, "5.1.6",
                "<old@example.org>: Recipient address rejected: User has moved to new@example.net"}

      down = [{"down", FailingTable.new()}]

      assert Recipients.check(routing(moved_users: down), "a@example.org") ==
               {:error, "cannot read table down"}

      assert Recipients.check(routing(mailboxes: down), "a@hosted.example") ==
               {:error, "cannot read table down"}
    end
  end

  test "bcc" do
    r =
      routing(
        always_bcc: "archive@example.org",
        sender_bcc: table(%{"@sales.example" => "sales-copy@example.org"}),
        recipient_bcc: table(%{"ceo@example.org" => "assistant@example.org, archive@example.org"})
      )

    assert Recipients.bcc(r, "bob@sales.example", ["ceo@example.org", "x@example.net"]) ==
             {:ok, ["archive@example.org", "sales-copy@example.org", "assistant@example.org"]}

    assert Recipients.bcc(routing(), "", ["a@example.org"]) == {:ok, []}

    down = routing(recipient_bcc: [{"down", FailingTable.new()}])
    assert Recipients.bcc(down, "", ["a@example.org"]) == {:error, "cannot read table down"}
  end
end
