defmodule Sovite.Core.RouterTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.{Router, Routing, Transport}
  alias Sovite.Test.FailingTable
  alias Sovite.Test.MemoryTable, as: Memory

  defp routing(fields \\ []) do
    struct!(
      %Routing{
        hostname: "mx.example.org",
        local_domains: MapSet.new(["example.org"]),
        relay_domains: MapSet.new(["relayed.example"]),
        hosted_domains: MapSet.new(["hosted.example"]),
        mailboxes: [{"mailboxes", Memory.new(%{"alice@hosted.example" => "x"})}],
        delimiter: "+"
      },
      fields
    )
  end

  defp table(id, map), do: [{id, Memory.new(map)}]

  defp transport(spec) do
    {:ok, transport} = Transport.parse(spec)
    transport
  end

  defp remote(nexthop, extra \\ %{}),
    do: {:remote, Map.merge(%{nexthop: nexthop, source: %{}, auth: nil}, extra)}

  test "routes by domain class" do
    r = routing()

    assert Router.route(r, "", "a@example.org") ==
             {:defer, "4.3.2", "local delivery is not available yet"}

    assert Router.route(r, "", "a@Example.NET") == remote({:mx, "example.net"})
    assert Router.route(r, "", "a@[192.0.2.1]") == remote({:literal, {192, 0, 2, 1}})
    assert Router.route(r, "", "a@relayed.example") == remote({:mx, "relayed.example"})

    assert Router.route(r, "", "alice@hosted.example") ==
             {:defer, "4.3.2", "mailbox delivery is not available yet"}

    assert Router.route(r, "", "not an address") ==
             {:fail, "5.1.3", "bad recipient address syntax"}
  end

  test "fails unknown and relocated users" do
    r = routing(moved_users: table("relocated", %{"old@example.net" => "new@example.com"}))

    assert {:fail, "5.1.1", "<bob@hosted.example>: User unknown in mailbox table"} =
             Router.route(r, "", "bob@hosted.example")

    assert Router.route(r, "", "old@example.net") ==
             {:fail, "5.1.6", "<old@example.net>: User has moved to new@example.com"}
  end

  test "sends everything not hosted to the relay host" do
    relay = %{host: "smtp.isp.example", port: 587, mx: false}
    r = routing(relayhost: relay, relay_auth: %{username: "u", password: "p"})

    assert Router.route(r, "", "a@example.net") ==
             remote({:host, relay}, %{auth: %{username: "u", password: "p"}})

    assert Router.route(r, "", "a@[192.0.2.1]") ==
             remote({:host, relay}, %{auth: %{username: "u", password: "p"}})
  end

  test "transport maps override the class transport" do
    maps =
      table("transport", %{
        "special@example.net" => "smtp:[special.example]:2525",
        "example.net" => "error:5.7.1 we do not deliver there",
        ".sub.example.com" => ":[sub-relay.example]",
        "retry.example" => "retry:4.4.0 down for maintenance",
        "drop.example" => "discard:spam trap",
        "lmtp.example" => "lmtp:unix:/run/dovecot/lmtp",
        "bad.example" => "nonsense:x",
        "*" => "smtp:"
      })

    r = routing(transports: maps)

    assert Router.route(r, "", "special+tag@example.net") ==
             remote({:host, %{host: "special.example", port: 2525, mx: false}})

    assert Router.route(r, "", "other@example.net") == {:fail, "5.7.1", "we do not deliver there"}

    assert Router.route(r, "", "a@deep.sub.example.com") ==
             remote({:host, %{host: "sub-relay.example", port: 25, mx: false}})

    assert Router.route(r, "", "a@retry.example") == {:defer, "4.4.0", "down for maintenance"}
    assert Router.route(r, "", "a@drop.example") == {:discard, "spam trap"}

    assert Router.route(r, "", "a@lmtp.example") ==
             {:defer, "4.3.2", "LMTP delivery is not available yet"}

    assert {:defer, "4.3.5", "invalid transport \"nonsense:x\"" <> _} =
             Router.route(r, "", "a@bad.example")

    assert Router.route(r, "", "a@anywhere.example") == remote({:mx, "anywhere.example"})
  end

  test "class transports can be changed" do
    r =
      routing(
        class_transports: %{
          local: transport("smtp:[mailstore.internal]"),
          hosted: transport("mailbox"),
          relay: transport("smtp"),
          remote: transport("error:5.7.1 no outbound mail")
        }
      )

    assert Router.route(r, "", "a@example.org") ==
             remote({:host, %{host: "mailstore.internal", port: 25, mx: false}})

    assert Router.route(r, "", "a@example.net") == {:fail, "5.7.1", "no outbound mail"}
  end

  test "an error transport with a 4xx status defers" do
    r = routing(transports: table("t", %{"*" => "error:4.3.0 not now"}))
    assert Router.route(r, "", "a@example.net") == {:defer, "4.3.0", "not now"}
  end

  test "sender-dependent relay host, source address, and credentials" do
    r =
      routing(
        relayhost: %{host: "default.example", port: 25, mx: false},
        sender_relayhosts:
          table("relays", %{"@corp.example" => "[smtp.corp.example]:587", "bad@x.example" => "!!"}),
        sender_source_addresses:
          table("sources", %{
            "vip@corp.example" => "192.0.2.10, 2001:db8::10",
            "odd@corp.example" => "nope"
          }),
        source_address: %{ipv4: {192, 0, 2, 1}},
        relay_credentials:
          table("credentials", %{
            "@corp.example" => "corp:secret",
            "[default.example]" => "default:pw",
            "broken@corp.example" => "no-colon"
          })
      )

    corp = %{host: "smtp.corp.example", port: 587, mx: false}

    assert Router.route(r, "vip@corp.example", "a@example.net") ==
             remote({:host, corp}, %{
               source: %{ipv4: {192, 0, 2, 10}, ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x10}},
               auth: %{username: "corp", password: "secret"}
             })

    assert Router.route(r, "someone@else.example", "a@example.net") ==
             remote({:host, %{host: "default.example", port: 25, mx: false}}, %{
               source: %{ipv4: {192, 0, 2, 1}},
               auth: %{username: "default", password: "pw"}
             })

    # Notifications (null sender) use the defaults.
    assert {:remote, %{auth: %{username: "default"}}} = Router.route(r, "", "a@example.net")

    assert {:defer, "4.3.5", "invalid relay host" <> _} =
             Router.route(r, "bad@x.example", "a@example.net")

    assert {:defer, "4.3.5", "invalid source address" <> _} =
             Router.route(r, "odd@corp.example", "a@example.net")

    assert {:defer, "4.3.5", "relay credentials" <> _} =
             Router.route(r, "broken@corp.example", "a@example.net")
  end

  test "a table that cannot be read defers" do
    failing = [{"down", FailingTable.new()}]

    for field <- [:transports, :sender_relayhosts, :sender_source_addresses, :moved_users] do
      assert {:defer, "4.3.0", "lookup error: cannot read table down"} =
               Router.route(routing([{field, failing}]), "a@b.example", "x@example.net"),
             inspect(field)
    end

    r = routing(relayhost: %{host: "r.example", port: 25, mx: false}, relay_credentials: failing)
    assert {:defer, "4.3.0", _} = Router.route(r, "a@b.example", "x@example.net")

    assert {:defer, "4.3.0", _} =
             Router.route(routing(mailboxes: failing), "", "alice@hosted.example")
  end

  test "names destinations for logs" do
    assert Router.name({:mx, "example.net"}) == "example.net"
    assert Router.name({:literal, {192, 0, 2, 1}}) == "[192.0.2.1]"
    assert Router.name({:host, %{host: "isp.example", port: 25, mx: true}}) == "isp.example"

    assert Router.name({:host, %{host: "smtp.isp.example", port: 587, mx: false}}) ==
             "[smtp.isp.example]:587"

    assert Router.name(%{nexthop: {:host, %{host: "[192.0.2.1]", port: 25, mx: false}}}) ==
             "[192.0.2.1]"
  end
end
