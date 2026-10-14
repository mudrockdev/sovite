defmodule Sovite.Core.RouteInfoTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.{RouteInfo, Routing}
  alias Sovite.Test.MemoryTable, as: Memory

  defp routing(fields \\ []) do
    struct!(
      %Routing{
        hostname: "mx.example.org",
        local_domains: MapSet.new(["example.org"]),
        aliased_domains: MapSet.new(["aliases.example"]),
        hosted_domains: MapSet.new(["hosted.example"]),
        mailboxes: [{"mailboxes", Memory.new(%{"alice@hosted.example" => "x"})}],
        aliases: [
          {"aliases",
           Memory.new(%{"team@aliases.example" => "alice@hosted.example, bob@example.net"})}
        ],
        relayhost: %{host: "smtp.isp.example", port: 587, mx: false},
        relay_auth: %{username: "u", password: "p"},
        source_address: %{ipv4: {192, 0, 2, 9}},
        delimiter: "+"
      },
      fields
    )
  end

  test "shows the class, expansion, and destination of each address" do
    info = RouteInfo.resolve(routing(), "team@aliases.example")

    assert %{
             address: "team@aliases.example",
             rewritten: nil,
             domain: "aliases.example",
             class: "aliased",
             expanded: ["alice@hosted.example", "bob@example.net"],
             recipients: [
               %{address: "alice@hosted.example", result: "deliver", transport: "mailbox"},
               %{
                 address: "bob@example.net",
                 result: "deliver",
                 transport: "smtp",
                 nexthop: "[smtp.isp.example]:587",
                 source: %{ipv4: "192.0.2.9"},
                 login: "u"
               }
             ]
           } = info

    text = RouteInfo.format(info)
    assert text =~ "domain: aliases.example (aliased)"
    assert text =~ "expands to: alice@hosted.example, bob@example.net"
    assert text =~ "alice@hosted.example: deliver via mailbox"

    assert text =~
             "bob@example.net: deliver via smtp to [smtp.isp.example]:587 (from 192.0.2.9, login u)"
  end

  test "shows why an address is refused" do
    info = RouteInfo.resolve(routing(), "nobody@hosted.example")
    assert [%{result: "fail", status: "5.1.1"}] = info.recipients
    assert info.expanded == nil
    assert RouteInfo.format(info) =~ "nobody@hosted.example: fail 5.1.1"

    assert [%{result: "fail", status: "5.1.3"}] = RouteInfo.resolve(routing(), "bad").recipients
  end

  test "shows rewriting" do
    routing =
      routing(
        recipient_rewrites: [{"rewrites", Memory.new(%{"old@example.org" => "new@example.org"})}]
      )

    info = RouteInfo.resolve(routing, "old@example.org")
    assert info.rewritten == "new@example.org"
    assert [%{address: "new@example.org", transport: "local"}] = info.recipients
    assert RouteInfo.format(info) =~ "rewritten to: new@example.org"
  end
end
