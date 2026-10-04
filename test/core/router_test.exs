defmodule Sovite.Core.RouterTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Router

  @opts %{local_domains: MapSet.new(["example.org"]), relayhost: nil}

  test "routes local domains, MX domains, and address literals" do
    assert Router.route("a@example.org", @opts) == :local
    assert Router.route("a@EXAMPLE.org", @opts) == :local
    assert Router.route("a@Example.NET", @opts) == {:remote, {:mx, "example.net"}}
    assert Router.route("a@[192.0.2.1]", @opts) == {:remote, {:literal, {192, 0, 2, 1}}}
    assert Router.route("not an address", @opts) == :invalid
  end

  test "sends all remote mail to the relay host" do
    relay = %{host: "smtp.isp.example", port: 587, mx: false}
    opts = %{@opts | relayhost: relay}

    assert Router.route("a@example.net", opts) == {:remote, {:relayhost, relay}}
    assert Router.route("a@[192.0.2.1]", opts) == {:remote, {:relayhost, relay}}
    assert Router.route("a@example.org", opts) == :local
  end

  test "names destinations for logs" do
    assert Router.name({:mx, "example.net"}) == "example.net"
    assert Router.name({:literal, {192, 0, 2, 1}}) == "[192.0.2.1]"
    assert Router.name({:relayhost, %{host: "isp.example", port: 25, mx: true}}) == "isp.example"

    assert Router.name({:relayhost, %{host: "smtp.isp.example", port: 587, mx: false}}) ==
             "[smtp.isp.example]:587"

    assert Router.name({:relayhost, %{host: "[192.0.2.1]", port: 25, mx: false}}) == "[192.0.2.1]"
  end
end
