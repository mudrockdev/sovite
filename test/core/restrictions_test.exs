defmodule Sovite.Core.RestrictionsTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Restrictions
  alias Sovite.SMTP.Reply
  alias Sovite.Test.{FailingTable, FakeDNS, TelemetryForwarder}
  alias Sovite.Test.MemoryTable, as: Memory

  defp context(fields \\ []) do
    Map.merge(
      %{
        client_ip: {192, 0, 2, 7},
        helo: "client.example.net",
        sender: "alice+x@example.net",
        recipient: nil,
        trusted: false,
        authenticated: false,
        access: %{},
        resolver: FakeDNS.resolver(%{}),
        delimiter: "+"
      },
      Map.new(fields)
    )
  end

  defp access(kind, map), do: %{kind => [{"access_rules", Memory.new(map)}]}

  defp reply({:reject, %Reply{} = reply}),
    do: {reply.code, reply |> Reply.to_string() |> String.replace_prefix("#{reply.code} ", "")}

  test "parses and places checks" do
    assert Restrictions.parse("client_access") == {:ok, "client_access"}
    assert Restrictions.parse("nope") == {:error, "unknown restriction \"nope\""}
    assert Restrictions.allowed?("client_access", :connect)
    refute Restrictions.allowed?("helo_access", :connect)
    refute Restrictions.allowed?("recipient_access", :mail)
  end

  test "constant and permit checks" do
    assert Restrictions.run(["reject"], :mail, context()) |> reply() ==
             {554, "5.7.1 Access denied"}

    assert Restrictions.run(["defer"], :mail, context()) |> reply() ==
             {450, "4.7.1 Try again later"}

    assert Restrictions.run(["permit", "reject"], :mail, context()) == :ok
    assert Restrictions.run(["permit_trusted", "reject"], :mail, context(trusted: true)) == :ok
    assert {:reject, _} = Restrictions.run(["permit_trusted", "reject"], :mail, context())

    assert Restrictions.run(
             ["permit_authenticated", "reject"],
             :mail,
             context(authenticated: true)
           ) == :ok
  end

  test "client access by address and IPv4 network" do
    ctx = context(access: access(:client, %{"192.0.2" => "REJECT spam source"}))

    assert Restrictions.run(["client_access"], :connect, ctx) |> reply() ==
             {554, "5.7.1 Client host [192.0.2.7] rejected: spam source"}

    ctx =
      context(
        client_ip: {0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0207},
        access: access(:client, %{"192.0.2.7" => "ACCEPT"})
      )

    assert Restrictions.run(["client_access", "reject"], :connect, ctx) == :ok
  end

  test "helo access by name and parent domains" do
    ctx = context(access: access(:helo, %{".example.net" => "DEFER later"}))

    assert Restrictions.run(["helo_access"], :helo, ctx) |> reply() ==
             {450, "4.7.1 <client.example.net>: Helo command rejected: later"}

    # Not known yet: skipped.
    assert Restrictions.run(["helo_access"], :mail, %{ctx | helo: nil}) == :ok
  end

  test "sender and recipient access" do
    ctx =
      context(
        access: access(:sender, %{"alice@example.net" => "550 5.7.0 not you", "<>" => "REJECT"})
      )

    assert Restrictions.run(["sender_access"], :mail, ctx) |> reply() ==
             {550, "5.7.0 <alice+x@example.net>: Sender address rejected: not you"}

    assert {:reject, _} = Restrictions.run(["sender_access"], :mail, %{ctx | sender: ""})

    ctx =
      context(
        recipient: "bob@example.org",
        access: access(:recipient, %{"bob@" => "421 closing"})
      )

    assert Restrictions.run(["recipient_access"], :rcpt, ctx) |> reply() ==
             {421, "4.7.1 <bob@example.org>: Recipient address rejected: closing"}
  end

  test "actions" do
    ctx = fn action -> context(access: access(:client, %{"192.0.2.7" => action})) end

    assert Restrictions.run(["client_access", "reject"], :mail, ctx.("CONTINUE")) |> reply() ==
             {554, "5.7.1 Access denied"}

    assert Restrictions.run(["client_access", "reject"], :mail, ctx.("DISCARD trap")) ==
             {:discard, "trap"}

    assert Restrictions.run(["client_access"], :mail, ctx.("HOLD")) == {:hold, "held"}
    assert Restrictions.run(["client_access"], :mail, ctx.("HOLD look")) == {:hold, "look"}

    assert Restrictions.run(["client_access"], :mail, ctx.("BOGUS")) |> reply() ==
             {451, "4.3.5 Server configuration error"}

    assert Restrictions.run(["client_access"], :mail, ctx.("650 x")) |> reply() ==
             {451, "4.3.5 Server configuration error"}

    TelemetryForwarder.attach([[:sovite, :restrictions, :warn]])
    assert Restrictions.run(["client_access"], :mail, ctx.("WARN odd client")) == :ok

    assert_received {:telemetry, [:sovite, :restrictions, :warn], _,
                     %{stage: :mail, check: "client_access", text: "odd client"}}
  end

  test "a failing table is a temporary error" do
    ctx = context(access: %{client: [{"access_rules", FailingTable.new()}]})

    assert Restrictions.run(["client_access"], :mail, ctx) |> reply() ==
             {451, "4.3.0 Temporary lookup failure"}
  end

  test "fully-qualified names" do
    assert Restrictions.run(["require_fqdn_helo"], :helo, context(helo: "[192.0.2.1]")) == :ok

    assert Restrictions.run(["require_fqdn_helo"], :helo, context(helo: "localhost")) |> reply() ==
             {504, "5.5.2 <localhost>: Helo command rejected: need fully-qualified hostname"}

    assert {:reject, _} =
             Restrictions.run(["require_fqdn_sender"], :mail, context(sender: "a@localhost"))

    assert Restrictions.run(["require_fqdn_sender"], :mail, context(sender: "")) == :ok

    assert {:reject, _} =
             Restrictions.run(["require_fqdn_recipient"], :rcpt, context(recipient: "b@host"))

    assert Restrictions.run(["require_fqdn_recipient"], :rcpt, context(recipient: "Postmaster")) ==
             :ok
  end

  test "known domains" do
    resolver =
      FakeDNS.resolver(%{
        {"good.example", :mx} => [{10, "mx.good.example"}],
        {"down.example", :mx} => {:error, :timeout},
        {"gone.example", :mx} => {:error, :nxdomain}
      })

    run = fn check, fields ->
      Restrictions.run([check], :rcpt, context([resolver: resolver] ++ fields))
    end

    assert run.("require_known_sender_domain", sender: "a@good.example") == :ok

    assert run.("require_known_sender_domain", sender: "a@gone.example") |> reply() ==
             {550, "5.1.8 <a@gone.example>: Sender address rejected: Domain not found"}

    assert run.("require_known_sender_domain", sender: "a@down.example") |> reply() ==
             {450, "4.1.8 <a@down.example>: Sender address rejected: Domain not found"}

    assert run.("require_known_sender_domain", sender: "a@[192.0.2.1]") == :ok

    assert {:reject, %{code: 550}} =
             run.("require_known_recipient_domain", recipient: "b@gone.example")
  end

  describe "reverse DNS" do
    @reverse %{
      {"7.2.0.192.in-addr.arpa", :ptr} => ["client.example.net"],
      {"client.example.net", :a} => [{192, 0, 2, 7}],
      {"8.2.0.192.in-addr.arpa", :ptr} => ["forged.example.net"],
      {"forged.example.net", :a} => [{198, 51, 100, 1}],
      {"9.2.0.192.in-addr.arpa", :ptr} => {:error, :servfail}
    }

    defp reverse(check, ip, fields \\ []) do
      context = context([client_ip: ip, resolver: FakeDNS.resolver(@reverse)] ++ fields)
      Restrictions.run([check], :connect, context)
    end

    test "require_reverse_hostname needs a PTR name" do
      assert reverse("require_reverse_hostname", {192, 0, 2, 7}) == :ok
      assert reverse("require_reverse_hostname", {192, 0, 2, 8}) == :ok

      assert reverse("require_reverse_hostname", {192, 0, 2, 10}) |> reply() ==
               {550,
                "5.7.25 Client host rejected: cannot find your reverse hostname, [192.0.2.10]"}

      assert {450, "4.7.25 " <> _} =
               reverse("require_reverse_hostname", {192, 0, 2, 9}) |> reply()
    end

    test "require_fcrdns needs the name to resolve back" do
      assert reverse("require_fcrdns", {192, 0, 2, 7}) == :ok

      assert reverse("require_fcrdns", {192, 0, 2, 8}) |> reply() ==
               {550, "5.7.25 Client host rejected: cannot find your hostname, [192.0.2.8]"}

      assert {550, _} = reverse("require_fcrdns", {192, 0, 2, 10}) |> reply()
      assert {450, _} = reverse("require_fcrdns", {192, 0, 2, 9}) |> reply()
    end

    test "uses a result looked up before" do
      assert reverse("require_fcrdns", {192, 0, 2, 10}, client_dns: {:ok, "x.example"}) == :ok
    end

    test "is looked up when a chain needs it" do
      assert Restrictions.reverse_dns?(%{connect: [], mail: ["require_fcrdns"]})
      refute Restrictions.reverse_dns?(%{helo: ["require_fqdn_helo"]})
    end
  end

  describe "EHLO names" do
    @helo_dns %{
      {"client.example.net", :a} => [{192, 0, 2, 7}],
      {"other.example.net", :a} => [{198, 51, 100, 1}],
      {"mail.example.net", :mx} => [{10, "client.example.net"}],
      {"down.example.net", :a} => {:error, :timeout},
      {"down.example.net", :mx} => {:error, :timeout}
    }

    defp helo(check, name, fields \\ []) do
      context = context([helo: name, resolver: FakeDNS.resolver(@helo_dns)] ++ fields)
      Restrictions.run([check], :helo, context)
    end

    test "reject_forged_helo" do
      own = [own_names: ["mx.example.com", "example.com"]]
      assert helo("reject_forged_helo", "client.example.net", own) == :ok
      assert helo("reject_forged_helo", "[192.0.2.7]", own) == :ok

      for name <- ["MX.example.com", "example.com.", "localhost", "[192.0.2.8]"] do
        assert {550, "5.7.1 <" <> rest} = helo("reject_forged_helo", name, own) |> reply()
        assert rest == name <> ">: Helo command rejected: forged hostname"
      end
    end

    test "require_known_helo" do
      assert helo("require_known_helo", "client.example.net") == :ok
      assert helo("require_known_helo", "mail.example.net") == :ok
      assert helo("require_known_helo", "[192.0.2.99]") == :ok

      assert helo("require_known_helo", "nowhere.example.net") |> reply() ==
               {550, "5.7.1 <nowhere.example.net>: Helo command rejected: Host not found"}

      assert {450, "4.7.1 " <> _} = helo("require_known_helo", "down.example.net") |> reply()
    end

    test "require_matching_helo" do
      assert helo("require_matching_helo", "client.example.net") == :ok
      assert helo("require_matching_helo", "[192.0.2.7]") == :ok

      assert helo("require_matching_helo", "other.example.net") |> reply() ==
               {550,
                "5.7.1 <other.example.net>: Helo command rejected: does not match your address"}

      assert {550, _} = helo("require_matching_helo", "[192.0.2.8]") |> reply()
      assert {550, _} = helo("require_matching_helo", "nowhere.example.net") |> reply()
      assert {450, _} = helo("require_matching_helo", "down.example.net") |> reply()
    end
  end

  test "patterns tried" do
    assert Restrictions.client_keys("192.0.2.7") == ["192.0.2.7", "192.0.2", "192.0", "192"]
    assert Restrictions.client_keys("2001:db8::1") == ["2001:db8::1"]

    assert Restrictions.domain_keys("a.b.example") ==
             ["a.b.example", ".b.example", "b.example", ".example", "example"]

    assert Restrictions.address_keys("Al+x@B.example", "+") ==
             [
               "al+x@b.example",
               "al@b.example",
               "b.example",
               ".example",
               "example",
               "al+x@",
               "al@"
             ]
  end
end
