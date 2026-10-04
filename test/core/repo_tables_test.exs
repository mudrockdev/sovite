defmodule Sovite.Core.RepoTablesTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Repo.Tables.{
    AccessRules,
    AddressRewrites,
    Aliases,
    BccRules,
    DomainCache,
    Domains,
    Mailboxes,
    RelocatedUsers,
    SenderRelays,
    Transports
  }

  alias Sovite.Test.Database

  @moduletag :tmp_dir

  setup %{tmp_dir: dir}, do: %{repo: Database.start!(dir)}

  defp errors({:error, %Ecto.Changeset{} = changeset}),
    do: Ecto.Changeset.traverse_errors(changeset, fn {message, _} -> message end)

  test "domains", %{repo: repo} do
    assert {:ok, domain} = Domains.add(repo, " Example.COM ", "hosted")
    assert domain.name == "example.com" and domain.kind == :hosted
    assert {:ok, _} = Domains.add(repo, "relay.example", :relay)
    assert %{name: ["has already been taken"]} = errors(Domains.add(repo, "example.com", "local"))
    assert %{kind: ["is invalid"]} = errors(Domains.add(repo, "x.example", "virtual"))
    assert %{name: ["is not a valid domain"]} = errors(Domains.add(repo, "not a domain", "local"))

    assert Domains.classes(repo) == %{"example.com" => :hosted, "relay.example" => :relay}
    assert {:ok, _} = Domains.set_enabled(repo, "relay.example", false)
    assert Domains.classes(repo) == %{"example.com" => :hosted}
    assert Enum.map(Domains.list(repo), & &1.name) == ["example.com", "relay.example"]

    assert Domains.delete(repo, "example.com") == :ok
    assert Domains.delete(repo, "example.com") == {:error, :not_found}
    assert Domains.set_enabled(repo, "nope.example", true) == {:error, :not_found}
  end

  test "the domain cache follows the database", %{repo: repo} do
    {:ok, _} = Domains.add(repo, "a.example", "local")
    start_supervised!({DomainCache, repo: repo, interval: 20})
    id = DomainCache.id(repo)
    assert DomainCache.classes(id) == %{"a.example" => :local}

    {:ok, _} = Domains.add(repo, "b.example", "aliased")
    Process.sleep(100)
    assert DomainCache.classes(id) == %{"a.example" => :local, "b.example" => :aliased}

    stop_supervised!(DomainCache)
    assert DomainCache.classes(id) == %{}
  end

  test "aliases", %{repo: repo} do
    assert {:ok, entry} =
             Aliases.add(repo, "Sales@Example.com", ["a@example.net", "b@example.net"])

    assert entry.address == "sales@example.com"
    assert Enum.map(entry.destinations, & &1.address) == ["a@example.net", "b@example.net"]

    # Adding again only adds what is new.
    assert {:ok, entry} =
             Aliases.add(repo, "sales@example.com", ["b@example.net", "c@example.net"])

    assert length(entry.destinations) == 3

    assert {:ok, _} = Aliases.add(repo, "root", ["admin@example.net"])
    assert {:ok, _} = Aliases.add(repo, "@catch.example", ["inbox@example.net"])
    assert %{address: [_]} = errors(Aliases.add(repo, "a b", ["x@example.net"]))

    assert %{address: ["is not a valid email address"]} =
             errors(Aliases.add(repo, "x@example.com", ["nope"]))

    table = %{repo: repo}

    assert Aliases.lookup(table, "SALES@example.com") ==
             {:ok, "a@example.net, b@example.net, c@example.net"}

    assert Aliases.lookup(table, "root") == {:ok, "admin@example.net"}
    assert Aliases.lookup(table, "x@example.com") == :error

    assert Aliases.remove_destination(repo, "sales@example.com", "b@example.net") == :ok

    assert Aliases.remove_destination(repo, "sales@example.com", "b@example.net") ==
             {:error, :not_found}

    assert {:ok, _} = Aliases.set_enabled(repo, "root", false)
    assert Aliases.lookup(table, "root") == :error
    assert length(Aliases.list(repo)) == 3

    assert Aliases.delete(repo, "sales@example.com") == :ok
    assert Aliases.lookup(table, "sales@example.com") == :error
    assert Aliases.delete(repo, "sales@example.com") == {:error, :not_found}
  end

  test "mailboxes", %{repo: repo} do
    assert {:ok, _} = Mailboxes.add(repo, "Alice@Hosted.example")
    assert {:ok, _} = Mailboxes.add(repo, "@open.example")
    assert %{address: [_]} = errors(Mailboxes.add(repo, "alice"))

    table = %{repo: repo}
    assert Mailboxes.lookup(table, "alice@hosted.example") == {:ok, "alice@hosted.example"}
    assert {:ok, _} = Mailboxes.set_enabled(repo, "alice@hosted.example", false)
    assert Mailboxes.lookup(table, "alice@hosted.example") == :error
    assert length(Mailboxes.list(repo)) == 2
    assert Mailboxes.delete(repo, "@open.example") == :ok
  end

  test "moved users", %{repo: repo} do
    assert {:ok, _} = RelocatedUsers.set(repo, "old@example.com", "new@example.net")
    assert {:ok, _} = RelocatedUsers.set(repo, "old@example.com", "bob@example.org")
    assert %{new_location: _} = errors(RelocatedUsers.set(repo, "x@example.com", "a\nb"))

    assert RelocatedUsers.lookup(%{repo: repo}, "OLD@example.com") == {:ok, "bob@example.org"}
    assert [%{new_location: "bob@example.org"}] = RelocatedUsers.list(repo)
    assert RelocatedUsers.delete(repo, "old@example.com") == :ok
    assert RelocatedUsers.lookup(%{repo: repo}, "old@example.com") == :error
  end

  test "transports", %{repo: repo} do
    assert {:ok, _} = Transports.set(repo, "Example.com", "lmtp:unix:/run/dovecot/lmtp")
    assert {:ok, _} = Transports.set(repo, ".sub.example.com", "smtp:[relay.example]:587")
    assert {:ok, _} = Transports.set(repo, "*", "smtp:")
    assert %{transport: [_]} = errors(Transports.set(repo, "x.example", "carrier-pigeon:"))
    assert %{pattern: [_]} = errors(Transports.set(repo, "not a pattern", "smtp"))

    assert Transports.lookup(%{repo: repo}, "example.com") == {:ok, "lmtp:unix:/run/dovecot/lmtp"}
    assert {:ok, _} = Transports.set(repo, "example.com", "smtp")
    assert Transports.lookup(%{repo: repo}, "example.com") == {:ok, "smtp"}
    assert length(Transports.list(repo)) == 3
    assert Transports.delete(repo, "*") == :ok
  end

  test "sender relays", %{repo: repo} do
    assert {:ok, _} =
             SenderRelays.set(repo, "@corp.example", %{relayhost: "[smtp.corp.example]:587"})

    assert {:ok, relay} =
             SenderRelays.set(repo, "@corp.example", %{
               source_address: "192.0.2.10 2001:db8::10",
               username: "corp",
               password: "secret"
             })

    assert relay.relayhost == "[smtp.corp.example]:587"
    refute inspect(relay) =~ "secret"

    assert %{relayhost: _} =
             errors(SenderRelays.set(repo, "a@x.example", %{relayhost: "bad host"}))

    assert %{source_address: _} =
             errors(
               SenderRelays.set(repo, "a@x.example", %{source_address: "192.0.2.1 192.0.2.2"})
             )

    assert %{username: _} = errors(SenderRelays.set(repo, "a@x.example", %{username: "a:b"}))

    lookup = &SenderRelays.lookup(%{repo: repo, field: &1}, "@corp.example")
    assert lookup.(:relayhost) == {:ok, "[smtp.corp.example]:587"}
    assert lookup.(:source_address) == {:ok, "192.0.2.10 2001:db8::10"}
    assert lookup.(:credentials) == {:ok, "corp:secret"}

    assert {:ok, _} = SenderRelays.set(repo, "@corp.example", %{username: nil, password: nil})
    assert lookup.(:credentials) == :error
    assert SenderRelays.lookup(%{repo: repo, field: :relayhost}, "@other.example") == :error
    assert [_] = SenderRelays.list(repo)
    assert SenderRelays.delete(repo, "@corp.example") == :ok
  end

  test "access rules", %{repo: repo} do
    assert {:ok, _} = AccessRules.set(repo, :client, "192.0.2", "reject", "go away")
    assert {:ok, _} = AccessRules.set(repo, "sender", "@spam.example", "DISCARD")
    assert {:ok, _} = AccessRules.set(repo, :client, "192.0.2", "550", "5.7.1 no")
    assert %{action: [_]} = errors(AccessRules.set(repo, :client, "x", "MAYBE"))
    assert %{kind: ["is invalid"]} = errors(AccessRules.set(repo, "header", "x", "REJECT"))

    assert AccessRules.lookup(%{repo: repo, kind: :client}, "192.0.2") == {:ok, "550 5.7.1 no"}
    assert AccessRules.lookup(%{repo: repo, kind: :sender}, "@spam.example") == {:ok, "DISCARD"}
    assert AccessRules.lookup(%{repo: repo, kind: :helo}, "192.0.2") == :error
    assert length(AccessRules.list(repo)) == 2
    assert AccessRules.delete(repo, :client, "192.0.2") == :ok
    assert AccessRules.delete(repo, :client, "192.0.2") == {:error, :not_found}
  end

  test "address rewrites", %{repo: repo} do
    assert {:ok, _} =
             AddressRewrites.set(repo, :sender, "alice@example.com", "Alice.Smith@example.com")

    assert {:ok, _} = AddressRewrites.set(repo, "both", "@old.example", "@new.example")
    assert {:ok, _} = AddressRewrites.set(repo, :sender, "alice@example.com", "a@example.com")
    assert %{replacement: [_]} = errors(AddressRewrites.set(repo, :both, "x@example.com", "a b"))

    assert AddressRewrites.lookup(%{repo: repo, kind: :sender}, "alice@example.com") ==
             {:ok, "a@example.com"}

    assert AddressRewrites.lookup(%{repo: repo, kind: :recipient}, "alice@example.com") == :error

    assert AddressRewrites.lookup(%{repo: repo, kind: :both}, "@old.example") ==
             {:ok, "@new.example"}

    assert length(AddressRewrites.list(repo)) == 2
    assert AddressRewrites.delete(repo, :both, "@old.example") == :ok
  end

  test "bcc rules", %{repo: repo} do
    assert {:ok, _} = BccRules.add(repo, :recipient, "ceo@example.com", "assistant@example.com")
    assert {:ok, _} = BccRules.add(repo, "recipient", "ceo@example.com", "archive@example.com")

    assert %{kind: _} =
             errors(BccRules.add(repo, :recipient, "ceo@example.com", "archive@example.com"))

    assert %{address: [_]} = errors(BccRules.add(repo, :sender, "@x.example", "nope"))

    assert BccRules.lookup(%{repo: repo, kind: :recipient}, "ceo@example.com") ==
             {:ok, "assistant@example.com, archive@example.com"}

    assert BccRules.lookup(%{repo: repo, kind: :sender}, "ceo@example.com") == :error
    assert length(BccRules.list(repo)) == 2
    assert BccRules.delete(repo, :recipient, "ceo@example.com", "assistant@example.com") == :ok
  end

  test "a database failure is a lookup error", %{repo: {module, pid}} do
    repo = {module, pid}
    Supervisor.stop(pid)
    assert {:error, {:database, _}} = Aliases.lookup(%{repo: repo}, "a@example.com")
  end
end
