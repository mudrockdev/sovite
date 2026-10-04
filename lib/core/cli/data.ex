defmodule Sovite.Core.CLI.Data do
  @moduledoc false
  # The sovitectl commands for routing data in the database: domains,
  # aliases, mailboxes, moved users, transports, sender relays, access
  # rules, address rewrites, and BCC rules.

  import Sovite.Core.CLI.Helpers

  alias Sovite.Core.Repo.Schemas.Domain

  alias Sovite.Core.Repo.Tables.{
    AccessRules,
    AddressRewrites,
    Aliases,
    BccRules,
    Domains,
    Mailboxes,
    RelocatedUsers,
    SenderRelays,
    Transports
  }

  @commands ~w(domain alias mailbox moved transport sender-relay access rewrite bcc)

  @usage """
    domain list                       List the domains in the database
    domain add NAME KIND              Add a domain. KIND: local, aliased, hosted, relay
    domain delete|enable|disable NAME
    alias list                        List aliases and their destinations
    alias add ADDRESS DEST...         Add destinations to an alias (ADDRESS: address, @domain, or local part)
    alias remove ADDRESS DEST         Remove one destination
    alias delete|enable|disable ADDRESS
    mailbox list                      List hosted mailboxes
    mailbox add|delete|enable|disable ADDRESS
    moved list                        List users who moved
    moved set ADDRESS TEXT...         Reject mail for ADDRESS with "User has moved to TEXT"
    moved delete ADDRESS
    transport list                    List transport map entries
    transport set PATTERN TRANSPORT   Route PATTERN (address, domain, .domain, *) through TRANSPORT
    transport delete PATTERN
    sender-relay list                 List sender-dependent relaying
    sender-relay set SENDER relayhost HOST
    sender-relay set SENDER source ADDRESS...
    sender-relay set SENDER login USERNAME   The password is read from standard input
    sender-relay clear SENDER relayhost|source|login
    sender-relay delete SENDER
    access list                       List access rules
    access set KIND PATTERN ACTION [TEXT...]  KIND: client, helo, sender, recipient
    access delete KIND PATTERN
    rewrite list                      List address rewrites
    rewrite set KIND PATTERN NEW      Rewrite addresses. KIND: sender, recipient, both
    rewrite delete KIND PATTERN
    bcc list                          List BCC rules
    bcc add KIND PATTERN ADDRESS      Copy mail whose sender/recipient (KIND) matches PATTERN to ADDRESS
    bcc delete KIND PATTERN ADDRESS
  """

  @doc "The commands this module handles."
  def commands, do: @commands

  @doc "Usage lines for the help text."
  def usage, do: @usage

  @doc "Runs a command. Returns the exit status, or `:usage`."
  def run(["domain", "list"], path), do: with_repo(path, &list_domains/1)

  def run(["domain", "add", name, kind], path) do
    if kind in Enum.map(Domain.kinds(), &Atom.to_string/1),
      do: with_repo(path, &result(Domains.add(&1, name, kind), "added #{name} (#{kind})")),
      else: fail("unknown kind #{inspect(kind)}: use local, aliased, hosted, or relay")
  end

  def run(["domain", "delete", name], path),
    do: with_repo(path, &result(Domains.delete(&1, name), "deleted #{name}", "no such domain"))

  def run(["domain", toggle, name], path) when toggle in ["enable", "disable"] do
    with_repo(path, fn repo ->
      repo
      |> Domains.set_enabled(name, toggle == "enable")
      |> result("#{toggle}d #{name}", "no such domain")
    end)
  end

  def run(["alias", "list"], path), do: with_repo(path, &list_aliases/1)

  def run(["alias", "add", address | [_ | _] = destinations], path) do
    with_repo(path, fn repo ->
      result(
        Aliases.add(repo, address, destinations),
        "#{address} -> #{Enum.join(destinations, ", ")}"
      )
    end)
  end

  def run(["alias", "remove", address, destination], path) do
    with_repo(path, fn repo ->
      repo
      |> Aliases.remove_destination(address, destination)
      |> result("removed #{destination} from #{address}", "no such alias destination")
    end)
  end

  def run(["alias", "delete", address], path),
    do:
      with_repo(path, &result(Aliases.delete(&1, address), "deleted #{address}", "no such alias"))

  def run(["alias", toggle, address], path) when toggle in ["enable", "disable"] do
    with_repo(path, fn repo ->
      repo
      |> Aliases.set_enabled(address, toggle == "enable")
      |> result("#{toggle}d #{address}", "no such alias")
    end)
  end

  def run(["mailbox", "list"], path), do: with_repo(path, &list_mailboxes/1)

  def run(["mailbox", "add", address], path),
    do: with_repo(path, &result(Mailboxes.add(&1, address), "added #{address}"))

  def run(["mailbox", "delete", address], path),
    do:
      with_repo(
        path,
        &result(Mailboxes.delete(&1, address), "deleted #{address}", "no such mailbox")
      )

  def run(["mailbox", toggle, address], path) when toggle in ["enable", "disable"] do
    with_repo(path, fn repo ->
      repo
      |> Mailboxes.set_enabled(address, toggle == "enable")
      |> result("#{toggle}d #{address}", "no such mailbox")
    end)
  end

  def run(["moved", "list"], path), do: with_repo(path, &list_relocated/1)

  def run(["moved", "set", address | [_ | _] = text], path) do
    location = Enum.join(text, " ")

    with_repo(
      path,
      &result(RelocatedUsers.set(&1, address, location), "#{address} moved to #{location}")
    )
  end

  def run(["moved", "delete", address], path) do
    with_repo(
      path,
      &result(RelocatedUsers.delete(&1, address), "deleted #{address}", "no such entry")
    )
  end

  def run(["transport", "list"], path), do: with_repo(path, &list_transports/1)

  def run(["transport", "set", pattern, transport], path),
    do:
      with_repo(
        path,
        &result(Transports.set(&1, pattern, transport), "#{pattern} -> #{transport}")
      )

  def run(["transport", "delete", pattern], path),
    do:
      with_repo(
        path,
        &result(Transports.delete(&1, pattern), "deleted #{pattern}", "no such entry")
      )

  def run(["sender-relay" | args], path), do: sender_relay(args, path)
  def run(["access" | args], path), do: access(args, path)
  def run(["rewrite" | args], path), do: rewrite(args, path)
  def run(["bcc" | args], path), do: bcc(args, path)
  def run(_argv, _path), do: :usage

  defp sender_relay(["list"], path), do: with_repo(path, &list_sender_relays/1)

  defp sender_relay(["set", sender, "relayhost", host], path),
    do: set_relay(path, sender, %{relayhost: host}, "mail from #{sender} goes through #{host}")

  defp sender_relay(["set", sender, "source" | [_ | _] = ips], path) do
    source = Enum.join(ips, " ")

    set_relay(
      path,
      sender,
      %{source_address: source},
      "mail from #{sender} is sent from #{source}"
    )
  end

  defp sender_relay(["set", sender, "login", username], path) do
    with_password(fn password ->
      set_relay(
        path,
        sender,
        %{username: username, password: password},
        "mail from #{sender} logs in as #{username}"
      )
    end)
  end

  defp sender_relay(["clear", sender, field], path)
       when field in ["relayhost", "source", "login"] do
    fields =
      case field do
        "relayhost" -> %{relayhost: nil}
        "source" -> %{source_address: nil}
        "login" -> %{username: nil, password: nil}
      end

    set_relay(path, sender, fields, "cleared #{field} for #{sender}")
  end

  defp sender_relay(["delete", sender], path),
    do:
      with_repo(
        path,
        &result(SenderRelays.delete(&1, sender), "deleted #{sender}", "no such entry")
      )

  defp sender_relay(_args, _path), do: :usage

  defp set_relay(path, sender, fields, message),
    do: with_repo(path, &result(SenderRelays.set(&1, sender, fields), message))

  defp access(["list"], path), do: with_repo(path, &list_access/1)

  defp access(["set", kind, pattern, action | text], path) do
    with {:ok, kind} <- access_kind(kind) do
      text = if text == [], do: nil, else: Enum.join(text, " ")

      with_repo(path, fn repo ->
        result(
          AccessRules.set(repo, kind, pattern, action, text),
          "#{kind} #{pattern}: #{action}"
        )
      end)
    end
  end

  defp access(["delete", kind, pattern], path) do
    with {:ok, kind} <- access_kind(kind) do
      with_repo(
        path,
        &result(
          AccessRules.delete(&1, kind, pattern),
          "deleted #{kind} #{pattern}",
          "no such rule"
        )
      )
    end
  end

  defp access(_args, _path), do: :usage

  defp rewrite(["list"], path), do: with_repo(path, &list_rewrites/1)

  defp rewrite(["set", kind, pattern, replacement], path) do
    with {:ok, kind} <- rewrite_kind(kind) do
      with_repo(path, fn repo ->
        result(
          AddressRewrites.set(repo, kind, pattern, replacement),
          "#{kind} #{pattern} -> #{replacement}"
        )
      end)
    end
  end

  defp rewrite(["delete", kind, pattern], path) do
    with {:ok, kind} <- rewrite_kind(kind) do
      with_repo(
        path,
        &result(
          AddressRewrites.delete(&1, kind, pattern),
          "deleted #{kind} #{pattern}",
          "no such rewrite"
        )
      )
    end
  end

  defp rewrite(_args, _path), do: :usage

  defp bcc(["list"], path), do: with_repo(path, &list_bcc/1)

  defp bcc(["add", kind, pattern, address], path) do
    with {:ok, kind} <- bcc_kind(kind) do
      with_repo(
        path,
        &result(
          BccRules.add(&1, kind, pattern, address),
          "#{kind} #{pattern}: copy to #{address}"
        )
      )
    end
  end

  defp bcc(["delete", kind, pattern, address], path) do
    with {:ok, kind} <- bcc_kind(kind) do
      with_repo(
        path,
        &result(
          BccRules.delete(&1, kind, pattern, address),
          "deleted #{kind} #{pattern} #{address}",
          "no such rule"
        )
      )
    end
  end

  defp bcc(_args, _path), do: :usage

  # Fixed table: never create atoms from the command line.
  defp access_kind("client"), do: {:ok, :client}
  defp access_kind("helo"), do: {:ok, :helo}
  defp access_kind("sender"), do: {:ok, :sender}
  defp access_kind("recipient"), do: {:ok, :recipient}

  defp access_kind(kind),
    do: fail("unknown kind #{inspect(kind)}: use client, helo, sender, or recipient")

  defp rewrite_kind("sender"), do: {:ok, :sender}
  defp rewrite_kind("recipient"), do: {:ok, :recipient}
  defp rewrite_kind("both"), do: {:ok, :both}

  defp rewrite_kind(kind),
    do: fail("unknown kind #{inspect(kind)}: use sender, recipient, or both")

  defp bcc_kind("sender"), do: {:ok, :sender}
  defp bcc_kind("recipient"), do: {:ok, :recipient}
  defp bcc_kind(kind), do: fail("unknown kind #{inspect(kind)}: use sender or recipient")

  ## Listing

  defp list_domains(repo) do
    for domain <- Domains.list(repo),
        do: IO.puts("#{domain.name}  #{domain.kind}#{disabled(domain)}")

    0
  end

  defp list_aliases(repo) do
    for entry <- Aliases.list(repo) do
      destinations = Enum.map_join(entry.destinations, ", ", & &1.address)
      IO.puts("#{entry.address}  -> #{destinations}#{disabled(entry)}")
    end

    0
  end

  defp list_mailboxes(repo) do
    for mailbox <- Mailboxes.list(repo), do: IO.puts("#{mailbox.address}#{disabled(mailbox)}")
    0
  end

  defp list_relocated(repo) do
    for entry <- RelocatedUsers.list(repo), do: IO.puts("#{entry.address}  #{entry.new_location}")
    0
  end

  defp list_transports(repo) do
    for entry <- Transports.list(repo), do: IO.puts("#{entry.pattern}  #{entry.transport}")
    0
  end

  defp list_sender_relays(repo) do
    for relay <- SenderRelays.list(repo) do
      parts =
        [
          relay.relayhost && "relayhost #{relay.relayhost}",
          relay.source_address && "source #{relay.source_address}",
          relay.username && "login #{relay.username}"
        ]
        |> Enum.filter(& &1)

      IO.puts("#{relay.sender}  #{Enum.join(parts, ", ")}")
    end

    0
  end

  defp list_access(repo) do
    for rule <- AccessRules.list(repo) do
      text = if rule.text, do: " " <> rule.text, else: ""
      IO.puts("#{rule.kind}  #{rule.pattern}  #{rule.action}#{text}")
    end

    0
  end

  defp list_rewrites(repo) do
    for rewrite <- AddressRewrites.list(repo),
        do: IO.puts("#{rewrite.kind}  #{rewrite.pattern}  -> #{rewrite.replacement}")

    0
  end

  defp list_bcc(repo) do
    for rule <- BccRules.list(repo),
        do: IO.puts("#{rule.kind}  #{rule.pattern}  -> #{rule.address}")

    0
  end

  defp disabled(%{enabled: false}), do: "  (disabled)"
  defp disabled(_row), do: ""
end
