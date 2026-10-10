defmodule Sovite.Core.Postfix.Imports do
  @moduledoc false
  # Postfix lookup tables -> sovitectl commands for import.sh: aliases,
  # mailboxes, transports, moved users, address rewrites, BCC rules,
  # sender-dependent relays, and domains kept in tables.

  alias Sovite.Core.Postfix.{Convert, MainCf, Services, State, Table}
  alias Sovite.Core.Transport

  @doc "Adds the import commands of every table main.cf names."
  def migrate(state) do
    state
    |> aliases()
    |> virtual_aliases()
    |> mailboxes()
    |> transports()
    |> relocated()
    |> rewrites()
    |> bcc()
    |> sender_relays()
    |> sender_logins()
  end

  # Reads each table of a list parameter. `fun` turns the entries into
  # {commands, problems, state}.
  defp each_table(state, name, opts, fun) do
    explicit = State.set?(state, name)
    tables = State.list(state, name)
    state = State.handle(state, name)

    if explicit or Keyword.get(opts, :default, false),
      do: Enum.reduce(tables, state, &import_table(&2, name, &1, explicit, opts, fun)),
      else: state
  end

  defp import_table(state, name, table, explicit, opts, fun) do
    read = if opts[:aliases], do: &Table.read_aliases/2, else: &Table.read/2

    case read.(table, state.read) do
      {:ok, entries} ->
        {commands, problems, state} = fun.(entries, state)

        state
        |> State.commands("#{name} = #{table}", commands)
        |> State.table_report(name, table, length(commands), problems, opts[:what] || "entries")

      # A default table (/etc/aliases) that does not exist.
      {:error, {:unreadable, _path, :enoent}} when not explicit ->
        state

      {:error, reason} ->
        State.report(state, :attention, name, table, Table.describe_error(reason) <> ".")
    end
  end

  # Builds the commands of a table with `fun`, called for each entry.
  defp entries_with(fun), do: &build(&1, &2, fun)

  # Builds commands from entries; `fun` returns {:ok, command},
  # {:skip}, or {:error, message} per entry.
  defp build(entries, state, fun) do
    {commands, problems, state} =
      Enum.reduce(entries, {[], [], state}, fn {key, value}, {commands, problems, state} ->
        case fun.(key, value, state) do
          {:ok, {:many, many}, state} -> {Enum.reverse(many) ++ commands, problems, state}
          {:ok, command, state} -> {[command | commands], problems, state}
          {:ok, command} -> {[command | commands], problems, state}
          :skip -> {commands, problems, state}
          {:error, message} -> {commands, [{key, message} | problems], state}
        end
      end)

    {Enum.reverse(commands), Enum.reverse(problems), state}
  end

  ## Aliases

  defp aliases(state) do
    opts = [aliases: true, default: true, what: "aliases"]
    each_table(state, "alias_maps", opts, entries_with(&alias_entry/3))
  end

  defp alias_entry(name, destinations, state) do
    if Convert.form?(name, [:local_part, :address]),
      do: alias_command(state, name, destinations),
      else: {:error, "not a local part or address"}
  end

  defp virtual_aliases(state),
    do: each_table(state, "virtual_alias_maps", [what: "aliases"], entries_with(&virtual_alias/3))

  defp virtual_alias(key, value, state) do
    cond do
      domain_declaration?(key, value) ->
        :skip

      Convert.form?(key, [:address, :catchall, :local_part]) ->
        alias_command(state, key, MainCf.split(value))

      true ->
        {:error, "not an address, @domain, or local part"}
    end
  end

  @doc """
  Whether a virtual table entry declares a domain (`example.com
  anything`), as Postfix reads virtual_alias_domains and
  virtual_mailbox_domains from the maps by default.
  """
  def domain_declaration?(key, value) do
    not String.contains?(key, "@") and String.contains?(key, ".") and Convert.domain?(key) and
      not String.contains?(value, "@")
  end

  defp alias_command(state, name, destinations) do
    {good, bad} =
      destinations
      |> Enum.map(&destination(state, &1))
      |> Enum.split_with(&match?({:ok, _}, &1))

    good = for {:ok, address} <- good, uniq: true, do: address
    bad = for {:error, message} <- bad, do: message

    cond do
      good == [] and bad == [] -> {:error, "no destinations"}
      good == [] -> {:error, Enum.join(bad, "; ")}
      bad == [] -> {:ok, ["alias", "add", name | good]}
      true -> {:ok, ["alias", "add", name | good], partial(state, name, bad)}
    end
  end

  defp partial(state, name, problems),
    do:
      State.report(
        state,
        :attention,
        "alias #{name}",
        nil,
        "Some destinations were left out: " <> Enum.join(problems, "; ") <> "."
      )

  # Destinations without a domain get myorigin, as Postfix appends it.
  defp destination(state, destination) do
    destination = String.trim_leading(destination, "\\")

    cond do
      String.starts_with?(destination, "|") ->
        {:error,
         "#{destination}: commands are not supported (use a [pipe.NAME] transport and a transport map entry)"}

      String.starts_with?(destination, ":include:") ->
        {:error, "#{destination}: :include: files are not supported (list the addresses)"}

      String.starts_with?(destination, "/") ->
        {:error, "#{destination}: delivery to files is not supported"}

      Convert.address?(destination) ->
        {:ok, destination}

      Convert.form?(destination, [:local_part]) and state.origin != nil ->
        {:ok, destination <> "@" <> state.origin}

      true ->
        {:error, "#{destination}: not an address"}
    end
  end

  ## Mailboxes

  defp mailboxes(state) do
    each_table(state, "virtual_mailbox_maps", [what: "mailboxes"], fn entries, state ->
      seen = State.flag(state, :mailbox_entries) || []
      state = State.flag(state, :mailbox_entries, seen ++ entries)
      build(entries, state, &mailbox_entry/3)
    end)
  end

  defp mailbox_entry(key, value, _state) do
    cond do
      domain_declaration?(key, value) -> :skip
      Convert.form?(key, [:address, :catchall]) -> {:ok, ["mailbox", "add", key]}
      true -> {:error, "not an address or @domain"}
    end
  end

  ## Transports

  defp transports(state) do
    opts = [what: "transport map entries"]
    each_table(state, "transport_maps", opts, entries_with(&transport_entry/3))
  end

  defp transport_entry(pattern, value, state) do
    if Convert.form?(pattern, [:address, :domain, :subdomains, :wildcard]) do
      with {:ok, spec, state} <- transport(state, value),
           do: {:ok, ["transport", "set", pattern, spec], state}
    else
      {:error, "not an address, domain, .domain, or *"}
    end
  end

  defp transport(state, value) do
    case Services.transport(state, value, "transport_maps") do
      {:ok, spec, state} -> {:ok, spec, state}
      {:error, message, _state} -> {:error, message}
    end
  end

  ## Moved users

  defp relocated(state),
    do: each_table(state, "relocated_maps", [what: "moved users"], entries_with(&moved_entry/3))

  defp moved_entry(key, value, _state) do
    cond do
      value == "" -> {:error, "no new location"}
      Convert.form?(key, [:address, :catchall]) -> {:ok, ["moved", "set", key, value]}
      true -> {:error, "not an address or @domain"}
    end
  end

  ## Rewrites

  @rewrites [
    {"canonical_maps", "both"},
    {"sender_canonical_maps", "sender"},
    {"recipient_canonical_maps", "recipient"}
  ]

  defp rewrites(state) do
    Enum.reduce(@rewrites, state, fn {name, kind}, state ->
      each_table(
        state,
        name,
        [what: "address rewrites"],
        entries_with(&rewrite_entry(kind, &1, &2, &3))
      )
    end)
  end

  @rewrite_forms [:address, :catchall, :local_part]

  defp rewrite_entry(kind, pattern, value, _state) do
    cond do
      not Convert.form?(pattern, @rewrite_forms) ->
        {:error, "not an address, @domain, or local part"}

      not Convert.form?(value, @rewrite_forms) ->
        {:error, "#{value}: not an address, @domain, or local part"}

      true ->
        {:ok, ["rewrite", "set", kind, pattern, value]}
    end
  end

  ## BCC

  defp bcc(state) do
    Enum.reduce([{"sender_bcc_maps", "sender"}, {"recipient_bcc_maps", "recipient"}], state, fn
      {name, kind}, state ->
        each_table(state, name, [what: "BCC rules"], entries_with(&bcc_entry(kind, &1, &2, &3)))
    end)
  end

  defp bcc_entry(kind, pattern, value, _state) do
    cond do
      not Convert.form?(pattern, [:address, :catchall]) -> {:error, "not an address or @domain"}
      not Convert.address?(value) -> {:error, "#{value}: not an address"}
      true -> {:ok, ["bcc", "add", kind, pattern, value]}
    end
  end

  ## Sender-dependent relays

  defp sender_relays(state) do
    passwords = passwords(state)
    by_sender = Convert.yes?(State.value(state, "smtp_sender_dependent_authentication"))
    state = State.handle(state, "smtp_sender_dependent_authentication")

    relay = &relay_commands(&3, &1, &2, passwords, by_sender)

    state =
      each_table(
        state,
        "sender_dependent_relayhost_maps",
        [what: "sender relays"],
        entries_with(relay)
      )

    state = if by_sender, do: sender_logins_only(state, passwords), else: state
    unused_passwords(state, passwords)
  end

  defp relay_commands(state, sender, relayhost, passwords, by_sender) do
    cond do
      not Convert.form?(sender, [:address, :catchall]) -> {:error, "not an address or @domain"}
      String.upcase(relayhost) == "DUNNO" -> :skip
      Transport.parse_host(relayhost, 25) == :error -> {:error, "#{relayhost}: not a relay host"}
      true -> relay_login(state, sender, relayhost, passwords, by_sender)
    end
  end

  # The relay host, and the login for it: by sender when
  # smtp_sender_dependent_authentication is on, else by relay host.
  defp relay_login(state, sender, relayhost, passwords, by_sender) do
    key = if by_sender and Map.has_key?(passwords, sender), do: sender, else: relayhost

    login =
      for {username, password} <- List.wrap(passwords[key]),
          do: {:stdin, password, ["sender-relay", "set", sender, "login", username]}

    state =
      state
      |> State.flag({:password_used, key}, true)
      |> State.flag({:relay_sender, sender}, true)

    {:ok, {:many, [["sender-relay", "set", sender, "relayhost", relayhost] | login]}, state}
  end

  # With smtp_sender_dependent_authentication, senders can have a login
  # for the default relay host.
  defp sender_logins_only(state, passwords) do
    commands =
      for {sender, {username, password}} <- passwords,
          Convert.form?(sender, [:address, :catchall]),
          not State.flag(state, {:relay_sender, sender}),
          do: {sender, {:stdin, password, ["sender-relay", "set", sender, "login", username]}}

    state =
      Enum.reduce(commands, state, fn {sender, _}, state ->
        State.flag(state, {:password_used, sender}, true)
      end)

    State.commands(
      state,
      "smtp_sasl_password_maps: logins by sender",
      Enum.map(commands, &elem(&1, 1))
    )
  end

  @doc "The entries of smtp_sasl_password_maps: key => {username, password}."
  def passwords(state) do
    Enum.reduce(State.list(state, "smtp_sasl_password_maps"), %{}, fn table, acc ->
      Map.merge(acc, password_entries(table, state))
    end)
  end

  defp password_entries(table, state) do
    case Table.read(table, state.read) do
      {:ok, entries} ->
        for {key, value} <- entries,
            [username, password] <- [String.split(value, ":", parts: 2)],
            into: %{},
            do: {key, {username, password}}

      {:error, _reason} ->
        %{}
    end
  end

  defp unused_passwords(state, passwords) do
    state = State.handle(state, "smtp_sasl_password_maps")
    unused = for {key, _} <- passwords, not State.flag(state, {:password_used, key}), do: key

    cond do
      not State.set?(state, "smtp_sasl_password_maps") ->
        state

      unused == [] ->
        State.report_param(
          state,
          :migrated,
          "smtp_sasl_password_maps",
          "Logins for the relay hosts (see delivery.relayhost_username and sender-relay commands)."
        )

      true ->
        State.report_param(
          state,
          :attention,
          "smtp_sasl_password_maps",
          "Only logins for the relay host and sender-dependent relays are migrated. Not migrated: #{Enum.sort(unused) |> Enum.join(", ")}."
        )
    end
  end

  ## Sender login maps

  # A sender pattern and the logins that may use it, gathered by login.
  defp sender_logins_entry({pattern, logins}, {senders, problems}) do
    if Convert.form?(pattern, [:address, :catchall]) do
      senders =
        Enum.reduce(MainCf.split(logins), senders, fn login, senders ->
          Map.update(senders, login, [pattern], &Enum.uniq(&1 ++ [pattern]))
        end)

      {senders, problems}
    else
      {senders, [{pattern, "not an address or @domain"} | problems]}
    end
  end

  defp not_migrated([]), do: ""

  defp not_migrated(problems),
    do:
      " Not migrated: " <>
        Enum.map_join(problems, "; ", fn {key, message} -> "#{key}: #{message}" end) <> "."

  defp sender_logins(state) do
    if State.set?(state, "smtpd_sender_login_maps") do
      State.list(state, "smtpd_sender_login_maps")
      |> Enum.reduce(State.handle(state, "smtpd_sender_login_maps"), &login_table/2)
    else
      state
    end
  end

  defp login_table(table, state) do
    case Table.read(table, state.read) do
      {:ok, entries} ->
        {senders, problems} = Enum.reduce(entries, {%{}, []}, &sender_logins_entry/2)

        state =
          Enum.reduce(Enum.sort(senders), state, fn {login, patterns}, state ->
            existing = State.get(state, "auth.senders", login) || []
            State.put(state, "auth.senders", login, Enum.uniq(existing ++ patterns))
          end)

        level = if problems == [], do: :migrated, else: :attention

        State.report(
          state,
          level,
          "smtpd_sender_login_maps",
          table,
          "-> [auth.senders] (#{map_size(senders)} logins). Sovite also lets a user send as its own login when it is an address." <>
            not_migrated(Enum.reverse(problems))
        )

      {:error, reason} ->
        State.report(
          state,
          :attention,
          "smtpd_sender_login_maps",
          table,
          Table.describe_error(reason) <> "."
        )
    end
  end
end
