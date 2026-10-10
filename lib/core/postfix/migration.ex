defmodule Sovite.Core.Postfix.Migration do
  @moduledoc """
  Turns a Postfix configuration into a Sovite one, for
  `sovitectl migrate postfix`.

  `migrate/3` reads the contents of `main.cf` and `master.cf`, and the
  lookup tables they name through a read function, and returns:

    * `config` - a `sovite.toml`, which `Sovite.Core.Config.parse/1`
      accepts. Values that need a look have a `# check:` comment.
    * `script` - an `import.sh` of `sovitectl` commands that load the
      lookup tables (aliases, mailboxes, transports, access rules, ...)
      into Sovite's database. It can hold relay passwords.
    * `report` - what was migrated, what was ignored because Sovite does
      it anyway or it does not apply, and what needs attention: settings
      Sovite has no equivalent for, and manual steps.

  It also returns the report lines as `entries`, the commands of the
  script as `commands` (argument lists, or `{:stdin, password, args}`),
  and the problems `Config.parse/1` found in `config` as `errors`, which
  should be none.

  Only the parameters main.cf sets are reported, apart from Postfix
  defaults that change what Sovite does (such as `mynetworks_style`).
  The files are untrusted input: no atoms are created from them.
  """

  alias Sovite.Core.Config

  alias Sovite.Core.Postfix.{
    Checks,
    Convert,
    Domains,
    Imports,
    MainCf,
    MasterCf,
    Security,
    Services,
    Settings,
    State,
    TomlWriter
  }

  @typedoc "A report line."
  @type entry :: %{
          level: :attention | :migrated | :ignored,
          setting: String.t(),
          value: String.t() | nil,
          message: String.t()
        }

  @type result :: %{
          config: String.t(),
          script: String.t(),
          report: String.t(),
          entries: [entry()],
          commands: [[String.t()] | {:stdin, String.t(), [String.t()]}],
          errors: [String.t()]
        }

  # The sections of sovite.toml, in the order of docs/configuration.md.
  @layout [
    {:table, "server"},
    {:table, "queue"},
    {:array, "listener"},
    {:table, "tls"},
    {:array, "tls.certificate"},
    {:table, "smtp"},
    {:table, "domains"},
    {:table, "routing"},
    {:table, "maildir"},
    :pipes,
    {:table, "delivery"},
    {:table, "screen"},
    {:array, "screen.dnsbl"},
    {:array, "screen.rhsbl"},
    {:table, "restrictions"},
    {:table, "rate_limit"},
    {:array, "milter"},
    {:table, "policy"},
    {:table, "sendmail"},
    {:table, "auth"},
    {:table, "auth.dovecot"},
    {:table, "auth.senders"},
    {:table, "spf"},
    {:table, "bounce"}
  ]

  @doc """
  Migrates `main_cf` and `master_cf` (`nil` when there is none).

  Options:

    * `:read` - reads a file Postfix names, such as a lookup table's
      source: `(path -> {:ok, binary} | {:error, reason})`. Default:
      `File.read/1`.
    * `:defaults` - Postfix defaults that depend on the system, such as
      `"myhostname"`. See `Sovite.Core.Postfix.MainCf.parse/2`.
    * `:source` - where the files came from, for the comments.
    * `:date` - the date for the comments. Default: today.
  """
  @spec migrate(String.t(), String.t() | nil, keyword()) :: result()
  def migrate(main_cf, master_cf, opts \\ []) do
    main = MainCf.parse(main_cf, Keyword.get(opts, :defaults, %{}))

    state = %State{
      main: main,
      services: if(master_cf, do: MasterCf.parse(master_cf), else: []),
      read: Keyword.get(opts, :read, &File.read/1),
      queue_directory: MainCf.value(main, "queue_directory"),
      origin: nil
    }

    state =
      state
      |> Domains.server()
      |> Domains.domains()
      |> Domains.networks()
      |> Security.tls()
      |> Security.auth()
      |> Security.client_tls()
      |> Checks.screen()
      |> listeners(master_cf != nil)
      |> Settings.milters()
      |> Settings.filters()
      |> Settings.policy()
      |> Checks.restrictions()
      |> Security.relayhost()
      |> Settings.routing()
      |> Settings.delivery()
      |> Settings.scalars()
      |> Imports.migrate()
      |> Settings.leftover()
      |> sendmail_listener()

    source = Keyword.get(opts, :source, "main.cf")
    date = opts |> Keyword.get(:date, Date.utc_today()) |> Date.to_iso8601()
    config = render_config(state, source, date)
    errors = validate(config)

    state =
      Enum.reduce(errors, state, fn error, state ->
        State.report(
          state,
          :attention,
          "sovite.toml",
          nil,
          "Does not pass sovitectl config check: #{error}. Fix it by hand."
        )
      end)

    entries = Enum.reverse(state.report)

    %{
      config: config,
      script: render_script(state.commands, source, date),
      report: render_report(entries, source, date),
      entries: entries,
      commands: Enum.reject(state.commands, &match?({:comment, _}, &1)),
      errors: errors
    }
  end

  defp listeners(state, false) do
    State.report(
      state,
      :attention,
      "master.cf",
      nil,
      "There is no master.cf, so no listeners were migrated: Sovite listens on 0.0.0.0:25 by default. Add [[listener]] tables for the other ports."
    )
  end

  defp listeners(state, true) do
    state = Services.listeners(state)

    if State.tables(state, "listener") == [],
      do:
        state
        |> State.flag(:no_listeners, true)
        |> State.report(
          :migrated,
          "master.cf",
          nil,
          "No service receives mail over the network: listener = [] (local programs still need a listener for sendmail; see [sendmail])."
        ),
      else: state
  end

  # Sovite's sendmail submits to sendmail.server, [127.0.0.1]:25 by
  # default: there should be a listener for it.
  defp sendmail_listener(state) do
    tables = State.tables(state, "listener")

    # Without master.cf, Sovite's default listener is 0.0.0.0:25.
    reachable =
      (tables == [] and State.flag(state, :no_listeners) != true) or
        Enum.any?(tables, fn {entries, _comment} ->
          {"address", address, _} = List.keyfind(entries, "address", 0)
          {"port", port, _} = List.keyfind(entries, "port", 0)
          address in ["0.0.0.0", "127.0.0.1"] and port == 25
        end)

    if reachable,
      do: state,
      else:
        State.report(
          state,
          :attention,
          "sendmail",
          nil,
          "No listener on 127.0.0.1 port 25, where Sovite's sendmail submits mail: set sendmail.server to a listener local programs may use (its clients must be in smtp.trusted_networks)."
        )
  end

  defp validate(config) do
    case Config.parse(config) do
      {:ok, _config} -> []
      {:error, errors} -> Enum.map(errors, &Exception.message/1)
    end
  end

  ## sovite.toml

  defp render_config(state, source, date) do
    header =
      {:comment,
       "Sovite configuration, generated by sovitectl migrate postfix from #{source} on #{date}. Read report.txt: the values marked \"check:\" below are among the things that need a look. Check the file with: sovitectl config check sovite.toml"}

    known =
      for {_kind, name} <- Enum.filter(@layout, &is_tuple/1), into: MapSet.new(), do: name

    extra =
      for section <- Map.keys(state.config),
          not MapSet.member?(known, section),
          not String.starts_with?(section, "pipe."),
          do: {:table, section}

    parts = Enum.flat_map(@layout ++ Enum.sort(extra), &layout_part(state, &1))

    root =
      if State.flag(state, :no_listeners),
        do: [{:entries, [{"listener", [], nil}]}],
        else: []

    TomlWriter.render([header | root] ++ parts)
  end

  defp layout_part(state, {:table, name}), do: [{:table, name, Map.get(state.config, name, [])}]

  defp layout_part(state, {:array, name}) do
    for {entries, comment} <- State.tables(state, name),
        do: {:array_table, name, entries, comment}
  end

  defp layout_part(state, :pipes) do
    for {"pipe." <> _ = name, entries} <- Enum.sort(state.config), do: {:table, name, entries}
  end

  ## import.sh

  defp render_script(commands, source, date) do
    body =
      case commands do
        [] -> ["# Nothing to import: main.cf names no lookup tables Sovite keeps."]
        commands -> Enum.map(commands, &script_line/1)
      end

    Enum.join(
      [
        "#!/bin/sh",
        "# Loads the lookup tables of the Postfix configuration in #{source} into",
        "# Sovite's database. Generated by sovitectl migrate postfix on #{date}.",
        "#",
        "# Run it once, after installing sovite.toml, as a user that may use the",
        "# database (such as the Sovite user): sh import.sh",
        "# Set SOVITECTL to sovitectl's path if it is not in PATH, and SOVITE_CONFIG",
        "# if the config is not /etc/sovite/sovite.toml. It can contain passwords:",
        "# keep it private, and delete it when you are done.",
        "",
        "sovitectl=${SOVITECTL:-sovitectl}",
        "status=0"
      ] ++ body ++ ["", ~s(exit "$status")],
      "\n"
    ) <> "\n"
  end

  defp script_line({:comment, heading}), do: "\n# " <> String.replace(heading, ~r/[\r\n]+/, " ")

  defp script_line({:stdin, password, args}),
    do: "printf '%s\\n' #{Convert.shell_quote(password)} | " <> command(args)

  defp script_line(args) when is_list(args), do: command(args)

  defp command(args),
    do: ~s("$sovitectl" ) <> Enum.map_join(args, " ", &Convert.shell_quote/1) <> " || status=1"

  ## report.txt

  @levels [
    {:attention, "Needs attention",
     "Settings Sovite has no equivalent for, and steps to take by hand."},
    {:migrated, "Migrated", "Settings that are now in sovite.toml or import.sh."},
    {:ignored, "Ignored",
     "Settings Sovite does not need: it does the same anyway, or they do not apply."}
  ]

  defp render_report(entries, source, date) do
    sections =
      for {level, title, intro} <- @levels do
        items = Enum.filter(entries, &(&1.level == level))
        heading = "#{title} (#{length(items)})"

        [heading, String.duplicate("-", String.length(heading)), intro, ""] ++
          Enum.flat_map(items, &report_item/1)
      end

    lines =
      [
        "Postfix migration report",
        "========================",
        "",
        "From #{source}, on #{date}: sovite.toml is the configuration, import.sh",
        "loads the lookup tables into the database, and this file says what",
        "changed.",
        ""
      ] ++
        Enum.concat(sections) ++
        [
          "Next steps",
          "----------",
          "1. Go through \"Needs attention\" above, and the \"check:\" comments in",
          "   sovite.toml.",
          "2. Run sovitectl config check sovite.toml, then install the file as",
          "   /etc/sovite/sovite.toml, readable by root and the Sovite user only.",
          "3. Run sh import.sh to load the lookup tables, then delete it.",
          "4. Stop Postfix, start Sovite, and send a test message each way.",
          ""
        ]

    Enum.join(lines, "\n")
  end

  defp report_item(entry) do
    title =
      if entry.value in [nil, ""], do: entry.setting, else: "#{entry.setting} = #{entry.value}"

    message =
      entry.message
      |> String.replace(~r/[\r\n]+/, " ")
      |> TomlWriter.wrap(70)
      |> Enum.map(&("    " <> &1))

    ["  * " <> String.replace(title, ~r/[\r\n]+/, " ") | message] ++ [""]
  end
end
