defmodule Sovite.Core.Postfix.Domains do
  @moduledoc false
  # main.cf: the host name and origin -> [server] and [sendmail], the
  # domain classes -> [domains] (lists) and import.sh (tables), and
  # mynetworks -> smtp.trusted_networks.

  alias Sovite.Core.Postfix.{Convert, Imports, State, Table}
  alias Sovite.Validators

  ## Host name and origin

  @doc "myhostname -> server.hostname, myorigin -> sendmail.origin."
  def server(state) do
    state
    |> hostname()
    |> origin()
    |> State.handle("mydomain")
  end

  defp hostname(state) do
    hostname = state |> State.value("myhostname") |> String.downcase()
    explicit = State.set?(state, "myhostname")

    cond do
      not Validators.hostname?(hostname) or not String.contains?(hostname, ".") ->
        State.report_param(
          state,
          :attention,
          "myhostname",
          "#{inspect(hostname)} is not a fully qualified host name. Set server.hostname by hand."
        )

      explicit ->
        state
        |> State.put("server", "hostname", hostname)
        |> State.report_param(:migrated, "myhostname", "server.hostname")

      true ->
        state
        |> State.put("server", "hostname", hostname, "the system's host name, as Postfix used it")
        |> State.report(
          :migrated,
          "myhostname",
          hostname,
          "server.hostname (main.cf does not set it: this is the system's host name)."
        )
    end
  end

  # myorigin can name a file, such as Debian's /etc/mailname.
  defp origin(state) do
    value = State.value(state, "myorigin")
    hostname = State.value(state, "myhostname") |> String.downcase()

    {origin, from} =
      if String.starts_with?(value, "/"),
        do: {read_name(state, value), " (from #{value})"},
        else: {value, ""}

    origin = origin && String.downcase(origin)

    cond do
      origin == nil or not Validators.domain?(origin) ->
        State.report_param(
          state,
          :attention,
          "myorigin",
          "#{inspect(origin || value)} is not a domain#{from}. Set sendmail.origin by hand."
        )

      origin == hostname ->
        state = %{state | origin: origin}

        if State.set?(state, "myorigin"),
          do:
            State.report_param(
              state,
              :ignored,
              "myorigin",
              "The same as server.hostname, Sovite's default for sendmail.origin."
            ),
          else: state

      true ->
        %{state | origin: origin}
        |> State.put("sendmail", "origin", origin)
        |> State.report_param(
          :migrated,
          "myorigin",
          "sendmail.origin = #{inspect(origin)}#{from}. Sovite only adds it to addresses without a domain that local programs send with sendmail; import.sh also uses it for aliases."
        )
    end
  end

  defp read_name(state, path) do
    case state.read.(path) do
      {:ok, contents} ->
        contents |> String.split(~r/\s+/, trim: true) |> List.first()

      {:error, _} ->
        nil
    end
  end

  ## Domains

  # Postfix's domain classes and Sovite's, in the order a domain that is
  # in more than one class keeps the first.
  @classes [
    {"mydestination", "local"},
    {"virtual_mailbox_domains", "hosted"},
    {"virtual_alias_domains", "aliased"},
    {"relay_domains", "relay"}
  ]

  @doc """
  The domain classes -> [domains], and `domain add` commands for the
  domains kept in tables.
  """
  def domains(state) do
    {state, _seen} =
      Enum.reduce(@classes, {state, %{}}, fn {name, kind}, {state, seen} ->
        domain_class(state, name, kind, seen)
      end)

    state
  end

  defp domain_class(state, name, kind, seen) do
    explicit = State.set?(state, name)
    items = State.list(state, name)
    state = State.handle(state, name)

    {names, tables, problems, state} =
      Enum.reduce(items, {[], [], [], state}, fn item, acc -> domain_item(item, acc) end)

    {names, dropped, seen} = unique(Enum.reverse(names), kind, seen)
    {tables, table_dropped, seen} = unique(Enum.reverse(tables), kind, seen)
    problems = Enum.reverse(problems) ++ dropped ++ table_dropped

    # An empty mydestination means no local domains, unlike Sovite's
    # default of server.hostname.
    listed = names != [] or (explicit and kind == "local")
    state = if listed, do: State.put(state, "domains", kind, names), else: state

    state =
      State.commands(
        state,
        "#{name}: domains in tables",
        Enum.map(tables, &["domain", "add", &1, kind])
      )

    {report_class(state, name, kind, listed, tables, problems), seen}
  end

  defp domain_item(item, {names, tables, problems, state}) do
    case domains_of(item, state) do
      {:names, found} -> {Enum.reverse(found) ++ names, tables, problems, state}
      {:tables, found} -> {names, Enum.reverse(found) ++ tables, problems, state}
      {:error, message} -> {names, tables, [message | problems], state}
    end
  end

  # A file of names, a table (whose domain keys count), or a domain.
  defp domains_of("/" <> _ = item, state) do
    case state.read.(item) do
      {:ok, contents} ->
        found = contents |> String.split(~r/[\s,]+/, trim: true) |> Enum.reject(&comment?/1)
        {:tables, Enum.map(found, &String.downcase/1)}

      {:error, reason} ->
        {:error, "#{item}: #{Table.describe_error({:unreadable, item, reason})}"}
    end
  end

  defp domains_of(item, state) do
    cond do
      String.contains?(item, ":") -> table_domains(item, state)
      Convert.domain?(item) -> {:names, [String.downcase(item)]}
      true -> {:error, "#{item} is not a domain"}
    end
  end

  defp table_domains(item, state) do
    case Table.read(item, state.read) do
      {:ok, entries} ->
        {:tables, for({key, value} <- entries, Imports.domain_declaration?(key, value), do: key)}

      {:error, {:unreadable, _path, :enoent}} ->
        {:tables, []}

      {:error, reason} ->
        {:error, "#{item}: #{Table.describe_error(reason)}"}
    end
  end

  defp comment?(word), do: String.starts_with?(word, "#")

  # A domain can only be in one Sovite class.
  defp unique(domains, kind, seen) do
    Enum.reduce(domains, {[], [], seen}, fn domain, {kept, dropped, seen} ->
      case Map.fetch(seen, domain) do
        {:ok, ^kind} ->
          {kept, dropped, seen}

        {:ok, other} ->
          {kept, ["#{domain} is already a #{other} domain" | dropped], seen}

        :error ->
          {[domain | kept], dropped, Map.put(seen, domain, kind)}
      end
    end)
    |> then(fn {kept, dropped, seen} -> {Enum.reverse(kept), Enum.reverse(dropped), seen} end)
  end

  defp report_class(state, name, kind, listed, tables, problems) do
    parts =
      [
        listed && "domains.#{kind}",
        tables != [] &&
          "#{length(tables)} domains from tables in import.sh (domain add ... #{kind})"
      ]
      |> Enum.filter(&is_binary/1)

    cond do
      parts == [] and problems == [] ->
        state

      problems == [] ->
        State.report(
          state,
          :migrated,
          name,
          State.explicit(state, name),
          Enum.join(parts, "; ") <> "."
        )

      true ->
        State.report(
          state,
          :attention,
          name,
          State.explicit(state, name),
          Enum.join(parts ++ ["Not migrated: " <> Enum.join(problems, "; ")], ". ") <> "."
        )
    end
  end

  ## Trusted networks

  @loopback ["127.0.0.0/8", "::1/128"]

  @doc "mynetworks (or mynetworks_style) -> smtp.trusted_networks."
  def networks(state) do
    state = State.handle(state, ["mynetworks", "mynetworks_style"])

    if State.set?(state, "mynetworks") do
      {networks, problems} = Convert.networks(State.list(state, "mynetworks"))

      state
      |> State.put("smtp", "trusted_networks", networks)
      |> State.report_param(
        State.level(problems),
        "mynetworks",
        "smtp.trusted_networks." <> State.not_migrated(problems)
      )
    else
      style(state, State.value(state, "mynetworks_style"))
    end
  end

  defp style(state, "host") do
    state
    |> State.put("smtp", "trusted_networks", @loopback)
    |> State.report(
      :migrated,
      "mynetworks_style",
      "host",
      "smtp.trusted_networks = the loopback networks. Postfix also trusted the other addresses of this host: add them if programs send mail from them."
    )
  end

  defp style(state, style) do
    state
    |> State.put(
      "smtp",
      "trusted_networks",
      @loopback,
      "Postfix trusted the #{style} networks of this host's interfaces: list them here"
    )
    |> State.report(
      :attention,
      "mynetworks_style",
      style,
      "Postfix trusted every client in the #{style} networks of this host's interfaces. Sovite needs them listed: smtp.trusted_networks has only the loopback networks."
    )
  end
end
