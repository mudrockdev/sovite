defmodule Sovite.Rules.Compiler do
  @moduledoc false
  # Rule files (decoded TOML) into a Sovite.Rules rule set. See
  # Sovite.Rules for the format.

  alias Sovite.Rules.{Expression, Maps, Pattern, Targets}

  @kinds ~w(group map symbol composite)
  @policies %{"remove" => :remove, "remove_weight" => :remove_weight, "leave" => :leave}

  @keys %{
    "group" => ~w(name description max_score min_score),
    "map" => ~w(name description type file entries),
    "symbol" => ~w(name description group score enabled match regex flags map condition),
    "composite" => ~w(name description group score enabled expression policy)
  }

  @type error :: {[String.t()], String.t()}

  # The fields of the Sovite.Rules struct, or the errors.
  @spec compile([{String.t(), map()}], keyword()) :: {:ok, map()} | {:error, [error()]}
  def compile(files, opts) do
    {entries, errors} = collect(files)
    {merged, merge_errors} = merge(entries)
    {compiled, entry_errors} = entries(merged)

    errors = errors ++ merge_errors ++ entry_errors

    errors =
      if errors == [], do: references(compiled, Keyword.get(opts, :flags)), else: errors

    if errors == [], do: {:ok, build(compiled)}, else: {:error, errors}
  end

  # Every entry of every file, with where it is: {kind, name, raw, path}.
  defp collect(files) do
    {entries, errors} =
      Enum.reduce(files, {[], []}, fn {source, map}, {entries, errors} ->
        {file_entries, file_errors} = file(source, map)
        {entries ++ file_entries, errors ++ file_errors}
      end)

    {entries, errors}
  end

  defp file(source, map) do
    unknown =
      for key <- Map.keys(map),
          key not in @kinds,
          do: {[source, key], "unknown key (expected #{Enum.join(@kinds, ", ")})"}

    {entries, errors} =
      for kind <- @kinds, Map.has_key?(map, kind), reduce: {[], unknown} do
        {entries, errors} ->
          case map[kind] do
            list when is_list(list) ->
              {kind_entries, kind_errors} = kind_entries(source, kind, list)
              {entries ++ kind_entries, errors ++ kind_errors}

            _ ->
              {entries, errors ++ [{[source, kind], "must be an array of tables ([[#{kind}]])"}]}
          end
      end

    {Enum.uniq_by(entries, &key/1), errors ++ duplicates(entries)}
  end

  defp key({kind, name, _raw, _path}), do: {namespace(kind), name}

  defp kind_entries(source, kind, list) do
    list
    |> Enum.with_index()
    |> Enum.reduce({[], []}, fn {raw, index}, {entries, errors} ->
      case named(kind, raw, [source, kind, "[#{index}]"]) do
        {:ok, entry} -> {entries ++ [entry], errors}
        {:error, error} -> {entries, errors ++ [error]}
      end
    end)
  end

  defp named(kind, %{"name" => name} = raw, path) when is_binary(name) do
    if name =~ ~r/\A[A-Za-z0-9_]{1,128}\z/,
      do: {:ok, {kind, name, raw, path}},
      else: {:error, {path ++ ["name"], "must be letters, digits, and _"}}
  end

  defp named(_kind, %{}, path), do: {:error, {path ++ ["name"], "is required"}}
  defp named(_kind, _raw, path), do: {:error, {path, "must be a table"}}

  defp duplicates(entries) do
    entries
    |> Enum.group_by(&key/1)
    |> Enum.flat_map(fn {_key, [_ | rest]} ->
      for {_kind, name, _raw, path} <- rest, do: {path ++ ["name"], "#{name} is already defined"}
    end)
  end

  # Symbols and composites share their names.
  defp namespace(kind) when kind in ["symbol", "composite"], do: "symbol"
  defp namespace(kind), do: kind

  # A later file's entry with the same name changes the keys it sets, so
  # local files adjust the default rules.
  defp merge(entries) do
    {order, merged, errors} =
      Enum.reduce(entries, {[], %{}, []}, fn {kind, name, raw, path} = entry,
                                             {order, merged, errors} ->
        key = key(entry)

        case merged do
          %{^key => {^kind, _name, old, _path}} ->
            {order, Map.put(merged, key, {kind, name, Map.merge(old, raw), path}), errors}

          %{^key => {other, _name, _old, _path}} ->
            {order, merged, errors ++ [{path ++ ["name"], "#{name} is already a #{other}"}]}

          %{} ->
            {[key | order], Map.put(merged, key, {kind, name, raw, path}), errors}
        end
      end)

    {order |> Enum.reverse() |> Enum.map(&merged[&1]), errors}
  end

  defp entries(merged) do
    Enum.reduce(merged, {[], []}, fn {kind, name, raw, path}, {compiled, errors} ->
      unknown =
        for key <- Map.keys(raw), key not in @keys[kind], do: {path ++ [key], "unknown key"}

      case entry(kind, name, raw) do
        {:ok, entry} when unknown == [] -> {compiled ++ [{kind, entry, path}], errors}
        {:ok, _entry} -> {compiled, errors ++ unknown}
        {:error, entry_errors} -> {compiled, errors ++ unknown ++ prefix(entry_errors, path)}
      end
    end)
  end

  defp prefix(errors, path), do: for({key, reason} <- errors, do: {path ++ key, reason})

  defp entry("group", name, raw) do
    with_fields(raw, [description: :string, max_score: :number, min_score: :number], fn f ->
      %{name: name, description: f.description, max_score: f.max_score, min_score: f.min_score}
    end)
  end

  defp entry("map", name, raw) do
    fields = [description: :string, type: :map_type, file: :string, entries: :strings]

    with {:ok, f} <- fields(raw, fields),
         :ok <- map_source(f) do
      {map, errors} = if f.entries, do: Maps.new(f.type, f.entries), else: {nil, []}

      case errors do
        [] ->
          {:ok, %{name: name, description: f.description, type: f.type, file: f.file, map: map}}

        errors ->
          {:error, for({index, reason} <- errors, do: {["entries", "[#{index - 1}]"], reason})}
      end
    end
  end

  defp entry("symbol", name, raw) do
    fields = [
      description: :string,
      group: :name,
      score: {:number, 0.0},
      enabled: {:boolean, true},
      match: :target,
      regex: :string,
      flags: {:string, ""},
      map: :name,
      condition: :expression
    ]

    with {:ok, f} <- fields(raw, fields),
         {:ok, matcher} <- matcher(f) do
      {:ok,
       %{
         name: name,
         description: f.description,
         group: f.group,
         score: f.score,
         enabled: f.enabled,
         target: f.match,
         matcher: matcher,
         condition: f.condition
       }}
    end
  end

  defp entry("composite", name, raw) do
    fields = [
      description: :string,
      group: :name,
      score: {:number, 0.0},
      enabled: {:boolean, true},
      expression: :expression,
      policy: {:policy, :remove}
    ]

    with {:ok, f} <- fields(raw, fields),
         :ok <- if(f.expression, do: :ok, else: {:error, [{["expression"], "is required"}]}) do
      {:ok,
       %{
         name: name,
         description: f.description,
         group: f.group,
         score: f.score,
         enabled: f.enabled,
         expression: f.expression,
         policy: f.policy
       }}
    end
  end

  defp map_source(%{type: nil}), do: {:error, [{["type"], "is required (#{types()})"}]}

  defp map_source(%{file: nil, entries: nil}),
    do: {:error, [{["file"], "or entries is required"}]}

  defp map_source(%{file: file, entries: entries}) when file != nil and entries != nil,
    do: {:error, [{["entries"], "cannot be given with file"}]}

  defp map_source(%{file: file}) when is_binary(file) do
    if Path.type(file) == :absolute,
      do: :ok,
      else: {:error, [{["file"], "must be an absolute path"}]}
  end

  defp map_source(_fields), do: :ok

  defp types, do: Enum.join(Enum.sort(Maps.types()), ", ")

  defp matcher(%{match: nil, regex: nil, map: nil}), do: {:ok, nil}

  defp matcher(%{match: nil}),
    do:
      {:error,
       [
         {["match"],
          "is required with regex or map (#{Enum.join(Enum.sort(Targets.names()), ", ")})"}
       ]}

  defp matcher(%{regex: nil, map: nil}), do: {:error, [{["match"], "needs regex or map"}]}

  defp matcher(%{regex: regex, map: map}) when regex != nil and map != nil,
    do: {:error, [{["map"], "cannot be given with regex"}]}

  defp matcher(%{map: map}) when map != nil, do: {:ok, {:map, map}}

  defp matcher(%{regex: regex, flags: flags}) do
    case Pattern.compile(regex, flags) do
      {:ok, pattern} -> {:ok, {:regex, pattern}}
      {:error, reason} -> {:error, [{["regex"], reason}]}
    end
  end

  # Fields.

  defp with_fields(raw, specs, build) do
    with {:ok, fields} <- fields(raw, specs), do: {:ok, build.(fields)}
  end

  defp fields(raw, specs) do
    {fields, errors} =
      Enum.reduce(specs, {%{}, []}, fn {key, spec}, {fields, errors} ->
        case field(raw, Atom.to_string(key), spec) do
          {:ok, value} -> {Map.put(fields, key, value), errors}
          {:error, error} -> {fields, errors ++ [error]}
        end
      end)

    if errors == [], do: {:ok, fields}, else: {:error, errors}
  end

  defp field(raw, key, spec) do
    {type, default} = if is_tuple(spec), do: spec, else: {spec, nil}

    with {:ok, value} <- Map.fetch(raw, key),
         {:error, reason} <- value(type, value) do
      {:error, {[key], reason}}
    else
      :error -> {:ok, default}
      {:ok, value} -> {:ok, value}
    end
  end

  defp value(:string, value) when is_binary(value), do: {:ok, value}
  defp value(:string, _value), do: {:error, "must be a string"}
  defp value(:number, value) when is_number(value), do: {:ok, value / 1}
  defp value(:number, _value), do: {:error, "must be a number"}
  defp value(:boolean, value) when is_boolean(value), do: {:ok, value}
  defp value(:boolean, _value), do: {:error, "must be true or false"}

  defp value(:name, value) when is_binary(value) do
    if value =~ ~r/\A[A-Za-z0-9_]{1,128}\z/,
      do: {:ok, value},
      else: {:error, "must be letters, digits, and _"}
  end

  defp value(:name, _value), do: {:error, "must be a string"}

  defp value(:strings, value) when is_list(value) do
    if Enum.all?(value, &is_binary/1), do: {:ok, value}, else: {:error, "must be strings"}
  end

  defp value(:strings, _value), do: {:error, "must be an array of strings"}

  defp value(:map_type, value) when is_binary(value) do
    case Maps.type(value) do
      {:ok, type} -> {:ok, type}
      :error -> {:error, "must be one of #{types()}"}
    end
  end

  defp value(:target, value) when is_binary(value) do
    case Targets.parse(value) do
      {:ok, target} -> {:ok, target}
      :error -> {:error, "must be one of #{Enum.join(Enum.sort(Targets.names()), ", ")}"}
    end
  end

  defp value(:expression, value) when is_binary(value) do
    case Expression.parse(value) do
      {:ok, expression} -> {:ok, expression}
      {:error, reason} -> {:error, "invalid expression: #{reason}"}
    end
  end

  defp value(:policy, value) when is_binary(value) do
    case Map.fetch(@policies, value) do
      {:ok, policy} -> {:ok, policy}
      :error -> {:error, "must be one of #{Enum.join(Map.keys(@policies), ", ")}"}
    end
  end

  defp value(type, _value) when type in [:map_type, :target, :expression, :policy],
    do: {:error, "must be a string"}

  # References between entries: maps, groups, symbols, flags, and
  # composites that would depend on themselves.
  defp references(compiled, flags) do
    maps = for {"map", map, _path} <- compiled, into: %{}, do: {map.name, map}

    groups =
      MapSet.new(
        for(
          {kind, entry, _} <- compiled,
          kind in ["symbol", "composite"],
          entry.group,
          do: entry.group
        ) ++
          for({"group", group, _} <- compiled, do: group.name)
      )

    symbols =
      MapSet.new(
        for {kind, entry, _} <- compiled, kind in ["symbol", "composite"], do: entry.name
      )

    known = %{groups: groups, symbols: symbols, flags: flags && MapSet.new(flags)}

    Enum.flat_map(compiled, fn
      {"symbol", %{matcher: {:map, name}}, path} when not is_map_key(maps, name) ->
        [{path ++ ["map"], "no map is named #{name}"}]

      {"symbol", symbol, path} ->
        expression_errors(symbol.condition, known, path ++ ["condition"])

      {"composite", composite, path} ->
        expression_errors(composite.expression, known, path ++ ["expression"])

      _ ->
        []
    end) ++ cycles(compiled)
  end

  defp expression_errors(nil, _known, _path), do: []

  defp expression_errors(expression, known, path) do
    expression
    |> Expression.refs()
    |> Enum.uniq()
    |> Enum.flat_map(fn
      {:symbol, name} ->
        if MapSet.member?(known.symbols, name),
          do: [],
          else: [{path, "no symbol is named #{name}"}]

      {kind, name} when kind in [:group, :group_positive] ->
        if MapSet.member?(known.groups, name), do: [], else: [{path, "no group is named #{name}"}]

      {:flag, name} ->
        if known.flags == nil or MapSet.member?(known.flags, name),
          do: [],
          else: [{path, "unknown flag #{name} (#{Enum.join(Enum.sort(known.flags), ", ")})"}]
    end)
  end

  defp cycles(compiled) do
    composites =
      for {"composite", composite, path} <- compiled,
          into: %{},
          do: {composite.name, {composite, path}}

    case order(composites) do
      {:ok, _order} ->
        []

      {:cycle, name} ->
        [{elem(composites[name], 1) ++ ["expression"], "#{name} depends on itself"}]
    end
  end

  # Composites, those they name first. `done` and `path` (the composites
  # being visited) are maps of names.
  defp order(composites) do
    case visit_all(Enum.sort(Map.keys(composites)), composites, {[], %{}}, %{}) do
      {:ok, {order, _done}} -> {:ok, Enum.reverse(order)}
      cycle -> cycle
    end
  end

  defp visit_all([], _composites, acc, _path), do: {:ok, acc}

  defp visit_all([name | names], composites, acc, path) do
    with {:ok, acc} <- visit(name, composites, acc, path),
         do: visit_all(names, composites, acc, path)
  end

  defp visit(name, composites, {_order, done} = acc, path) do
    cond do
      Map.has_key?(done, name) or not Map.has_key?(composites, name) ->
        {:ok, acc}

      Map.has_key?(path, name) ->
        {:cycle, name}

      true ->
        {composite, _path} = composites[name]
        names = for {:symbol, ref} <- Expression.refs(composite.expression), do: ref

        with {:ok, {order, done}} <- visit_all(names, composites, acc, Map.put(path, name, true)),
             do: {:ok, {[name | order], Map.put(done, name, true)}}
    end
  end

  defp build(compiled) do
    groups =
      for {"group", group, _} <- compiled, into: %{}, do: {group.name, Map.delete(group, :name)}

    symbols = for {"symbol", symbol, _} <- compiled, symbol.enabled, do: symbol

    composites =
      for {"composite", composite, _} <- compiled,
          composite.enabled,
          into: %{},
          do: {composite.name, {composite, nil}}

    {:ok, order} = order(composites)

    %{
      symbols: symbols,
      composites: Enum.map(order, &elem(composites[&1], 0)),
      groups: groups,
      maps: for({"map", map, _} <- compiled, into: %{}, do: {map.name, Map.delete(map, :name)}),
      declared:
        for(
          {kind, entry, _} <- compiled,
          kind in ["symbol", "composite"],
          into: %{},
          do: {entry.name, entry}
        )
    }
  end
end
