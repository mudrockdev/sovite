defmodule Sovite.Rules do
  @moduledoc """
  A rule engine for mail filtering, in the manner of Rspamd: rules find
  *symbols* in a message, each with a score, and the scores add up to the
  message's score, which decides what is done with it.

      {:ok, rules} = Sovite.Rules.compile([{"local.toml", Toml.decode!(text)}])
      result = Sovite.Rules.scan(rules, Sovite.Analyzer.analyze(message), raw: message)
      result.score
      for symbol <- result.symbols, do: {symbol.name, symbol.score}

  ## Rule files

  Rule files are TOML, with four kinds of entries, each with a `name`
  (letters, digits, and `_`) and an optional `description`:

      [[group]]
      name = "headers"
      max_score = 6.0           # the group adds at most this much
      min_score = -6.0          # and takes away at most this much

      [[map]]
      name = "bad_domains"
      type = "domain"           # ip, domain, address, or string (Sovite.Rules.Maps)
      entries = ["spam.example"]
      # or file = "/etc/sovite/maps/bad_domains.txt", which the caller loads

      [[symbol]]
      name = "SUBJECT_CAPS"
      group = "headers"
      score = 2.5
      match = "subject"
      regex = '\\A[^a-z]{12,}\\z'
      flags = ""                # i, m, s, x (Sovite.Rules.Pattern)
      condition = "!is:authenticated"

      [[symbol]]
      name = "URL_BAD_DOMAIN"
      score = 6.0
      match = "url_host"
      map = "bad_domains"

      [[symbol]]
      name = "R_SPF_FAIL"       # found by code, not a rule: given its score here
      score = 3.0

      [[composite]]
      name = "SPF_FAIL_CAPS"
      expression = "R_SPF_FAIL & SUBJECT_CAPS"   # Sovite.Rules.Expression
      score = 4.0
      policy = "remove"         # remove, remove_weight, or leave

  A symbol with `regex` matches when the pattern matches one of the
  values of `match`; with `map`, when one of them is in the map. A symbol
  without either is found by code (an SPF check, ...), and `scan/3` is
  told about it with `:symbols`. `condition` is an expression that must
  hold for the rule to run, over the flags of the message and the symbols
  found before it: those given to `scan/3`, then rules in order.

  `match` is one of:

    * `header:<Name>`, `raw_header:<Name>` - the values of the message's
      fields named so, with encoded words decoded or not;
      `mime_header:<Name>` the same in every MIME part; `headers` the
      whole header section; `subject` the subject.
    * `text`, `hidden_text` - the text of each text part (HTML made text),
      and what HTML hides; `html` the source of HTML parts; `body` the
      message's body, undecoded (when `scan/3` is given `:raw`).
    * `url`, `url_host` - URLs in the text, normalized, and their hosts;
      `address` mail addresses in the text.
    * `attachment_name`, `attachment_type` (by content when known),
      `attachment_hash` (SHA-256, lower-case hex).
    * `ip`, `hostname`, `helo`, `from`, `from_domain`, `rcpt`,
      `rcpt_domain`, `user` - the SMTP envelope (`:envelope` of `scan/3`).

  A composite matches when its expression holds over the symbols found.
  With `policy = "remove"` (the default) the symbols it names outside a
  negation are taken out, so their scores do not count twice;
  `remove_weight` keeps them listed with no score.

  Entries are merged by name across files: a later file's entry changes
  only the keys it sets, so local files can adjust or disable
  (`enabled = false`) the default rules.

  ## Telemetry

    * `[:sovite, :rules, :scan]` - `%{duration, score}` (native time
      units), `%{symbols, anomalies}`.
  """

  alias Sovite.Analyzer
  alias Sovite.Rules.{Compiler, Expression, Maps, Pattern, Targets}

  defstruct symbols: [], composites: [], groups: %{}, maps: %{}, declared: %{}

  @opaque t :: %__MODULE__{
            symbols: [map()],
            composites: [map()],
            groups: %{String.t() => map()},
            maps: %{String.t() => map()},
            declared: %{String.t() => map()}
          }

  @typedoc "A symbol found in a message: its score, group, and what it matched."
  @type hit :: %{
          name: String.t(),
          score: float(),
          group: String.t() | nil,
          description: String.t() | nil,
          options: [String.t()]
        }

  @typedoc """
  Something that cut a scan short: `:time_limit` (rules after it did not
  run), or `{:match_limit, symbol}` (its pattern needed too much work, and
  counted as not matching).
  """
  @type anomaly :: :time_limit | {:match_limit, String.t()}

  @type result :: %{score: float(), symbols: [hit()], anomalies: [anomaly()]}

  @typedoc """
  Where an entry with an error is (the file and keys, as
  `["local.toml", "symbol", "[2]", "regex"]`), and what is wrong.
  """
  @type error :: {[String.t()], String.t()}

  @max_options 3
  @max_option 100

  @doc """
  Compiles rule files, each `{name, decoded TOML}`, in order. With
  `:flags`, the flags expressions may use (`is:...`); others are errors.
  """
  @spec compile([{String.t(), map()}], keyword()) :: {:ok, t()} | {:error, [error()]}
  def compile(files, opts \\ []) do
    with {:ok, fields} <- Compiler.compile(files, opts), do: {:ok, struct!(__MODULE__, fields)}
  end

  @doc """
  The maps a rule set reads from files: `%{name => {type, path}}`. Load
  them with `Sovite.Rules.Maps.parse/2` and give them to `scan/3`.
  """
  @spec file_maps(t()) :: %{String.t() => {Maps.type(), Path.t()}}
  def file_maps(%__MODULE__{maps: maps}),
    do: for({name, %{file: file, type: type}} <- maps, file, into: %{}, do: {name, {type, file}})

  @doc "The symbols and composites of a rule set, with their scores and groups."
  @spec symbols(t()) :: [%{name: String.t(), score: float(), group: String.t() | nil}]
  def symbols(%__MODULE__{declared: declared}) do
    for {name, entry} <- Enum.sort(declared),
        do: %{name: name, score: entry.score, group: entry.group, description: entry.description}
  end

  @doc """
  Scans an analyzed message.

  ## Options

    * `:raw` - the message as it came, for `match = "body"`.
    * `:envelope` - `%{ip, hostname, helo, from, rcpts, user}`, strings
      (and a list of them for `rcpts`), any of them missing.
    * `:symbols` - symbols found by code: names, `{name, options}`, or
      `{name, options, score}`, the score for a symbol the rules do not
      declare (otherwise 0).
    * `:flags` - the flags of the message, for `is:` in expressions.
    * `:maps` - the maps of `file_maps/1`, loaded: `%{name => map}`. Those
      missing are empty.
    * `:timeout` - how long the rules may take, in milliseconds. Defaults
      to 5,000; rules after it do not run (see `t:anomaly/0`).
    * `:max_value` - the most bytes of a value a pattern looks at.
      Defaults to 1 MiB.
  """
  @spec scan(t(), Analyzer.t(), keyword()) :: result()
  def scan(%__MODULE__{} = rules, %Analyzer{} = analysis, opts \\ []) do
    start = System.monotonic_time()
    timeout = Keyword.get(opts, :timeout, 5000)

    state = %{
      rules: rules,
      analysis: analysis,
      input: %{
        raw: Keyword.get(opts, :raw),
        envelope: Map.new(Keyword.get(opts, :envelope, %{})),
        max_value: Keyword.get(opts, :max_value, 1024 * 1024)
      },
      flags: MapSet.new(Keyword.get(opts, :flags, [])),
      maps: Keyword.get(opts, :maps, %{}),
      deadline: System.monotonic_time(:millisecond) + timeout,
      values: %{},
      hits: [],
      found: %{},
      anomalies: []
    }

    state =
      state
      |> external(Keyword.get(opts, :symbols, []))
      |> run_rules(rules.symbols)
      |> run_composites(rules.composites)

    hits = removed(state)
    score = score(hits, rules.groups)
    anomalies = Enum.reverse(state.anomalies)

    :telemetry.execute(
      [:sovite, :rules, :scan],
      %{duration: System.monotonic_time() - start, score: score},
      %{symbols: Enum.map(hits, & &1.name), anomalies: anomalies}
    )

    %{score: score, symbols: hits, anomalies: anomalies}
  end

  defp external(state, symbols) do
    Enum.reduce(symbols, state, fn symbol, state ->
      {name, options, score} = external_symbol(symbol)

      case state.rules.declared do
        %{^name => %{enabled: false}} -> state
        %{^name => entry} -> hit(state, entry, options)
        %{} -> hit(state, %{name: name, score: score, group: nil, description: nil}, options)
      end
    end)
  end

  defp external_symbol({name, options, score}), do: {name, options, score / 1}
  defp external_symbol({name, options}), do: {name, options, 0.0}
  defp external_symbol(name), do: {name, [], 0.0}

  defp run_rules(state, rules) do
    Enum.reduce_while(rules, state, fn
      %{matcher: nil}, state ->
        {:cont, state}

      rule, state ->
        if System.monotonic_time(:millisecond) > state.deadline,
          do: {:halt, %{state | anomalies: [:time_limit | state.anomalies]}},
          else: {:cont, run_rule(state, rule)}
    end)
  end

  defp run_rule(state, rule) do
    if rule.condition == nil or holds?(rule.condition, state) do
      {values, state} = values(state, rule.target)

      case matches(rule.matcher, values, state) do
        {[], limited?} -> limit(state, rule, limited?)
        {options, limited?} -> state |> hit(rule, options) |> limit(rule, limited?)
      end
    else
      state
    end
  end

  defp limit(state, _rule, false), do: state

  defp limit(state, rule, true),
    do: %{state | anomalies: [{:match_limit, rule.name} | state.anomalies]}

  defp values(state, target) do
    case state.values do
      %{^target => values} ->
        {values, state}

      %{} ->
        values = Targets.values(target, state.analysis, state.input)
        {values, put_in(state.values[target], values)}
    end
  end

  defp matches({:regex, pattern}, values, _state) do
    Enum.reduce_while(values, {[], false}, fn value, {options, limited?} ->
      case Pattern.run(pattern, value) do
        {:match, match} -> more([match | options], limited?)
        :nomatch -> {:cont, {options, limited?}}
        :limit -> {:cont, {options, true}}
      end
    end)
    |> then(fn {options, limited?} -> {Enum.reverse(options), limited?} end)
  end

  defp matches({:map, name}, values, state) do
    case map(state, name) do
      nil -> {[], false}
      map -> {values |> Enum.filter(&Maps.member?(map, &1)) |> Enum.take(@max_options), false}
    end
  end

  defp more(options, limited?) when length(options) >= @max_options,
    do: {:halt, {options, limited?}}

  defp more(options, limited?), do: {:cont, {options, limited?}}

  defp map(state, name) do
    case state.rules.maps[name] do
      %{map: map} when map != nil -> map
      %{} -> state.maps[name]
    end
  end

  defp run_composites(state, composites) do
    Enum.reduce(composites, state, fn composite, state ->
      if holds?(composite.expression, state), do: hit(state, composite, []), else: state
    end)
  end

  defp holds?(expression, state) do
    Expression.eval(expression, fn
      {:symbol, name} -> Map.has_key?(state.found, name)
      {:group, group} -> Enum.any?(state.hits, &(&1.group == group))
      {:group_positive, group} -> Enum.any?(state.hits, &(&1.group == group and &1.score > 0))
      {:flag, flag} -> MapSet.member?(state.flags, flag)
    end)
  end

  # A symbol is found once: the first time counts.
  defp hit(state, entry, options) do
    if Map.has_key?(state.found, entry.name) do
      state
    else
      hit = %{
        name: entry.name,
        score: entry.score,
        group: entry.group,
        description: entry.description,
        options: Enum.map(options, &String.slice(&1, 0, @max_option))
      }

      %{state | hits: [hit | state.hits], found: Map.put(state.found, entry.name, true)}
    end
  end

  # What matched composites take out.
  defp removed(state) do
    {remove, zero} =
      state.rules.composites
      |> Enum.filter(&Map.has_key?(state.found, &1.name))
      |> Enum.reduce({MapSet.new(), MapSet.new()}, fn composite, {remove, zero} ->
        names = Expression.positive_symbols(composite.expression)

        case composite.policy do
          :remove -> {MapSet.union(remove, MapSet.new(names)), zero}
          :remove_weight -> {remove, MapSet.union(zero, MapSet.new(names))}
          :leave -> {remove, zero}
        end
      end)

    state.hits
    |> Enum.reverse()
    |> Enum.reject(&MapSet.member?(remove, &1.name))
    |> Enum.map(&if(MapSet.member?(zero, &1.name), do: %{&1 | score: 0.0}, else: &1))
  end

  # The sum of the scores, each group's share within its limits.
  defp score(hits, groups) do
    hits
    |> Enum.group_by(& &1.group, & &1.score)
    |> Enum.map(fn {group, scores} -> group_score(scores, groups[group]) end)
    |> Enum.sum()
    |> Kernel.+(0.0)
    |> Float.round(2)
  end

  defp group_score(scores, nil), do: Enum.sum(scores)

  defp group_score(scores, group) do
    positive = scores |> Enum.filter(&(&1 > 0)) |> Enum.sum()
    negative = scores |> Enum.filter(&(&1 < 0)) |> Enum.sum()
    positive = if group.max_score, do: min(positive, group.max_score), else: positive
    negative = if group.min_score, do: max(negative, group.min_score), else: negative
    positive + negative
  end
end
