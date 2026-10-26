defmodule Sovite.RulesFuzzTest do
  # Fuzzing of the filter's rule engine: expressions, maps, and rule files
  # as an operator may write them, and scans of any message. None of it
  # may crash: a rule file is reported as wrong, a message is scored.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.{Analyzer, Rules}
  alias Sovite.Rules.{Expression, Maps}
  alias Sovite.Test.Fuzz

  @moduletag :fuzz
  # `mix fuzz` runs each property many times.
  @moduletag timeout: :infinity

  property "any expression is parsed or refused" do
    seeds = ["A & !(g:x | g+:y) | is:tls", "((A))", "!!A&B|C"]

    check all(
            text <- Fuzz.input(seeds, ["&", "|", "!", "(", ")", ":", "g:", "is:"]),
            max_runs: Fuzz.runs()
          ) do
      case Fuzz.quick(fn -> Expression.parse(text) end) do
        {:ok, expression} ->
          assert is_boolean(Expression.eval(expression, &match?({:symbol, _}, &1)))

        {:error, reason} ->
          assert is_binary(reason)
      end
    end
  end

  property "any map text is read, and any value looked up" do
    seed = "192.0.2.0/24\n2001:db8::/32 # x\nexample.com\n@example.org\na@b.example\nE3B0\n"

    check all(
            type <- member_of([:ip, :domain, :address, :string]),
            text <- Fuzz.input([seed], ["\n", "/", ".", "@", "#", ":", " "]),
            value <- Fuzz.input(["192.0.2.9", "x.example.com", "a@b.example"], [".", "@", ":"]),
            max_runs: Fuzz.runs()
          ) do
      {map, errors} = Fuzz.quick(fn -> Maps.parse(type, text) end)
      assert Enum.all?(errors, fn {line, reason} -> is_integer(line) and is_binary(reason) end)
      assert is_boolean(Maps.member?(map, String.replace_invalid(value)))
    end
  end

  property "any rule file is compiled or refused" do
    keys = ~w(name score group match regex flags map condition expression policy type entries file
              enabled description max_score)

    values =
      one_of([
        string(:printable, max_length: 20),
        member_of(["subject", "url_host", "header:From", "A & B", "(", "ip", "/x", "remove"]),
        float(min: -10.0, max: 10.0),
        boolean(),
        list_of(string(:alphanumeric, max_length: 8), max_length: 3)
      ])

    entry = optional_map(Map.new(keys, &{&1, values}))
    named = bind(entry, fn e -> map(member_of(~w(A B C g m)), &Map.put(e, "name", &1)) end)

    entries = list_of(one_of([named, entry]), max_length: 4)
    file = optional_map(Map.new(~w(symbol composite group map other), &{&1, entries}))

    check all(file <- file, max_runs: Fuzz.runs()) do
      case Fuzz.quick(fn -> Rules.compile([{"fuzz.toml", file}], flags: ["tls"]) end) do
        {:ok, rules} ->
          assert is_list(Rules.symbols(rules))

        {:error, errors} ->
          assert Enum.all?(errors, fn {path, reason} -> is_list(path) and is_binary(reason) end)
      end
    end
  end

  @rules """
  [[map]]
  name = "hosts"
  type = "domain"
  entries = ["example.com"]

  [[symbol]]
  name = "SUBJECT"
  score = 1.0
  match = "subject"
  regex = '(?i)\\A(free|cheap)'

  [[symbol]]
  name = "HOST"
  score = 2.0
  match = "url_host"
  map = "hosts"

  [[symbol]]
  name = "HEADERS"
  score = 0.5
  match = "raw_header:x-mailer"
  regex = "."
  condition = "!is:tls"

  [[composite]]
  name = "BOTH"
  expression = "SUBJECT & HOST"
  score = 3.0
  """

  property "any message is scored" do
    {:ok, rules} = Rules.compile([{"rules.toml", Toml.decode!(@rules)}])
    seed = "Subject: Free stuff\r\nX-Mailer: x\r\n\r\nhttp://www.example.com/a\r\n"

    check all(
            message <- Fuzz.input([seed], ["\r\n", ":", "http://", "=?", "?="]),
            max_runs: Fuzz.runs()
          ) do
      result = Fuzz.quick(fn -> Rules.scan(rules, Analyzer.analyze(message), raw: message) end)
      assert is_float(result.score)
      assert Enum.all?(result.symbols, &(&1.name in ~w(SUBJECT HOST HEADERS BOTH)))

      assert Enum.all?(result.symbols, fn symbol ->
               Enum.all?(symbol.options, &String.valid?/1)
             end)
    end
  end
end
