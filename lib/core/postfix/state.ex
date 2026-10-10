defmodule Sovite.Core.Postfix.State do
  @moduledoc false
  # What the migration has produced so far: config entries, arrays of
  # tables, import commands, and report lines, plus the Postfix input.

  alias Sovite.Core.Postfix.{MainCf, MasterCf}

  defstruct [
    :main,
    :services,
    :read,
    :queue_directory,
    :origin,
    config: %{},
    arrays: %{},
    commands: [],
    report: [],
    handled: MapSet.new(),
    flags: %{}
  ]

  @type level :: :attention | :migrated | :ignored

  @type t :: %__MODULE__{
          main: MainCf.t(),
          services: [MasterCf.service()],
          read: (String.t() -> {:ok, binary()} | {:error, term()}),
          queue_directory: String.t(),
          origin: String.t() | nil,
          config: %{String.t() => [{String.t(), term(), String.t() | nil}]},
          arrays: %{String.t() => [{list(), String.t() | nil}]},
          commands: list(),
          report: [map()],
          handled: MapSet.t(),
          flags: map()
        }

  @doc "The expanded value of a main.cf parameter."
  def value(state, name), do: MainCf.value(state.main, name)

  @doc "The expanded value of a main.cf parameter, split into a list."
  def list(state, name), do: MainCf.list(state.main, name)

  @doc "Whether main.cf sets the parameter."
  def set?(state, name), do: MainCf.set?(state.main, name)

  @doc "The expanded value if main.cf sets the parameter, otherwise nil."
  def explicit(state, name), do: if(set?(state, name), do: value(state, name))

  @doc "Expands parameter references in text."
  def expand(state, text), do: MainCf.expand(state.main, text)

  @doc "Marks main.cf parameters as dealt with, so they are not reported as left over."
  def handle(state, names) when is_list(names),
    do: %{state | handled: Enum.into(names, state.handled)}

  def handle(state, name), do: handle(state, [name])

  @doc "Sets a config key. A key already set keeps its position."
  def put(state, section, key, value, comment \\ nil) do
    entries = Map.get(state.config, section, [])

    entries =
      if List.keymember?(entries, key, 0),
        do: List.keyreplace(entries, key, 0, {key, value, comment}),
        else: entries ++ [{key, value, comment}]

    %{state | config: Map.put(state.config, section, entries)}
  end

  @doc "The value of a config key set so far, or nil."
  def get(state, section, key) do
    case List.keyfind(Map.get(state.config, section, []), key, 0) do
      {^key, value, _comment} -> value
      nil -> nil
    end
  end

  @doc "Removes a config key."
  def delete(state, section, key) do
    entries = state.config |> Map.get(section, []) |> List.keydelete(key, 0)
    %{state | config: Map.put(state.config, section, entries)}
  end

  @doc "Adds a table to an array of tables, such as \"listener\"."
  def add_table(state, array, entries, comment \\ nil) do
    tables = Map.get(state.arrays, array, []) ++ [{entries, comment}]
    %{state | arrays: Map.put(state.arrays, array, tables)}
  end

  @doc "The tables of an array so far."
  def tables(state, array), do: Map.get(state.arrays, array, [])

  @doc "Replaces the tables of an array."
  def put_tables(state, array, tables),
    do: %{state | arrays: Map.put(state.arrays, array, tables)}

  @doc "Adds import commands under a heading, if there are any."
  def commands(state, _heading, []), do: state

  def commands(state, heading, commands),
    do: %{state | commands: state.commands ++ [{:comment, heading} | commands]}

  @doc "Adds a report line."
  def report(state, level, setting, value, message) do
    line = %{level: level, setting: setting, value: value, message: message}
    %{state | report: [line | state.report]}
  end

  @doc "Reports a main.cf parameter, and marks it as dealt with."
  def report_param(state, level, name, message) do
    state
    |> handle(name)
    |> report(level, name, MainCf.raw(state.main, name), message)
  end

  @doc "Sets a flag other steps read."
  def flag(state, name, value), do: %{state | flags: Map.put(state.flags, name, value)}

  @doc "Reads a flag."
  def flag(state, name), do: Map.get(state.flags, name)

  @doc "A path relative to Postfix's queue directory made absolute."
  def queue_path(state, path) do
    if Path.type(path) == :absolute,
      do: path,
      else: Path.join(state.queue_directory, path)
  end

  @doc "The master.cf service named `name` of type `type` (a list of types), or nil."
  def service(state, name, types) do
    state.services
    |> Enum.filter(&(&1.name == name and &1.type in types))
    |> List.last()
  end

  @doc """
  Reports the outcome of importing a table: how many entries, and the
  ones that could not be imported, as `{key, message}`.
  """
  def table_report(state, setting, item, count, problems, what) do
    level = if problems == [], do: :migrated, else: :attention

    report(
      state,
      level,
      setting,
      item,
      "#{count} #{what} in import.sh." <> problem_text(problems)
    )
  end

  defp problem_text([]), do: ""

  defp problem_text(problems) do
    shown = Enum.take(problems, 20)
    more = length(problems) - length(shown)

    " Not imported: " <>
      Enum.map_join(shown, "; ", fn {key, message} -> "#{key}: #{message}" end) <>
      if(more > 0, do: "; and #{more} more.", else: ".")
  end
end
