defmodule Sovite.Core.Config.Schema do
  @moduledoc false
  # Validates decoded TOML (string-keyed maps) against a schema and returns
  # atom-keyed maps. Atoms come from the schema only, never from the input.
  #
  # A schema is a list of fields: {key :: atom, type, opts}
  #
  # Types:
  #   :string | :boolean | :hostname | :absolute_path
  #   :file_name               - a single path component, no "/"
  #   :file_name_pattern       - a file name with one "{n}" and optional "{date}"
  #   :strftime                - a Calendar.strftime/2 format
  #   :byte_size               - bytes as an integer or "512K", "100M", "1G"
  #   {:integer, min, max}
  #   {:enum, [atom]}          - the input string must equal one of the atom names
  #   {:section, [field]}      - a nested table
  #
  # Options:
  #   default: value or zero-arity function (defaults are validated too)
  #   required: true

  alias Sovite.Core.Config.Error

  @type field :: {atom(), term(), keyword()}

  @spec validate(term(), [field()], [String.t()]) :: {:ok, map()} | {:error, [Error.t()]}
  def validate(input, fields, path \\ [])

  def validate(input, fields, path) when is_map(input) do
    known = MapSet.new(fields, fn {key, _type, _opts} -> Atom.to_string(key) end)

    unknown_errors =
      for key <- input |> Map.keys() |> Enum.sort(), not MapSet.member?(known, key) do
        %Error{path: path ++ [key], reason: "unknown key"}
      end

    {values, field_errors} =
      Enum.reduce(fields, {%{}, []}, fn {key, type, opts}, {values, errors} ->
        name = Atom.to_string(key)

        case validate_field(Map.fetch(input, name), type, opts, path ++ [name]) do
          {:ok, value} -> {Map.put(values, key, value), errors}
          {:error, new_errors} -> {values, errors ++ new_errors}
        end
      end)

    case unknown_errors ++ field_errors do
      [] -> {:ok, values}
      errors -> {:error, errors}
    end
  end

  def validate(_input, _fields, path),
    do: {:error, [%Error{path: path, reason: "expected a table"}]}

  defp validate_field(:error, {:section, fields}, _opts, path), do: validate(%{}, fields, path)

  defp validate_field(:error, type, opts, path) do
    cond do
      Keyword.has_key?(opts, :default) ->
        value =
          case Keyword.fetch!(opts, :default) do
            fun when is_function(fun, 0) -> fun.()
            value -> value
          end

        with {:error, reason} <- cast(type, value) do
          {:error, [%Error{path: path, reason: reason <> " (default value)"}]}
        end

      Keyword.get(opts, :required, false) ->
        {:error, [%Error{path: path, reason: "is required"}]}

      true ->
        {:ok, nil}
    end
  end

  defp validate_field({:ok, value}, {:section, fields}, _opts, path),
    do: validate(value, fields, path)

  defp validate_field({:ok, value}, type, _opts, path) do
    with {:error, reason} <- cast(type, value) do
      {:error, [%Error{path: path, reason: reason}]}
    end
  end

  defp cast(:string, value) when is_binary(value), do: {:ok, value}
  defp cast(:string, value), do: type_error("a string", value)

  defp cast(:boolean, value) when is_boolean(value), do: {:ok, value}
  defp cast(:boolean, value), do: type_error("true or false", value)

  defp cast({:integer, min, max}, value) when is_integer(value) and value >= min and value <= max,
    do: {:ok, value}

  defp cast({:integer, min, max}, value),
    do: type_error("an integer from #{min} to #{max}", value)

  # Defaults are written as atoms in the schema, so accept those as well.
  defp cast({:enum, allowed}, value) when is_atom(value) do
    if value in allowed, do: {:ok, value}, else: enum_error(allowed, value)
  end

  defp cast({:enum, allowed}, value) when is_binary(value) do
    case Enum.find(allowed, &(Atom.to_string(&1) == value)) do
      nil -> enum_error(allowed, value)
      atom -> {:ok, atom}
    end
  end

  defp cast({:enum, allowed}, value), do: enum_error(allowed, value)

  defp cast(:hostname, value) when is_binary(value) do
    if Sovite.Validators.hostname?(value),
      do: {:ok, value},
      else: {:error, "#{inspect(value)} is not a valid hostname"}
  end

  defp cast(:hostname, value), do: type_error("a hostname string", value)

  defp cast(:absolute_path, value) when is_binary(value) do
    if Path.type(value) == :absolute,
      do: {:ok, value},
      else: {:error, "#{inspect(value)} is not an absolute path"}
  end

  defp cast(:absolute_path, value), do: type_error("an absolute path", value)

  defp cast(:file_name, value) when is_binary(value) do
    if value in ["", ".", ".."] or String.contains?(value, ["/", <<0>>]),
      do: {:error, "#{inspect(value)} is not a valid file name"},
      else: {:ok, value}
  end

  defp cast(:file_name, value), do: type_error("a file name", value)

  defp cast(:file_name_pattern, value) when is_binary(value) do
    placeholders = Regex.scan(~r/\{[^}]*\}/, value) |> List.flatten()

    cond do
      match?({:error, _}, cast(:file_name, value)) ->
        {:error, "#{inspect(value)} is not a valid file name"}

      Enum.count(placeholders, &(&1 == "{n}")) != 1 ->
        {:error, "#{inspect(value)} must contain {n} exactly once"}

      unknown = Enum.find(placeholders, &(&1 not in ["{n}", "{date}"])) ->
        {:error, "#{inspect(value)} has unknown placeholder #{unknown}, expected {date} or {n}"}

      true ->
        {:ok, value}
    end
  end

  defp cast(:file_name_pattern, value), do: type_error("a file name", value)

  defp cast(:strftime, value) when is_binary(value) do
    sample = Calendar.strftime(~N[2026-12-31 23:59:59], value)

    if String.contains?(sample, ["/", <<0>>]),
      do: {:error, "#{inspect(value)} must not produce a \"/\""},
      else: {:ok, value}
  rescue
    ArgumentError -> {:error, "#{inspect(value)} is not a valid strftime format"}
  end

  defp cast(:strftime, value), do: type_error("a strftime format string", value)

  defp cast(:byte_size, value) when is_integer(value) and value > 0, do: {:ok, value}

  defp cast(:byte_size, value) when is_binary(value) do
    case Regex.run(~r/\A(\d+)\s*([KMG]?)B?\z/i, String.trim(value)) do
      [_, digits, unit] ->
        bytes = String.to_integer(digits) * unit_size(String.upcase(unit))
        if bytes > 0, do: {:ok, bytes}, else: byte_size_error(value)

      _ ->
        byte_size_error(value)
    end
  end

  defp cast(:byte_size, value), do: byte_size_error(value)

  defp unit_size(""), do: 1
  defp unit_size("K"), do: 1024
  defp unit_size("M"), do: 1024 * 1024
  defp unit_size("G"), do: 1024 * 1024 * 1024

  defp byte_size_error(value), do: type_error(~s(a size like "512M" or "1G"), value)

  defp type_error(expected, value), do: {:error, "expected #{expected}, got #{inspect(value)}"}

  defp enum_error(allowed, value) do
    {:error,
     "expected one of #{Enum.map_join(allowed, ", ", &inspect(Atom.to_string(&1)))}, got #{inspect(value)}"}
  end
end
