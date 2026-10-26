defmodule Sovite.Core.Filter.RuleFiles do
  @moduledoc """
  Reads the rule files of `[filter] rules` (files, or directories whose
  `*.toml` files are read in name order) and compiles them into a
  `Sovite.Rules` rule set.

  Sovite's built-in rules (`priv/rules/*.toml`: the symbols of its own
  checks, see `Sovite.Core.Filter.Checks`) are read first, so the files
  of `[filter] rules` can change them.
  """

  alias Sovite.Rules

  # What the caller knows of a message, for `is:` in rule expressions.
  @flags ~w(authenticated trusted tls inbound outbound)

  @doc "The flags rule expressions may use; see `Sovite.Core.Filter.flags/0`."
  @spec flags() :: [String.t()]
  def flags, do: @flags

  @doc "The built-in rule files, in order."
  @spec builtin() :: [Path.t()]
  def builtin,
    do: :sovite |> :code.priv_dir() |> Path.join("rules/*.toml") |> Path.wildcard() |> Enum.sort()

  @doc "The rule files of `paths`, after the built-in ones, in order."
  @spec files([Path.t()]) :: {:ok, [Path.t()]} | {:error, [String.t()]}
  def files(paths) do
    {files, errors} =
      Enum.reduce(paths, {[], []}, fn path, {files, errors} ->
        case expand(path) do
          {:ok, more} -> {files ++ more, errors}
          {:error, reason} -> {files, errors ++ [reason]}
        end
      end)

    if errors == [], do: {:ok, Enum.uniq(builtin() ++ files)}, else: {:error, errors}
  end

  defp expand(path) do
    case File.stat(path) do
      {:ok, %{type: :directory}} ->
        {:ok, path |> Path.join("*.toml") |> Path.wildcard() |> Enum.sort()}

      {:ok, _stat} ->
        {:ok, [path]}

      {:error, reason} ->
        {:error, "cannot read #{path}: #{:file.format_error(reason)}"}
    end
  end

  @doc """
  Reads and compiles the rule files of `paths`, with the flags
  expressions may use. Errors are lines such as
  `"/etc/sovite/rules/local.toml: symbol[2].regex: missing )"`.
  """
  @spec load([Path.t()], [String.t()]) :: {:ok, Rules.t()} | {:error, [String.t()]}
  def load(paths, flags) do
    with {:ok, files} <- files(paths),
         {:ok, decoded} <- decode_all(files) do
      case Rules.compile(decoded, flags: flags) do
        {:ok, rules} -> {:ok, rules}
        {:error, errors} -> {:error, Enum.map(errors, &format/1)}
      end
    end
  end

  defp decode_all(files) do
    {decoded, errors} =
      Enum.reduce(files, {[], []}, fn file, {decoded, errors} ->
        case decode(file) do
          {:ok, map} -> {decoded ++ [{file, map}], errors}
          {:error, reason} -> {decoded, errors ++ ["#{file}: #{reason}"]}
        end
      end)

    if errors == [], do: {:ok, decoded}, else: {:error, errors}
  end

  defp decode(file) do
    with {:ok, contents} <- read(file),
         # The TOML decoder crashes on bytes that are not UTF-8.
         true <- String.valid?(contents) || {:error, "invalid TOML: not UTF-8"} do
      case Toml.decode(contents) do
        {:ok, map} -> {:ok, map}
        {:error, {:invalid_toml, reason}} -> {:error, "invalid TOML: " <> String.trim(reason)}
        {:error, reason} -> {:error, "invalid TOML: #{inspect(reason)}"}
      end
    end
  end

  defp read(file) do
    case File.read(file) do
      {:ok, contents} -> {:ok, contents}
      {:error, reason} -> {:error, "cannot read: #{:file.format_error(reason)}"}
    end
  end

  # ["local.toml", "symbol", "[2]", "regex"] as "local.toml: symbol[2].regex".
  defp format({[file], reason}), do: "#{file}: #{reason}"

  defp format({[file | path], reason}) do
    keys =
      path
      |> Enum.with_index()
      |> Enum.map_join(fn
        {"[" <> _ = index, _position} -> index
        {key, 0} -> key
        {key, _position} -> "." <> key
      end)

    "#{file}: #{keys}: #{reason}"
  end
end
