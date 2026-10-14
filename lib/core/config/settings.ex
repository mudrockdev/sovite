defmodule Sovite.Core.Config.Settings do
  @moduledoc """
  The settings of a config file as `key = value` lines, like Postfix's
  `postconf`: every key of the schema, with its value from the file or its
  default. Keys are dotted paths (`smtp.max_message_size`), with array
  indexes for tables that repeat (`listener[0].port`). Values are TOML.

      smtp.max_message_size = "25M"
      listener[0].mode = "submission"

  Keys that have neither a value nor a default are left out, and so are
  listener keys whose default depends on the listener's mode. Secrets
  (passwords, client secrets, SRS secrets, the password in
  `database.url`, `tracing.headers` values) are shown as `"********"`.
  """

  alias Sovite.Core.Config

  @typedoc "A setting: its key, its value as TOML, and whether the value is the default."
  @type setting :: {key :: String.t(), value :: String.t(), default? :: boolean()}

  @redacted ~s("********")

  @doc "The settings of a decoded config file (`Sovite.Core.Config` `raw`)."
  @spec list(map()) :: [setting()]
  def list(raw) when is_map(raw), do: fields(Config.schema(), raw, "")

  @doc """
  The settings that differ between `old` and `new`, as `{key, old_value,
  new_value}`; a value is `nil` when the key has none on that side.
  """
  @spec diff([setting()], [setting()]) :: [{String.t(), String.t() | nil, String.t() | nil}]
  def diff(old, new) do
    old = Map.new(old, fn {key, value, _default} -> {key, value} end)
    new = Map.new(new, fn {key, value, _default} -> {key, value} end)

    (Map.keys(old) ++ Map.keys(new))
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.flat_map(fn key ->
      if old[key] == new[key], do: [], else: [{key, old[key], new[key]}]
    end)
  end

  @doc "Formats settings as lines."
  @spec format([setting()]) :: String.t()
  def format(settings),
    do: Enum.map_join(settings, "", fn {key, value, _default} -> "#{key} = #{value}\n" end)

  ## Walking the schema

  defp fields(fields, raw, prefix) do
    Enum.flat_map(fields, fn {key, type, opts} ->
      name = Atom.to_string(key)
      setting(prefix <> name, type, Map.fetch(raw, name), opts)
    end)
  end

  defp setting(key, {:section, fields}, {:ok, value}, _opts) when is_map(value),
    do: fields(fields, value, key <> ".")

  defp setting(key, {:section, fields}, :error, _opts), do: fields(fields, %{}, key <> ".")

  defp setting(key, {:list, {:section, fields}}, found, opts) do
    case value(found, opts) do
      {:ok, items, default} when is_list(items) ->
        items
        |> Enum.with_index()
        |> Enum.flat_map(fn {item, index} -> section_item(key, index, fields, item, default) end)

      _ ->
        []
    end
  end

  defp setting(key, {:map, _key_type, {:section, fields}}, {:ok, value}, _opts)
       when is_map(value) do
    value
    |> Enum.sort()
    |> Enum.flat_map(fn {name, item} ->
      if is_map(item), do: fields(fields, item, "#{key}.#{toml_key(name)}."), else: []
    end)
  end

  defp setting(key, type, found, opts) do
    case value(found, opts) do
      {:ok, nil, _default} -> []
      {:ok, value, default} -> [{key, encode(key, type, value), default}]
      :none -> []
    end
  end

  # Tables in a list with defaults: their keys are default too.
  defp section_item(key, index, fields, item, default) when is_map(item) do
    for {item_key, value, item_default} <- fields(fields, item, "#{key}[#{index}]."),
        do: {item_key, value, default and item_default}
  end

  defp section_item(_key, _index, _fields, _item, _default), do: []

  defp value({:ok, value}, _opts), do: {:ok, value, false}

  defp value(:error, opts) do
    case Keyword.fetch(opts, :default) do
      {:ok, fun} when is_function(fun, 0) -> {:ok, fun.(), true}
      {:ok, value} -> {:ok, value, true}
      :error -> :none
    end
  end

  ## TOML values

  defp encode(key, type, value) do
    if secret?(key, type), do: redact(key, value), else: toml(value)
  end

  defp secret?(key, _type) do
    name = key |> String.split(".") |> List.last()

    String.contains?(name, ["password", "secret"]) or key == "database.url" or
      String.starts_with?(key, "tracing.headers")
  end

  # Keep the URL readable, without its password.
  defp redact("database.url", value) when is_binary(value) do
    case URI.parse(value) do
      %URI{userinfo: userinfo} = uri when is_binary(userinfo) ->
        user = userinfo |> :binary.split(":") |> hd()
        toml(URI.to_string(%{uri | userinfo: user <> ":********"}))

      _ ->
        toml(value)
    end
  end

  defp redact(_key, value) when is_map(value),
    do: toml(Map.new(value, fn {name, _value} -> {name, "********"} end))

  defp redact(_key, _value), do: @redacted

  defp toml(value) when is_binary(value), do: JSON.encode!(value)
  defp toml(value) when is_boolean(value), do: Atom.to_string(value)
  defp toml(value) when is_atom(value), do: JSON.encode!(Atom.to_string(value))
  defp toml(value) when is_integer(value), do: Integer.to_string(value)
  defp toml(value) when is_float(value), do: Float.to_string(value)
  defp toml(values) when is_list(values), do: "[" <> Enum.map_join(values, ", ", &toml/1) <> "]"

  defp toml(%{} = map) do
    pairs =
      map |> Enum.sort() |> Enum.map_join(", ", fn {k, v} -> "#{toml_key(k)} = #{toml(v)}" end)

    if pairs == "", do: "{}", else: "{ " <> pairs <> " }"
  end

  defp toml(value), do: JSON.encode!(inspect(value))

  defp toml_key(key) do
    key = to_string(key)
    if String.match?(key, ~r/\A[A-Za-z0-9_-]+\z/), do: key, else: JSON.encode!(key)
  end
end
