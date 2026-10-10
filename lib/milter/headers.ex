defmodule Sovite.Milter.Headers do
  @moduledoc """
  Applies a milter's header modifications to the header fields of a
  message, with libmilter's index rules, and turns fields into the name
  and value that `Sovite.Milter.header/3` sends.

  Fields are `Sovite.Message.Headers` fields: `{name, raw}`, with the
  lower-cased name and the whole field, continuation lines and final
  CRLF included. Fields the milter does not touch keep every byte.

      fields = Sovite.Message.Headers.parse(header)
      fields = Sovite.Milter.Headers.apply(fields, modifications)

  Modifications are applied one after the other, each to the result of
  the ones before it:

    * `{:add_header, name, value}` appends the field at the end.
    * `{:insert_header, index, name, value}` inserts it at position
      `index` among all fields: 0 is the top. Past the end, it is appended.
    * `{:change_header, index, name, value}` replaces the `index`th field
      called `name` (case-insensitive, from 1; 0 counts as 1). When there
      are fewer, the field is appended, as Sendmail does.
    * `{:delete_header, index, name}` removes the `index`th field called
      `name`, if there is one.

  Other modifications are ignored.
  """

  import Kernel, except: [apply: 2]

  alias Sovite.Message.Headers

  @doc "Applies the header modifications in `modifications` to `fields`."
  @spec apply([Headers.field()], [Sovite.Milter.modification()]) :: [Headers.field()]
  def apply(fields, modifications), do: Enum.reduce(modifications, fields, &modify(&2, &1))

  defp modify(fields, {:add_header, name, value}), do: fields ++ [field(name, value)]

  defp modify(fields, {:insert_header, index, name, value}),
    do: List.insert_at(fields, index, field(name, value))

  defp modify(fields, {:change_header, index, name, value}) do
    case position(fields, name, index) do
      nil -> fields ++ [field(name, value)]
      position -> List.replace_at(fields, position, field(name, value))
    end
  end

  defp modify(fields, {:delete_header, index, name}) do
    case position(fields, name, index) do
      nil -> fields
      position -> List.delete_at(fields, position)
    end
  end

  defp modify(fields, _modification), do: fields

  # Where the index-th field called name is in the list.
  defp position(fields, name, index) do
    name = String.downcase(name, :ascii)

    fields
    |> Enum.with_index()
    |> Enum.filter(fn {{field_name, _raw}, _position} -> field_name == name end)
    |> Enum.at(max(index, 1) - 1)
    |> case do
      {_field, position} -> position
      nil -> nil
    end
  end

  defp field(name, value), do: {String.downcase(name, :ascii), name <> ":" <> value <> "\r\n"}

  @doc """
  Splits a field into its name, as written, and its value: everything
  after the colon, without the final line break. Returns `nil` for a line
  that is not a field.

      iex> Sovite.Milter.Headers.name_value({"subject", "Subject: Hello\\r\\n world\\r\\n"})
      {"Subject", " Hello\\r\\n world"}
  """
  @spec name_value(Headers.field()) :: {String.t(), String.t()} | nil
  def name_value({nil, _raw}), do: nil

  def name_value({_name, raw}) do
    [name, value] = :binary.split(raw, ":")
    value = if String.ends_with?(value, "\r\n"), do: binary_slice(value, 0..-3//1), else: value
    {String.trim_trailing(name), value}
  end
end
