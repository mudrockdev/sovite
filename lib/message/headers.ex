defmodule Sovite.Message.Headers do
  @moduledoc """
  The header section of a message (RFC 5322 §2.2), as a list of fields
  that keeps every byte of the original, so unchanged fields are passed
  through exactly (folding and all), which matters for signatures.

      {:ok, header, body} = Headers.split(data)
      fields = Headers.parse(header)
      fields |> Headers.delete(["Return-Path"]) |> Headers.encode()

  Each field is `{name, raw}`: the lower-cased field name and the whole
  field with its continuation lines and final CRLF. A line in the header
  section that is not a field is kept with name `nil`.
  """

  @type field :: {String.t() | nil, binary()}

  @doc """
  Splits message data at the empty line that ends the header section.
  Returns `:more` when `data` does not contain it yet. A message that
  starts with an empty line has no header fields.
  """
  @spec split(binary()) :: {:ok, header :: binary(), body :: binary()} | :more
  def split("\r\n" <> body), do: {:ok, "", body}

  def split(data) do
    case :binary.match(data, "\r\n\r\n") do
      {index, 4} ->
        {:ok, binary_part(data, 0, index + 2),
         binary_part(data, index + 4, byte_size(data) - index - 4)}

      :nomatch ->
        :more
    end
  end

  @doc "Parses a header section (CRLF line endings) into fields."
  @spec parse(binary()) :: [field()]
  def parse(header) do
    header
    |> String.split(~r/(?<=\r\n)/)
    |> Enum.reject(&(&1 == ""))
    |> Enum.reduce([], fn
      <<c, _::binary>> = line, [{name, raw} | rest] when c in [?\s, ?\t] ->
        [{name, raw <> line} | rest]

      line, acc ->
        [{field_name(line), line} | acc]
    end)
    |> Enum.reverse()
  end

  # field-name = 1*ftext, printable ASCII except ":".
  defp field_name(line) do
    case Regex.run(~r/\A([\x21-\x39\x3b-\x7e]+)[ \t]*:/, line) do
      [_, name] -> String.downcase(name, :ascii)
      nil -> nil
    end
  end

  @doc "Returns whether a field named `name` is present (case-insensitive)."
  @spec has?([field()], String.t()) :: boolean()
  def has?(fields, name) do
    name = String.downcase(name, :ascii)
    Enum.any?(fields, &(elem(&1, 0) == name))
  end

  @doc "Removes every field with one of `names` (case-insensitive)."
  @spec delete([field()], [String.t()]) :: [field()]
  def delete(fields, names) do
    names = MapSet.new(names, &String.downcase(&1, :ascii))
    Enum.reject(fields, fn {name, _raw} -> MapSet.member?(names, name) end)
  end

  @doc "Appends a field. `value` must already be folded if long."
  @spec append([field()], String.t(), String.t()) :: [field()]
  def append(fields, name, value),
    do: fields ++ [{String.downcase(name, :ascii), "#{name}: #{value}\r\n"}]

  @doc "Encodes fields back into a header section."
  @spec encode([field()]) :: iodata()
  def encode(fields), do: Enum.map(fields, &elem(&1, 1))
end
