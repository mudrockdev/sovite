defmodule Sovite.DKIM.Canon do
  @moduledoc """
  Header canonicalization (RFC 6376 §3.4.1 and §3.4.2), and the header
  data a signature covers (§3.7, §5.4.2).

  Body canonicalization works on a stream, see `Sovite.DKIM.Body`.
  """

  alias Sovite.DKIM.Tags

  @type algorithm :: :simple | :relaxed

  @doc """
  Canonicalizes one header field, given as its raw text with the final
  CRLF.

      iex> Sovite.DKIM.Canon.header("SubJect :  Hello \\r\\n  world  \\r\\n", :relaxed)
      "subject:Hello world\\r\\n"
  """
  @spec header(String.t(), algorithm()) :: String.t()
  def header(raw, :simple), do: raw

  def header(raw, :relaxed) do
    [name, value] = :binary.split(raw, ":")

    value =
      value
      |> String.replace(~r/\r\n(?=[ \t])/, "")
      |> String.replace_suffix("\r\n", "")
      |> String.replace(~r/[ \t]+/, " ")
      |> String.trim(" ")

    String.downcase(String.replace(name, ~r/[ \t]+\z/, ""), :ascii) <> ":" <> value <> "\r\n"
  end

  @doc """
  Selects the fields named in `names` (a signature's `h=` tag), as
  §5.4.2 says: each occurrence of a name takes the next instance from the
  bottom of the header; a name with no instance left adds nothing.

  `fields` are as `Sovite.Message.Headers.parse/1` returns them.
  """
  @spec select([{String.t() | nil, String.t()}], [String.t()]) :: [String.t()]
  def select(fields, names) do
    available =
      fields
      |> Enum.reverse()
      |> Enum.reduce(%{}, fn
        {nil, _raw}, acc -> acc
        {name, raw}, acc -> Map.update(acc, name, [raw], &(&1 ++ [raw]))
      end)

    {selected, _} =
      Enum.reduce(names, {[], available}, fn name, {acc, available} ->
        name = String.downcase(name, :ascii)

        case Map.get(available, name, []) do
          [raw | rest] -> {[raw | acc], Map.put(available, name, rest)}
          [] -> {acc, available}
        end
      end)

    Enum.reverse(selected)
  end

  @doc """
  The data that is hashed and signed: the selected fields, canonicalized,
  then the signature field itself with its `b=` value emptied and no final
  CRLF.
  """
  @spec signed_data([String.t()], String.t(), algorithm()) :: iodata()
  def signed_data(selected, signature_raw, algorithm) do
    signature =
      signature_raw
      |> Tags.empty_b()
      |> header(algorithm)
      |> String.replace_suffix("\r\n", "")

    [Enum.map(selected, &header(&1, algorithm)), signature]
  end
end
