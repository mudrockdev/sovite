defmodule Sovite.LDAP.Filter do
  @moduledoc """
  Parses RFC 4515 LDAP search filters into `:eldap` filters, with
  placeholders filled in after parsing.

  A placeholder is `%` and a letter; `build/2` takes the value of each
  letter, such as `%{"u" => "alice@example.com"}`. `%%` is a `%`, and a
  letter without a value is left as it is.

  Because placeholders are replaced in the parsed values, input cannot
  change the filter's structure: `*)(uid=*` is just a strange name, never
  an injection.

      iex> {:ok, filter} = Sovite.LDAP.Filter.parse("(&(objectClass=person)(mail=%u))")
      iex> Sovite.LDAP.Filter.build(filter, %{"u" => "a*b@example.com"})
      {:and, [{:equalityMatch, {:AttributeValueAssertion, ~c"objectClass", ~c"person"}}, {:equalityMatch, {:AttributeValueAssertion, ~c"mail", ~c"a*b@example.com"}}]}
  """

  @typedoc "A parsed filter, to fill in with `build/2`."
  @type t :: tuple()

  @doc "Parses a filter string. Returns `:error` for invalid syntax."
  @spec parse(String.t()) :: {:ok, t()} | :error
  def parse(string) do
    case filter(string) do
      {:ok, filter, ""} -> {:ok, filter}
      _ -> :error
    end
  end

  @doc "Fills in the placeholders from `values` and returns an `:eldap` filter."
  @spec build(t(), %{String.t() => binary()}) :: term()
  def build({:and, filters}, values), do: :eldap.and(Enum.map(filters, &build(&1, values)))
  def build({:or, filters}, values), do: :eldap.or(Enum.map(filters, &build(&1, values)))
  def build({:not, filter}, values), do: :eldap.not(build(filter, values))
  def build({:present, attr}, _values), do: :eldap.present(attr)

  def build({:substrings, attr, parts}, values) do
    :eldap.substrings(attr, for({kind, value} <- parts, do: {kind, fill(value, values)}))
  end

  def build({op, attr, value}, values), do: apply(:eldap, op, [attr, fill(value, values)])

  @doc """
  Replaces the placeholders in `string` with `values`, escaping each
  value with `escape`.
  """
  @spec substitute(String.t(), %{String.t() => binary()}, (binary() -> binary())) :: binary()
  def substitute(string, values, escape \\ & &1) do
    Regex.replace(~r/%([a-z%])/, string, fn
      "%%", _ -> "%"
      whole, letter -> if value = values[letter], do: escape.(value), else: whole
    end)
  end

  ## Parser

  defp filter("(" <> rest) do
    with {:ok, filter, rest} <- component(rest),
         ")" <> rest <- rest do
      {:ok, filter, rest}
    else
      _ -> :error
    end
  end

  defp filter(_), do: :error

  defp component("&" <> rest), do: list(rest, :and, [])
  defp component("|" <> rest), do: list(rest, :or, [])

  defp component("!" <> rest) do
    with {:ok, filter, rest} <- filter(rest), do: {:ok, {:not, filter}, rest}
  end

  defp component(rest), do: item(rest)

  defp list("(" <> _ = rest, kind, acc) do
    with {:ok, filter, rest} <- filter(rest), do: list(rest, kind, [filter | acc])
  end

  defp list(_rest, _kind, []), do: :error
  defp list(rest, kind, acc), do: {:ok, {kind, Enum.reverse(acc)}, rest}

  defp item(string) do
    with [_, attr, op, value, rest] <-
           Regex.run(
             ~r/\A([A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)(~=|>=|<=|=)([^()]*)(.*)\z/s,
             string
           ),
         {:ok, filter} <- assertion(String.to_charlist(attr), op, value) do
      {:ok, filter, rest}
    else
      _ -> :error
    end
  end

  defp assertion(attr, "=", "*"), do: {:ok, {:present, attr}}

  defp assertion(attr, "=", value) do
    if String.contains?(value, "*") do
      substrings(attr, String.split(value, "*"))
    else
      with {:ok, value} <- unescape(value), do: {:ok, {:equalityMatch, attr, value}}
    end
  end

  defp assertion(attr, op, value) do
    name = %{"~=" => :approxMatch, ">=" => :greaterOrEqual, "<=" => :lessOrEqual}[op]
    with {:ok, value} <- unescape(value), do: {:ok, {name, attr, value}}
  end

  defp substrings(attr, [initial | rest]) do
    {middle, [final]} = Enum.split(rest, -1)

    parts =
      [{:initial, initial}] ++ Enum.map(middle, &{:any, &1}) ++ [{:final, final}]

    parts
    |> Enum.reject(fn {_kind, value} -> value == "" end)
    |> Enum.reduce_while({:ok, []}, fn {kind, value}, {:ok, acc} ->
      case unescape(value) do
        {:ok, value} -> {:cont, {:ok, [{kind, value} | acc]}}
        :error -> {:halt, :error}
      end
    end)
    |> case do
      {:ok, []} -> :error
      {:ok, parts} -> {:ok, {:substrings, attr, Enum.reverse(parts)}}
      :error -> :error
    end
  end

  # "\2a" style escapes (RFC 4515 §3).
  defp unescape(value) do
    if Regex.match?(~r/\\(?![0-9A-Fa-f]{2})/, value),
      do: :error,
      else:
        {:ok,
         Regex.replace(~r/\\([0-9A-Fa-f]{2})/, value, fn _, hex ->
           <<String.to_integer(hex, 16)>>
         end)}
  end

  # Values are octet strings: keep the bytes, valid UTF-8 or not.
  defp fill(value, values), do: value |> substitute(values) |> :binary.bin_to_list()
end
