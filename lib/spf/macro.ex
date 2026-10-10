defmodule Sovite.SPF.Macro do
  @moduledoc """
  SPF macro strings (RFC 7208 §7).

  A macro string is parsed once with `parse/2` and expanded with
  `expand/2` or `expand_domain/2` against a `t:context/0`:

      iex> {:ok, macro} = Sovite.SPF.Macro.parse("%{ir}.%{v}._spf.%{d2}")
      iex> Sovite.SPF.Macro.expand(macro, %{
      ...>   sender: "strong-bad@email.example.com",
      ...>   domain: "email.example.com",
      ...>   ip: {192, 0, 2, 3}
      ...> })
      "3.2.0.192.in-addr._spf.example.com"

  Expansion is pure. The `p` macro needs a validated host name for the
  client, which takes DNS lookups, so the caller looks it up when
  `uses_ptr?/1` says so and passes it as `:ptr`.
  """

  @typedoc """
  The values macros expand to.

    * `:sender` - `s`, and `l` and `o` from its local part and domain.
    * `:domain` - `d`, the domain being checked.
    * `:ip` - `i`, `v`, and `c`, the client address.
    * `:helo` - `h`. Defaults to `"unknown"`.
    * `:ptr` - `p`, the client's validated host name. Defaults to
      `"unknown"`.
    * `:receiver` - `r`. Defaults to `"unknown"`.
    * `:now` - `t`, in Unix seconds. Defaults to the current time.
  """
  @type context :: %{
          optional(:sender) => String.t(),
          optional(:domain) => String.t(),
          optional(:ip) => :inet.ip_address(),
          optional(:helo) => String.t() | nil,
          optional(:ptr) => String.t() | nil,
          optional(:receiver) => String.t() | nil,
          optional(:now) => integer() | nil
        }

  @typedoc """
  Where a macro string appears, which decides what it may contain.

    * `:domain_spec` - a mechanism or modifier target. Must end like a
      domain name, and may not use `c`, `r`, or `t`.
    * `:explanation` - the text of an `exp=` record. May contain spaces.
    * `:macro_string` - the value of an unknown modifier.
  """
  @type kind :: :domain_spec | :explanation | :macro_string

  @typedoc "A letter, digits (labels to keep), reverse, delimiters, URL-escape."
  @type macro ::
          {:macro, atom(), pos_integer() | nil, boolean(), [String.t()], boolean()}

  @typedoc "A parsed macro string."
  @type t :: [String.t() | {:escape, String.t()} | macro()]

  @letters %{
    ?s => :s,
    ?l => :l,
    ?o => :o,
    ?d => :d,
    ?i => :i,
    ?p => :p,
    ?v => :v,
    ?h => :h,
    ?c => :c,
    ?r => :r,
    ?t => :t
  }

  @explanation_only [:c, :r, :t]

  # RFC 7208 §7.3: a name used in a query is at most 253 characters.
  @max_domain 253

  @doc """
  Parses a macro string of the given `kind`.

      iex> Sovite.SPF.Macro.parse("%{d}")
      {:ok, [{:macro, :d, nil, false, [], false}]}
      iex> Sovite.SPF.Macro.parse("%{c}.example.com")
      {:error, "macro letter not allowed here"}
      iex> Sovite.SPF.Macro.parse("%{c}", :explanation)
      {:ok, [{:macro, :c, nil, false, [], false}]}
  """
  @spec parse(String.t(), kind()) :: {:ok, t()} | {:error, String.t()}
  def parse(string, kind \\ :domain_spec) when is_binary(string) do
    with {:ok, parts} <- parse_parts(string, kind, [], ""),
         :ok <- check_end(parts, kind) do
      {:ok, parts}
    end
  end

  defp parse_parts(<<>>, _kind, acc, literal), do: {:ok, Enum.reverse(push(acc, literal))}

  defp parse_parts(<<"%", escape, rest::binary>>, kind, acc, literal) when escape in ~c"%_-" do
    expansion = %{?% => "%", ?_ => " ", ?- => "%20"}
    parse_parts(rest, kind, [{:escape, expansion[escape]} | push(acc, literal)], "")
  end

  defp parse_parts(<<"%{", rest::binary>>, kind, acc, literal) do
    with {:ok, macro, rest} <- parse_macro(rest, kind),
         do: parse_parts(rest, kind, [macro | push(acc, literal)], "")
  end

  defp parse_parts(<<"%", _rest::binary>>, _kind, _acc, _literal), do: {:error, "invalid macro"}

  # macro-literal is %x21-24 / %x26-7E; explanations may also hold spaces.
  defp parse_parts(<<char, rest::binary>>, kind, acc, literal)
       when char in 0x21..0x7E or (char == ?\s and kind == :explanation),
       do: parse_parts(rest, kind, acc, literal <> <<char>>)

  defp parse_parts(_string, _kind, _acc, _literal), do: {:error, "invalid character"}

  defp push(acc, ""), do: acc
  defp push(acc, literal), do: [literal | acc]

  defp parse_macro(string, kind) do
    with [letter, digits, reverse, delimiters, rest] <-
           Regex.run(~r/\A([a-zA-Z])([0-9]*)([rR]?)([.\-+,\/_=]*)\}(.*)\z/s, string,
             capture: :all_but_first
           ),
         {:ok, name} <- letter(letter, kind),
         {:ok, keep} <- keep(digits) do
      delimiters = String.graphemes(delimiters)
      escape? = String.upcase(letter) == letter
      {:ok, {:macro, name, keep, reverse != "", delimiters, escape?}, rest}
    else
      {:error, _} = error -> error
      nil -> {:error, "invalid macro"}
    end
  end

  defp letter(letter, kind) do
    <<char>> = String.downcase(letter)

    case Map.fetch(@letters, char) do
      {:ok, name} when name in @explanation_only and kind == :domain_spec ->
        {:error, "macro letter not allowed here"}

      {:ok, name} ->
        {:ok, name}

      :error ->
        {:error, "invalid macro"}
    end
  end

  defp keep(""), do: {:ok, nil}

  defp keep(digits) do
    case String.to_integer(digits) do
      0 -> {:error, "invalid macro"}
      keep -> {:ok, keep}
    end
  end

  # domain-end = ( "." toplabel [ "." ] ) / macro-expand
  defp check_end(parts, :domain_spec) do
    case List.last(parts) do
      literal when is_binary(literal) ->
        if Regex.match?(
             ~r/\.([a-z0-9]*[a-z][a-z0-9]*|[a-z0-9]+-[a-z0-9-]*[a-z0-9])\.?\z/i,
             literal
           ),
           do: :ok,
           else: {:error, "invalid domain"}

      nil ->
        {:error, "invalid domain"}

      _macro ->
        :ok
    end
  end

  defp check_end(_parts, _kind), do: :ok

  @doc "Returns `true` if `macro` uses the `p` macro, which needs a PTR lookup."
  @spec uses_ptr?(t()) :: boolean()
  def uses_ptr?(macro), do: Enum.any?(macro, &match?({:macro, :p, _, _, _, _}, &1))

  @doc """
  Expands `macro` with the values in `context`.

      iex> {:ok, macro} = Sovite.SPF.Macro.parse("%{l1r-}.%{O}", :macro_string)
      iex> Sovite.SPF.Macro.expand(macro, %{sender: "strong-bad@email.example.com"})
      "strong.email.example.com"
  """
  @spec expand(t(), context()) :: String.t()
  def expand(macro, context), do: Enum.map_join(macro, &expand_part(&1, context))

  @doc """
  Expands `macro` for use as a domain name: if the result is longer than
  253 characters, labels are removed from the left until it fits
  (RFC 7208 §7.3).
  """
  @spec expand_domain(t(), context()) :: String.t()
  def expand_domain(macro, context), do: macro |> expand(context) |> truncate()

  defp truncate(name) when byte_size(name) <= @max_domain, do: name

  defp truncate(name) do
    case :binary.split(name, ".") do
      [_label, rest] -> truncate(rest)
      [_label] -> name
    end
  end

  defp expand_part(literal, _context) when is_binary(literal), do: literal
  defp expand_part({:escape, expansion}, _context), do: expansion

  defp expand_part({:macro, letter, keep, reverse?, delimiters, escape?}, context) do
    value = context |> value(letter) |> transform(keep, reverse?, delimiters)
    if escape?, do: URI.encode(value, &URI.char_unreserved?/1), else: value
  end

  # RFC 7208 §7.3: split on the delimiters, optionally reverse, keep the
  # rightmost labels, and always join with ".".
  defp transform(value, keep, reverse?, delimiters) do
    labels = String.split(value, if(delimiters == [], do: ["."], else: delimiters))
    labels = if reverse?, do: Enum.reverse(labels), else: labels
    labels = if keep, do: Enum.take(labels, -keep), else: labels
    Enum.join(labels, ".")
  end

  defp value(context, :s), do: Map.fetch!(context, :sender)
  defp value(context, :l), do: context |> Map.fetch!(:sender) |> split_sender() |> elem(0)
  defp value(context, :o), do: context |> Map.fetch!(:sender) |> split_sender() |> elem(1)
  defp value(context, :d), do: Map.fetch!(context, :domain)
  defp value(context, :i), do: context |> Map.fetch!(:ip) |> dotted()
  defp value(context, :p), do: Map.get(context, :ptr) || "unknown"
  defp value(context, :h), do: Map.get(context, :helo) || "unknown"
  defp value(context, :c), do: context |> Map.fetch!(:ip) |> :inet.ntoa() |> to_string()
  defp value(context, :r), do: Map.get(context, :receiver) || "unknown"

  defp value(context, :t),
    do: Integer.to_string(Map.get(context, :now) || System.os_time(:second))

  defp value(context, :v) do
    if tuple_size(Map.fetch!(context, :ip)) == 4, do: "in-addr", else: "ip6"
  end

  # The sender is local-part "@" domain, and the local part may itself
  # contain a quoted "@".
  defp split_sender(sender) do
    case :binary.matches(sender, "@") do
      [] ->
        {"postmaster", sender}

      matches ->
        {at, 1} = List.last(matches)
        <<local::binary-size(^at), "@", domain::binary>> = sender
        {local, domain}
    end
  end

  @doc """
  Formats an address for the `i` macro: dotted decimal for IPv4, and
  dot-separated nibbles for IPv6 (RFC 7208 §7.3).

      iex> Sovite.SPF.Macro.dotted({0x2001, 0xDB8, 0, 0, 0, 0, 0, 0xCB01})
      "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1"
  """
  @spec dotted(:inet.ip_address()) :: String.t()
  def dotted({_, _, _, _} = ip), do: ip |> Tuple.to_list() |> Enum.join(".")

  def dotted(ip) do
    bytes = for part <- Tuple.to_list(ip), into: <<>>, do: <<part::16>>
    bytes |> Base.encode16(case: :lower) |> String.graphemes() |> Enum.join(".")
  end
end
