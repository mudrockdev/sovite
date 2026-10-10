defmodule Sovite.Core.Postfix.MainCf do
  @moduledoc """
  Reads Postfix's `main.cf` and expands parameter values the way Postfix
  does, for `Sovite.Core.Postfix.Migration`.

  The file has one `name = value` per logical line. Lines whose first
  non-whitespace character is `#` are comments, and a line that starts
  with whitespace continues the one before it. Values can refer to other
  parameters as `$name`, `${name}`, or `$(name)`, and use the conditional
  forms `${name?value}` (`value` when `$name` is not empty),
  `${name:value}` (when it is empty), and `${name?{value1}:{value2}}`.
  `$$` is a literal `$`. Parameters not in the file get Postfix's
  defaults, for the ones the migration needs.

  The file is untrusted input: names stay strings.
  """

  defstruct params: %{}, names: [], defaults: %{}

  @type t :: %__MODULE__{
          params: %{String.t() => String.t()},
          names: [String.t()],
          defaults: %{String.t() => String.t()}
        }

  # Postfix's defaults (Postfix 3.x) for the parameters the migration reads.
  # myhostname is the system's host name; mydomain is derived from it.
  @defaults %{
    "myhostname" => "localhost",
    "myorigin" => "$myhostname",
    "mydestination" => "$myhostname, localhost.$mydomain, localhost",
    "config_directory" => "/etc/postfix",
    "queue_directory" => "/var/spool/postfix",
    "data_directory" => "/var/lib/postfix",
    "inet_interfaces" => "all",
    "inet_protocols" => "all",
    "mynetworks_style" => "host",
    "relay_domains" => "",
    "virtual_alias_domains" => "$virtual_alias_maps",
    "virtual_mailbox_domains" => "$virtual_mailbox_maps",
    "alias_maps" => "hash:/etc/aliases",
    "virtual_transport" => "virtual",
    "local_transport" => "local:$myhostname",
    "relay_transport" => "relay",
    "default_transport" => "smtp",
    "smtpd_sasl_type" => "cyrus",
    "smtpd_sasl_path" => "smtpd",
    "smtpd_tls_key_file" => "$smtpd_tls_cert_file",
    "smtpd_tls_eckey_file" => "$smtpd_tls_eccert_file",
    "smtpd_delay_reject" => "yes",
    "milter_default_action" => "tempfail",
    "milter_connect_timeout" => "30s",
    "milter_command_timeout" => "30s",
    "milter_content_timeout" => "300s",
    "smtp_address_preference" => "any",
    "postscreen_dnsbl_threshold" => "1",
    "postscreen_greet_action" => "ignore",
    "postscreen_dnsbl_action" => "ignore",
    "postscreen_greet_wait" => "${stress?{2}:{6}}s",
    "anvil_rate_time_unit" => "60s",
    "smtp_sasl_auth_enable" => "no",
    "smtpd_sasl_auth_enable" => "no",
    "mail_name" => "Postfix"
  }

  # Postfix stops expanding after this many nested references.
  @max_depth 100

  @doc """
  Parses `contents`. `defaults` override Postfix's built-in defaults,
  such as `"myhostname"` (the system's host name) and
  `"config_directory"`.
  """
  @spec parse(String.t(), %{String.t() => String.t()}) :: t()
  def parse(contents, defaults \\ %{}) do
    {params, names} =
      contents
      |> logical_lines()
      |> Enum.reduce({%{}, []}, &parameter/2)

    %__MODULE__{params: params, names: Enum.reverse(names), defaults: defaults}
  end

  # `name = value`; a later line for the same name wins, as in Postfix.
  defp parameter({_number, line}, {params, names}) do
    case String.split(line, "=", parts: 2) do
      [name, value] when name != "" ->
        name = String.trim(name)
        names = if Map.has_key?(params, name), do: names, else: [name | names]
        {Map.put(params, name, String.trim(value)), names}

      _ ->
        {params, names}
    end
  end

  @doc """
  Splits Postfix configuration text into logical lines: comments and
  blank lines are dropped, and lines starting with whitespace are joined
  to the one before. Returns `{line_number, text}` pairs.

      iex> Sovite.Core.Postfix.MainCf.logical_lines("a = 1\\n  2\\n# c\\nb = 3\\n")
      [{1, "a = 1 2"}, {4, "b = 3"}]
  """
  @spec logical_lines(String.t()) :: [{pos_integer(), String.t()}]
  def logical_lines(contents) do
    contents
    |> String.split("\n")
    |> Enum.with_index(1)
    |> Enum.reduce([], fn {line, number}, acc ->
      line = String.trim_trailing(line)
      trimmed = String.trim_leading(line)

      cond do
        trimmed == "" or String.starts_with?(trimmed, "#") -> acc
        trimmed != line and acc != [] -> continue_line(acc, trimmed)
        true -> [{number, trimmed} | acc]
      end
    end)
    |> Enum.reverse()
  end

  defp continue_line([{number, text} | rest], more), do: [{number, text <> " " <> more} | rest]

  @doc "Whether the file sets `name`."
  @spec set?(t(), String.t()) :: boolean()
  def set?(%__MODULE__{params: params}, name), do: Map.has_key?(params, name)

  @doc "The names the file sets, in file order."
  @spec names(t()) :: [String.t()]
  def names(%__MODULE__{names: names}), do: names

  @doc "The value of `name` as written in the file, or `nil`."
  @spec raw(t(), String.t()) :: String.t() | nil
  def raw(%__MODULE__{params: params}, name), do: Map.get(params, name)

  @doc """
  The expanded value of `name`: from the file, or the default. Unknown
  parameters are empty, as in Postfix.
  """
  @spec value(t(), String.t()) :: String.t()
  def value(main, name), do: lookup(main, name, 0)

  @doc "The expanded value of `name`, split into a list. See `split/1`."
  @spec list(t(), String.t()) :: [String.t()]
  def list(main, name), do: main |> value(name) |> split()

  @doc """
  Splits a list value on whitespace and commas, keeping `{ ... }` groups
  (and `type:{ ... }` tables) together.

      iex> Sovite.Core.Postfix.MainCf.split("a, b  c,{ d, e }, inline:{ x=1, y=2 }")
      ["a", "b", "c", "{ d, e }", "inline:{ x=1, y=2 }"]
  """
  @spec split(String.t()) :: [String.t()]
  def split(value) do
    {items, current, _depth} =
      value
      |> String.graphemes()
      |> Enum.reduce({[], "", 0}, fn
        "{", {items, current, depth} ->
          {items, current <> "{", depth + 1}

        "}", {items, current, depth} ->
          {items, current <> "}", max(depth - 1, 0)}

        char, {items, current, 0} when char in [" ", "\t", ",", "\n", "\r"] ->
          {push(items, current), "", 0}

        char, {items, current, depth} ->
          {items, current <> char, depth}
      end)

    items |> push(current) |> Enum.reverse()
  end

  defp push(items, ""), do: items
  defp push(items, item), do: [item | items]

  @doc """
  Strips the braces of a `{ ... }` group and the whitespace inside.
  Other text is returned trimmed.

      iex> Sovite.Core.Postfix.MainCf.ungroup("{ a = b }")
      "a = b"
  """
  @spec ungroup(String.t()) :: String.t()
  def ungroup(text) do
    text = String.trim(text)

    if String.starts_with?(text, "{") and String.ends_with?(text, "}"),
      do: text |> String.slice(1..-2//1) |> String.trim(),
      else: text
  end

  @doc "Expands the parameter references in `text`."
  @spec expand(t(), String.t()) :: String.t()
  def expand(main, text), do: expand(main, text, 0)

  defp expand(_main, text, depth) when depth > @max_depth, do: text
  defp expand(main, text, depth), do: expand(main, text, depth, [])

  defp expand(_main, "", _depth, acc), do: acc |> Enum.reverse() |> IO.iodata_to_binary()
  defp expand(main, "$$" <> rest, depth, acc), do: expand(main, rest, depth, ["$" | acc])

  defp expand(main, "${" <> rest, depth, acc), do: expand_group(main, rest, "{", "}", depth, acc)
  defp expand(main, "$(" <> rest, depth, acc), do: expand_group(main, rest, "(", ")", depth, acc)

  defp expand(main, "$" <> rest, depth, acc) do
    case Regex.run(~r/\A[A-Za-z0-9_]+/, rest) do
      [name] ->
        value = lookup(main, name, depth + 1)

        expand(
          main,
          binary_part(rest, byte_size(name), byte_size(rest) - byte_size(name)),
          depth,
          [value | acc]
        )

      nil ->
        expand(main, rest, depth, ["$" | acc])
    end
  end

  defp expand(main, text, depth, acc) do
    case :binary.match(text, "$") do
      {at, _} when at > 0 ->
        expand(main, binary_part(text, at, byte_size(text) - at), depth, [
          binary_part(text, 0, at) | acc
        ])

      _ ->
        expand(main, "", depth, [text | acc])
    end
  end

  # "${name...}" and "$(name...)": the text up to the matching close.
  defp expand_group(main, rest, open, close, depth, acc) do
    case take_balanced(rest, open, close) do
      {inner, rest} -> expand(main, rest, depth, [macro(main, inner, depth) | acc])
      :error -> expand(main, rest, depth, ["$" <> open | acc])
    end
  end

  defp macro(main, inner, depth) do
    case Regex.run(~r/\A([A-Za-z0-9_-]+)(.*)\z/s, inner) do
      [_, name, ""] -> lookup(main, name, depth + 1)
      [_, name, "?" <> branch] -> conditional(main, name, branch, true, depth)
      [_, name, ":" <> branch] -> conditional(main, name, branch, false, depth)
      _ -> ""
    end
  end

  # "?value" / ":value" / "?{value1}:{value2}".
  defp conditional(main, name, branch, when_set, depth) do
    set = lookup(main, name, depth + 1) != ""

    {chosen, otherwise} =
      case take_braced(branch) do
        {value, ":" <> other} when when_set -> {value, ungroup_or(other)}
        {value, ""} -> {value, ""}
        _ -> {branch, ""}
      end

    if set == when_set,
      do: expand(main, chosen, depth + 1),
      else: expand(main, otherwise, depth + 1)
  end

  defp ungroup_or(text) do
    case take_braced(text) do
      {value, ""} -> value
      _ -> text
    end
  end

  defp take_braced("{" <> rest) do
    case take_balanced(rest, "{", "}") do
      {inner, rest} -> {inner, rest}
      :error -> :error
    end
  end

  defp take_braced(_text), do: :error

  # The text before the close that matches an already consumed open.
  defp take_balanced(text, open, close) do
    text
    |> String.graphemes()
    |> Enum.reduce_while({1, []}, fn
      ^open, {depth, acc} ->
        {:cont, {depth + 1, [open | acc]}}

      ^close, {1, acc} ->
        {:halt, {:done, acc}}

      ^close, {depth, acc} ->
        {:cont, {depth - 1, [close | acc]}}

      char, {depth, acc} ->
        {:cont, {depth, [char | acc]}}
    end)
    |> case do
      {:done, acc} ->
        inner = acc |> Enum.reverse() |> Enum.join()
        {inner, binary_part(text, byte_size(inner) + 1, byte_size(text) - byte_size(inner) - 1)}

      _ ->
        :error
    end
  end

  defp lookup(_main, _name, depth) when depth > @max_depth, do: ""

  defp lookup(main, name, depth) do
    case raw_or_default(main, name) do
      nil -> ""
      value -> expand(main, value, depth)
    end
  end

  defp raw_or_default(main, "mydomain") do
    Map.get(main.params, "mydomain") || Map.get(main.defaults, "mydomain") ||
      parent_domain(lookup(main, "myhostname", 1))
  end

  defp raw_or_default(main, name),
    do: Map.get(main.params, name) || Map.get(main.defaults, name) || Map.get(@defaults, name)

  # Postfix: myhostname without its first label, or "localdomain".
  defp parent_domain(hostname) do
    case String.split(hostname, ".", parts: 2) do
      [_first, rest] when rest != "" -> rest
      _ -> "localdomain"
    end
  end
end
