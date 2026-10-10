defmodule Sovite.AuthResults do
  @moduledoc """
  The `Authentication-Results:` header field (RFC 8601), which tells the
  next hop and the user's mail client what this server found out about
  a message:

      Authentication-Results: mx.example.org;
              spf=pass smtp.mailfrom=alice@example.com;
              dkim=pass header.d=example.com header.s=sel header.b=AbCdEf12

  The first value, the authserv-id, names the server that did the
  checks. Results claiming to be ours that arrive with a message are
  forged, so they must be removed before ours are added (RFC 8601 §5),
  see `strip/2`.

  A result is a map:

      %{method: "spf", result: "pass", reason: nil, comment: nil,
        properties: [{"smtp.mailfrom", "alice@example.com"}]}
  """

  alias Sovite.Message.Headers

  @typedoc ~s(A property such as `{"smtp.mailfrom", "a@example.com"}` or `{"header.d", "example.com"}`.)
  @type property :: {String.t(), String.t()}

  @type result :: %{
          required(:method) => String.t(),
          required(:result) => String.t(),
          optional(:reason) => String.t() | nil,
          optional(:properties) => [property()],
          optional(:comment) => String.t() | nil
        }

  @doc """
  Returns the field value, without the field name and the final CRLF,
  one result per folded line.

      iex> Sovite.AuthResults.value("mx.example.org", [
      ...>   %{method: "spf", result: "pass", properties: [{"smtp.mailfrom", "a@example.com"}]}
      ...> ])
      "mx.example.org;\\r\\n\\tspf=pass smtp.mailfrom=a@example.com"
      iex> Sovite.AuthResults.value("mx.example.org", [])
      "mx.example.org; none"

  A `:reason` is always a quoted-string; a `:comment` follows the result
  in parentheses. Property values that are not a plain token or
  address are quoted. Control characters in them are replaced by
  spaces, so no value can end the field early.
  """
  @spec value(String.t(), [result()]) :: String.t()
  def value(authserv_id, []), do: format_value(authserv_id) <> "; none"

  def value(authserv_id, results),
    do: Enum.join([format_value(authserv_id) | Enum.map(results, &format_result/1)], ";\r\n\t")

  @doc """
  Returns the whole header field, ending in CRLF.

      iex> Sovite.AuthResults.field("mx.example.org", [])
      "Authentication-Results: mx.example.org; none\\r\\n"
  """
  @spec field(String.t(), [result()]) :: String.t()
  def field(authserv_id, results),
    do: "Authentication-Results: " <> value(authserv_id, results) <> "\r\n"

  defp format_result(result) do
    IO.iodata_to_binary([
      result.method,
      "=",
      result.result,
      if(comment = result[:comment], do: [" (", escape(comment, ~c"()\\"), ")"], else: []),
      if(reason = result[:reason], do: [" reason=", quote_string(reason)], else: []),
      for({name, value} <- result[:properties] || [], do: [" ", name, "=", format_pvalue(value)])
    ])
  end

  defp format_value(value), do: if(token?(value), do: value, else: quote_string(value))

  # pvalue = value / [[local-part] "@"] domain-name
  defp format_pvalue(value) do
    if token?(value) or Regex.match?(address(), value),
      do: value,
      else: quote_string(value)
  end

  # RFC 2045 token: printable US-ASCII except tspecials.
  defp token?(value), do: Regex.match?(~r/\A[!#$%&'*+\-.0-9A-Z^_`a-z{|}~]+\z/, value)

  defp address do
    atom = "[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    label = "[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    Regex.compile!("\\A(?:#{atom}(?:\\.#{atom})*)?@#{label}(?:\\.#{label})*\\z")
  end

  defp quote_string(text), do: ~s(") <> escape(text, ~c"\\\"") <> ~s(")

  defp escape(text, specials) do
    for <<c <- text>>, into: "" do
      cond do
        c in specials -> <<?\\, c>>
        c < 0x20 or c == 0x7F -> " "
        true -> <<c>>
      end
    end
  end

  @doc """
  Returns the authserv-id of a field value (the text after
  `Authentication-Results:`), unquoted.

      iex> Sovite.AuthResults.authserv_id(" (checked) mx.example.org 1; spf=pass")
      {:ok, "mx.example.org"}
      iex> Sovite.AuthResults.authserv_id(" ; spf=pass")
      :error
  """
  @spec authserv_id(String.t()) :: {:ok, String.t()} | :error
  def authserv_id(value) do
    case value |> unfold() |> skip_cfws() |> read_value() do
      {:ok, id, _rest} -> {:ok, id}
      :error -> :error
    end
  end

  @doc """
  Removes every `Authentication-Results:` field whose authserv-id is
  `authserv_id`, compared without regard to case. Fields whose
  authserv-id cannot be read are kept.
  """
  @spec strip([Headers.field()], String.t()) :: [Headers.field()]
  def strip(fields, authserv_id) do
    ours = String.downcase(authserv_id, :ascii)

    Enum.reject(fields, fn
      {"authentication-results", raw} ->
        [_name, value] = :binary.split(raw, ":")

        case authserv_id(value) do
          {:ok, id} -> String.downcase(id, :ascii) == ours
          :error -> false
        end

      _ ->
        false
    end)
  end

  @doc """
  Parses a field value into its authserv-id and results.

  Comments and the version after the authserv-id are dropped, and so is
  a method version (`dkim/1`). Method, result and property names are
  lower-cased; values are kept as written. Parsing is lenient about
  what real servers send, such as unquoted base64 in `header.b`.

      iex> Sovite.AuthResults.parse("mx.example.org; spf=pass (ok) smtp.mailfrom=a@example.com")
      {:ok, "mx.example.org",
       [%{method: "spf", result: "pass", reason: nil, properties: [{"smtp.mailfrom", "a@example.com"}]}]}
  """
  @spec parse(String.t()) :: {:ok, String.t(), [result()]} | :error
  def parse(value) do
    with {:ok, id, rest} <- value |> unfold() |> skip_cfws() |> read_value(),
         {:ok, results} <- rest |> skip_version() |> results([]) do
      {:ok, id, results}
    end
  end

  defp skip_version(input) do
    rest = skip_cfws(input)

    case span(rest, &(&1 in ?0..?9)) do
      {"", _rest} -> rest
      {_version, rest} -> rest
    end
  end

  defp results(input, acc) do
    case skip_cfws(input) do
      "" ->
        {:ok, Enum.reverse(acc)}

      ";" <> rest ->
        case rest |> skip_cfws() |> resinfo() do
          {:ok, result, rest} -> results(rest, [result | acc])
          {:none, rest} -> results(rest, acc)
          :error -> :error
        end

      _ ->
        :error
    end
  end

  # "none" (no results) and an empty resinfo before a trailing ";" both
  # add nothing.
  defp resinfo(input) do
    {method, rest} = span(input, &keyword_char?/1)

    case rest |> skip_method_version() |> skip_cfws() do
      "=" <> rest when method != "" ->
        case rest |> skip_cfws() |> span(&keyword_char?/1) do
          {"", _rest} ->
            :error

          {result, rest} ->
            result = %{method: lower(method), result: lower(result), reason: nil, properties: []}
            specs(rest, result)
        end

      rest when method == "" ->
        {:none, rest}

      rest ->
        if lower(method) == "none", do: {:none, rest}, else: :error
    end
  end

  defp skip_method_version(input) do
    case skip_cfws(input) do
      "/" <> rest -> rest |> skip_cfws() |> span(&(&1 in ?0..?9)) |> elem(1)
      _ -> input
    end
  end

  defp specs(input, result) do
    case skip_cfws(input) do
      rest when rest == "" or binary_part(rest, 0, 1) == ";" ->
        {:ok, %{result | properties: Enum.reverse(result.properties)}, rest}

      rest ->
        {name, rest} = span(rest, &(&1 not in ~c" \t\r\n;(=\""))

        spec(name, skip_cfws(rest), result)
    end
  end

  defp spec("", _rest, _result), do: :error

  defp spec(name, "=" <> rest, result) do
    with {:ok, value, rest} <- rest |> skip_cfws() |> read_pvalue() do
      specs(rest, add_spec(result, lower(name), value))
    end
  end

  # A stray word: ignored.
  defp spec(_name, rest, result), do: specs(rest, result)

  defp add_spec(result, "reason", value), do: %{result | reason: value}

  defp add_spec(result, name, value),
    do: %{result | properties: [{name, value} | result.properties]}

  # A quoted local-part followed by "@domain" is an address, kept as
  # written; a quoted-string alone is unquoted.
  defp read_pvalue(~s(") <> quoted = input) do
    with {:ok, value, rest} <- read_quoted(quoted, []) do
      case rest do
        "@" <> _ ->
          {:ok, domain, rest} = read_pvalue(rest)
          local = binary_part(input, 0, byte_size(input) - byte_size(rest) - byte_size(domain))
          {:ok, local <> domain, rest}

        _ ->
          {:ok, value, rest}
      end
    end
  end

  defp read_pvalue(input) do
    {value, rest} = span(input, &(&1 not in ~c" \t\r\n;(\""))
    {:ok, value, rest}
  end

  # An RFC 2045 value: token or quoted-string.
  defp read_value(~s(") <> rest), do: read_quoted(rest, [])

  defp read_value(input) do
    case span(input, &token_char?/1) do
      {"", _rest} -> :error
      {token, rest} -> {:ok, token, rest}
    end
  end

  defp read_quoted(~s(") <> rest, acc),
    do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary(), rest}

  defp read_quoted(<<?\\, c, rest::binary>>, acc), do: read_quoted(rest, [c | acc])
  defp read_quoted(<<c, rest::binary>>, acc), do: read_quoted(rest, [c | acc])
  defp read_quoted("", _acc), do: :error

  defp token_char?(c), do: c in 0x21..0x7E and c not in ~c"()<>@,;:\\\"/[]?="

  defp keyword_char?(c), do: c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c in ~c"-_"

  defp lower(text), do: String.downcase(text, :ascii)

  defp span(input, fun), do: span(input, fun, 0)

  defp span(input, fun, n) do
    case input do
      <<_::binary-size(^n), c, _::binary>> ->
        if fun.(c), do: span(input, fun, n + 1), else: split_at(input, n)

      _ ->
        split_at(input, n)
    end
  end

  defp split_at(input, n),
    do: {binary_part(input, 0, n), binary_part(input, n, byte_size(input) - n)}

  # Unfolding removes the CRLF before continuation whitespace (RFC 5322 §2.2.3).
  defp unfold(value), do: String.replace(value, ~r/\r\n(?=[ \t])/, "")

  defp skip_cfws(<<c, rest::binary>>) when c in ~c" \t\r\n", do: skip_cfws(rest)
  defp skip_cfws("(" <> rest), do: rest |> skip_comment(1) |> skip_cfws()
  defp skip_cfws(rest), do: rest

  # Comments nest; an unterminated one runs to the end.
  defp skip_comment(rest, 0), do: rest
  defp skip_comment("", _depth), do: ""
  defp skip_comment(<<?\\, _, rest::binary>>, depth), do: skip_comment(rest, depth)
  defp skip_comment("(" <> rest, depth), do: skip_comment(rest, depth + 1)
  defp skip_comment(")" <> rest, depth), do: skip_comment(rest, depth - 1)
  defp skip_comment(<<_, rest::binary>>, depth), do: skip_comment(rest, depth)
end
