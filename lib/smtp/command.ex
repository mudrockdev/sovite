defmodule Sovite.SMTP.Command do
  @moduledoc """
  Parses SMTP command lines (RFC 5321 §4.1).

  The line is given without its CRLF. Verbs and parameter keywords are
  case-insensitive. Only printable ASCII is accepted. Verbs map to atoms
  from a fixed table; parameter keywords stay strings, upper-cased.

      iex> Sovite.SMTP.Command.parse("MAIL FROM:<a@example.com> SIZE=1024")
      {:ok, {:mail, "a@example.com", [{"SIZE", "1024"}]}}
      iex> Sovite.SMTP.Command.parse("RCPT TO:<@relay.example:b@example.net>")
      {:ok, {:rcpt, "b@example.net", []}}
      iex> Sovite.SMTP.Command.parse("rcpt to:<Postmaster>")
      {:ok, {:rcpt, "Postmaster", []}}

  Paths must be in angle brackets. Whitespace after `FROM:` and `TO:` is
  tolerated, since common clients send it. Source routes are accepted and
  ignored (RFC 5321 §4.1.1.3 and Appendix C). The mailbox is checked with
  `Sovite.Validators.split_mailbox/1`.
  """

  alias Sovite.SMTP.XText
  alias Sovite.Validators

  @type params :: [{String.t(), String.t() | nil}]

  @type t ::
          {:ehlo, String.t()}
          | {:helo, String.t()}
          | {:lhlo, String.t()}
          | {:mail, String.t(), params()}
          | {:rcpt, String.t(), params()}
          | :data
          | :rset
          | :quit
          | {:noop, String.t()}
          | {:vrfy, String.t()}
          | {:help, String.t()}
          | :starttls
          | {:auth, mechanism :: String.t(), initial_response :: String.t() | nil}
          | {:xclient, attributes()}
          | {:xforward, attributes()}

  @typedoc """
  `XCLIENT` and `XFORWARD` attributes: upper-cased names and decoded
  values, `nil` for `[UNAVAILABLE]` and `[TEMPUNAVAIL]`.
  """
  @type attributes :: [{String.t(), String.t() | nil}]

  @typedoc """
  Why a line did not parse:

    * `:unrecognized` - unknown verb
    * `:not_implemented` - a known SMTP verb this server does not support
    * `:non_smtp` - an HTTP request or header line, as in cross-protocol
      attacks
    * `:invalid_characters` - control or non-ASCII characters
    * `:syntax` - wrong arguments for the verb
    * `:invalid_sender` / `:invalid_recipient` - bad path or mailbox
    * `:invalid_parameter` - malformed `KEYWORD=value` parameter
  """
  @type error ::
          :unrecognized
          | :not_implemented
          | :non_smtp
          | :invalid_characters
          | :syntax
          | :invalid_sender
          | :invalid_recipient
          | :invalid_parameter

  @verbs %{
    "EHLO" => :ehlo,
    "HELO" => :helo,
    "LHLO" => :lhlo,
    "MAIL" => :mail,
    "RCPT" => :rcpt,
    "DATA" => :data,
    "RSET" => :rset,
    "QUIT" => :quit,
    "NOOP" => :noop,
    "VRFY" => :vrfy,
    "HELP" => :help,
    "STARTTLS" => :starttls,
    "AUTH" => :auth,
    "XCLIENT" => :xclient,
    "XFORWARD" => :xforward
  }

  @not_implemented ~w(EXPN TURN ETRN ATRN BDAT SEND SOML SAML)
  @http ~w(GET POST HEAD PUT DELETE OPTIONS CONNECT PATCH TRACE)

  @doc "Parses one command line. Returns the verb, if known, with errors."
  @spec parse(binary()) :: {:ok, t()} | {:error, atom() | nil, error()}
  def parse(line) when is_binary(line) do
    {verb, argument} = split_verb(line)

    cond do
      not printable?(line) -> {:error, Map.get(@verbs, verb), :invalid_characters}
      Map.has_key?(@verbs, verb) -> parse_verb(Map.fetch!(@verbs, verb), argument)
      verb in @not_implemented -> {:error, nil, :not_implemented}
      verb in @http or header_line?(verb) -> {:error, nil, :non_smtp}
      true -> {:error, nil, :unrecognized}
    end
  end

  # "Host: example.com", "User-Agent: ...": an HTTP request's header.
  defp header_line?(verb), do: verb =~ ~r/\A[A-Z0-9-]+:\z/

  defp split_verb(line) do
    case :binary.split(line, " ") do
      [verb, argument] -> {String.upcase(verb, :ascii), argument}
      [verb] -> {String.upcase(verb, :ascii), ""}
    end
  end

  defp printable?(line), do: for(<<c <- line>>, reduce: true, do: (acc -> acc and c in 32..126))

  defp parse_verb(verb, argument) when verb in [:ehlo, :helo, :lhlo] do
    case String.trim(argument) do
      "" -> {:error, verb, :syntax}
      domain -> {:ok, {verb, domain}}
    end
  end

  defp parse_verb(:mail, argument), do: parse_path(:mail, argument, "FROM:", :invalid_sender)
  defp parse_verb(:rcpt, argument), do: parse_path(:rcpt, argument, "TO:", :invalid_recipient)

  defp parse_verb(verb, argument) when verb in [:data, :rset, :quit, :starttls] do
    if String.trim(argument) == "", do: {:ok, verb}, else: {:error, verb, :syntax}
  end

  defp parse_verb(verb, argument) when verb in [:noop, :help],
    do: {:ok, {verb, String.trim(argument)}}

  defp parse_verb(:vrfy, argument) do
    case String.trim(argument) do
      "" -> {:error, :vrfy, :syntax}
      string -> {:ok, {:vrfy, string}}
    end
  end

  # AUTH mechanism [initial-response] (RFC 4954 §4). The response stays
  # base64; "=" stands for an empty one.
  defp parse_verb(:auth, argument) do
    case String.split(argument, " ") do
      [mechanism] -> auth(mechanism, nil)
      [mechanism, response] -> auth(mechanism, response)
      _ -> {:error, :auth, :syntax}
    end
  end

  # XCLIENT / XFORWARD name=value ..., values in xtext.
  defp parse_verb(verb, argument) when verb in [:xclient, :xforward] do
    argument
    |> String.split(" ", trim: true)
    |> Enum.reduce_while({:ok, []}, fn attribute, {:ok, acc} ->
      case attribute(attribute) do
        {:ok, pair} -> {:cont, {:ok, [pair | acc]}}
        :error -> {:halt, :error}
      end
    end)
    |> case do
      {:ok, [_ | _] = attributes} -> {:ok, {verb, Enum.reverse(attributes)}}
      _ -> {:error, verb, :syntax}
    end
  end

  ## Paths and parameters

  defp attribute(attribute) do
    with [name, value] <- :binary.split(attribute, "="),
         true <- String.match?(name, ~r/\A[A-Za-z]{1,20}\z/),
         {:ok, value} <- XText.decode(value) do
      value = if value in ["[UNAVAILABLE]", "[TEMPUNAVAIL]"], do: nil, else: value
      {:ok, {String.upcase(name, :ascii), value}}
    else
      _ -> :error
    end
  end

  defp auth(mechanism, response) do
    if String.match?(mechanism, ~r/\A[A-Za-z0-9_-]{1,20}\z/) and response != "",
      do: {:ok, {:auth, String.upcase(mechanism, :ascii), response}},
      else: {:error, :auth, :syntax}
  end

  defp parse_path(verb, argument, prefix, path_error) do
    size = byte_size(prefix)

    with <<keyword::binary-size(^size), rest::binary>> <- argument,
         true <- String.upcase(keyword, :ascii) == prefix,
         {:ok, path, rest} <- bracketed(String.trim_leading(rest, " ")),
         {:ok, mailbox} <- mailbox(verb, path) do
      case parse_params(rest) do
        {:ok, params} -> {:ok, {verb, mailbox, params}}
        :error -> {:error, verb, :invalid_parameter}
      end
    else
      {:error, :mailbox} -> {:error, verb, path_error}
      {:error, :brackets} -> {:error, verb, path_error}
      _ -> {:error, verb, :syntax}
    end
  end

  # Returns what is inside <...> and the rest. ">" inside a quoted local
  # part does not close the path.
  defp bracketed(<<?<, rest::binary>>), do: scan_path(rest, false, 0, rest)
  defp bracketed(_), do: {:error, :brackets}

  defp scan_path(<<?>, rest::binary>>, false, length, start),
    do: {:ok, binary_part(start, 0, length), rest}

  defp scan_path(<<?\\, _, rest::binary>>, true, length, start),
    do: scan_path(rest, true, length + 2, start)

  defp scan_path(<<?", rest::binary>>, quoted, length, start),
    do: scan_path(rest, not quoted, length + 1, start)

  defp scan_path(<<_, rest::binary>>, quoted, length, start),
    do: scan_path(rest, quoted, length + 1, start)

  defp scan_path(<<>>, _quoted, _length, _start), do: {:error, :brackets}

  defp mailbox(:mail, ""), do: {:ok, ""}

  defp mailbox(:rcpt, path) when byte_size(path) == 10 do
    if String.downcase(path, :ascii) == "postmaster", do: {:ok, path}, else: checked(path)
  end

  defp mailbox(_verb, <<?@, _::binary>> = path) do
    # A-d-l ":" Mailbox. Only the mailbox matters.
    with [route, mailbox] <- :binary.split(path, ":"),
         true <- route |> String.split(",") |> Enum.all?(&route_hop?/1) do
      checked(mailbox)
    else
      _ -> {:error, :mailbox}
    end
  end

  defp mailbox(_verb, path), do: checked(path)

  defp route_hop?(<<?@, domain::binary>>), do: Validators.domain?(domain)
  defp route_hop?(_), do: false

  defp checked(mailbox) do
    case Validators.split_mailbox(mailbox) do
      {:ok, _} -> {:ok, mailbox}
      {:error, _} -> {:error, :mailbox}
    end
  end

  defp parse_params(rest) do
    case String.trim(rest, " ") do
      "" ->
        {:ok, []}

      # Parameters must be separated from the path by a space.
      _ when binary_part(rest, 0, 1) != " " ->
        :error

      trimmed ->
        trimmed
        |> String.split(" ", trim: true)
        |> Enum.reduce_while({:ok, []}, &collect_param/2)
        |> case do
          {:ok, params} -> {:ok, Enum.reverse(params)}
          :error -> :error
        end
    end
  end

  defp collect_param(param, {:ok, acc}) do
    case parse_param(param) do
      {:ok, pair} -> {:cont, {:ok, [pair | acc]}}
      :error -> {:halt, :error}
    end
  end

  # esmtp-keyword = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
  # esmtp-value   = 1*(%d33-60 / %d62-126)
  defp parse_param(param) do
    {keyword, value} =
      case :binary.split(param, "=") do
        [keyword, value] -> {keyword, value}
        [keyword] -> {keyword, nil}
      end

    if String.match?(keyword, ~r/\A[A-Za-z0-9][A-Za-z0-9-]*\z/) and
         (value == nil or String.match?(value, ~r/\A[\x21-\x3c\x3e-\x7e]+\z/)),
       do: {:ok, {String.upcase(keyword, :ascii), value}},
       else: :error
  end
end
