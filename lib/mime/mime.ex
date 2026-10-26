defmodule Sovite.MIME do
  @moduledoc """
  The MIME structure of a message (RFC 2045, 2046, 2183, 2231): its parts,
  nested, each with its header fields, type, parameters, file name, and
  decoded content, and the text of text parts in UTF-8.

      part = Sovite.MIME.parse(message)
      for leaf <- Sovite.MIME.leaves(part), leaf.text, do: leaf.text

  Parsing never fails: a filter must look at whatever comes, and broken
  structure is itself a sign of spam. What does not follow the rules, or
  goes over a limit, is noted as an anomaly of the part it was found in
  (see `t:anomaly/0`), and parsing goes on as far as it can.

  ## Limits

    * `:max_depth` - how deep parts nest (multiparts and attached
      messages). Defaults to 20. Deeper parts are not parsed.
    * `:max_parts` - parts in all. Defaults to 500. Parts after the limit
      are not parsed.
    * `:max_size` - decoded content in all, in bytes. Defaults to 32 MiB.
      Content past it is cut.
    * `:max_header` - the header section of one part, in bytes. Defaults
      to 64 KiB. Fields past it are left out.

  Line endings may be CRLF or LF.
  """

  alias Sovite.Charset
  alias Sovite.Message.Headers
  alias Sovite.MIME.{EncodedWord, Params, Transfer}

  @typedoc """
  Something wrong with a part:

    * `:no_boundary` - a multipart without a `boundary` parameter: taken
      as text.
    * `:no_parts` - a multipart in which the boundary never appears.
    * `:unclosed` - a multipart without its closing boundary.
    * `:damaged_encoding` - base64 or quoted-printable that does not
      decode cleanly.
    * `:unknown_charset` - a text part in a charset `Sovite.Charset` does
      not know: taken as UTF-8, or windows-1252.
    * `:unknown_encoding` - a `Content-Transfer-Encoding` that is not one
      RFC 2045 defines: the content is taken as it is.
    * `:encoded_composite` - a multipart or message with a transfer
      encoding other than 7bit, 8bit, or binary (RFC 2045 §6.4 forbids
      it; it is decoded anyway).
    * `:depth_limit`, `:part_limit`, `:size_limit`, `:header_limit` -
      a limit cut the part short.
  """
  @type anomaly ::
          :no_boundary
          | :no_parts
          | :unclosed
          | :damaged_encoding
          | :unknown_charset
          | :unknown_encoding
          | :encoded_composite
          | :depth_limit
          | :part_limit
          | :size_limit
          | :header_limit

  defstruct headers: [],
            type: "text/plain",
            params: %{},
            disposition: nil,
            filename: nil,
            encoding: nil,
            body: nil,
            text: nil,
            parts: [],
            anomalies: []

  @typedoc """
  A part. `type` is the lower-cased media type, `params` its parameters;
  `disposition` (`"inline"`, `"attachment"`, or `nil`) and `filename` are
  from `Content-Disposition:` (or the type's `name`). `body` is the
  decoded content of a part that is not a multipart or a message, and
  `text` its text in UTF-8 when it is a `text/*` part. `parts` are the
  parts of a multipart, or the message inside a `message/rfc822` (or
  `message/global`) part.
  """
  @type t :: %__MODULE__{
          headers: [Headers.field()],
          type: String.t(),
          params: %{String.t() => String.t()},
          disposition: String.t() | nil,
          filename: String.t() | nil,
          encoding: String.t() | nil,
          body: binary() | nil,
          text: String.t() | nil,
          parts: [t()],
          anomalies: [anomaly()]
        }

  @defaults [max_depth: 20, max_parts: 500, max_size: 32 * 1024 * 1024, max_header: 64 * 1024]
  @encodings ~w(7bit 8bit binary base64 quoted-printable)

  @doc "Parses a message (header section and body). See the module docs."
  @spec parse(binary(), keyword()) :: t()
  def parse(message, opts \\ []) when is_binary(message) do
    limits = Map.new(Keyword.merge(@defaults, opts))
    state = %{parts: 0, size: 0, limits: limits}
    {part, _state} = entity(crlf(message), 0, "text/plain", state)
    part
  end

  @doc "The parts that are not multiparts or messages, in order, depth first."
  @spec leaves(t()) :: [t()]
  def leaves(%__MODULE__{parts: []} = part), do: if(composite?(part), do: [], else: [part])
  def leaves(%__MODULE__{parts: parts}), do: Enum.flat_map(parts, &leaves/1)

  @doc "Every part, the root first, depth first."
  @spec flatten(t()) :: [t()]
  def flatten(%__MODULE__{parts: parts} = part), do: [part | Enum.flat_map(parts, &flatten/1)]

  @doc "The anomalies of every part."
  @spec anomalies(t()) :: [anomaly()]
  def anomalies(part), do: part |> flatten() |> Enum.flat_map(& &1.anomalies)

  @doc "Whether a part is an attachment: so disposed, or with a file name and not inline text."
  @spec attachment?(t()) :: boolean()
  def attachment?(%__MODULE__{disposition: "attachment"}), do: true

  def attachment?(%__MODULE__{filename: name, disposition: disposition, type: type}),
    do: name != nil and not (disposition == "inline" and String.starts_with?(type, "text/"))

  defp composite?(%{type: "multipart/" <> _}), do: true
  defp composite?(%{type: type}), do: type in ["message/rfc822", "message/global"]

  # Bare LF line endings become CRLF, which Sovite.Message.Headers needs.
  defp crlf(data) do
    if :binary.match(data, "\n") == :nomatch or not bare_lf?(data),
      do: data,
      else: Regex.replace(~r/(?<!\r)\n/, data, "\r\n")
  end

  defp bare_lf?(data), do: Regex.match?(~r/(?<!\r)\n/, data)

  ## Entities

  defp entity(data, depth, default_type, state) do
    state = %{state | parts: state.parts + 1}

    cond do
      state.parts > state.limits.max_parts ->
        {%__MODULE__{anomalies: [:part_limit]}, state}

      depth > state.limits.max_depth ->
        {%__MODULE__{anomalies: [:depth_limit]}, state}

      true ->
        {fields, body, anomalies} = split_header(data, state.limits.max_header)
        part = describe(fields, default_type, anomalies)
        content(part, body, depth, state)
    end
  end

  defp split_header(data, max) do
    {header, body} =
      case Headers.split(data) do
        {:ok, header, body} -> {header, body}
        # No empty line: only a header section.
        :more -> {data, ""}
      end

    if byte_size(header) > max do
      # Whole lines only.
      cut = binary_part(header, 0, max)

      kept =
        case :binary.matches(cut, "\r\n") do
          [] -> ""
          matches -> binary_part(cut, 0, elem(List.last(matches), 0) + 2)
        end

      {Headers.parse(kept), body, [:header_limit]}
    else
      {Headers.parse(header), body, []}
    end
  end

  defp describe(fields, default_type, anomalies) do
    {type, params} =
      case Headers.get(fields, "content-type") do
        nil -> {default_type, %{}}
        value -> media_type(Params.parse(value), default_type)
      end

    {disposition, disposition_params} =
      case Headers.get(fields, "content-disposition") do
        nil -> {nil, %{}}
        value -> Params.parse(value)
      end

    encoding =
      case Headers.get(fields, "content-transfer-encoding") do
        nil -> nil
        value -> value |> String.trim() |> String.downcase(:ascii)
      end

    %__MODULE__{
      headers: fields,
      type: type,
      params: params,
      disposition: disposition,
      filename: disposition_params["filename"] || params["name"],
      encoding: encoding,
      anomalies: anomalies
    }
  end

  # A type without "/" is not one: the default (RFC 2045 §5.2).
  defp media_type({type, params}, default) when is_binary(type) do
    if Regex.match?(~r/\A[^\/\s]+\/[^\/\s]+\z/, type), do: {type, params}, else: {default, params}
  end

  defp media_type({nil, params}, default), do: {default, params}

  ## Content

  defp content(%{type: "multipart/" <> subtype} = part, body, depth, state) do
    case part.params["boundary"] do
      boundary when is_binary(boundary) and boundary != "" ->
        {body, part} = composite_body(part, body)
        multipart(part, body, boundary, subtype, depth, state)

      _ ->
        leaf(
          %{part | type: "text/plain", anomalies: [:no_boundary | part.anomalies]},
          body,
          state
        )
    end
  end

  defp content(%{type: type} = part, body, depth, state)
       when type in ["message/rfc822", "message/global"] do
    {body, part} = composite_body(part, body)
    {message, state} = entity(body, depth + 1, "text/plain", state)
    {%{part | parts: [message]}, state}
  end

  defp content(part, body, _depth, state), do: leaf(part, body, state)

  # Multiparts and messages must not be encoded, but are, by some.
  defp composite_body(%{encoding: encoding} = part, body)
       when encoding in [nil, "7bit", "8bit", "binary"],
       do: {body, part}

  defp composite_body(part, body) do
    {_result, decoded} = Transfer.decode(body, part.encoding)
    {crlf(decoded), %{part | anomalies: [:encoded_composite | part.anomalies]}}
  end

  defp multipart(part, body, boundary, subtype, depth, state) do
    default = if subtype == "digest", do: "message/rfc822", else: "text/plain"

    case split_parts(body, boundary) do
      {[], _closed} ->
        {%{part | anomalies: [:no_parts | part.anomalies]}, state}

      {bodies, closed} ->
        {parts, state} =
          Enum.map_reduce(bodies, state, fn body, state ->
            entity(body, depth + 1, default, state)
          end)

        anomalies = if closed, do: part.anomalies, else: [:unclosed | part.anomalies]
        {%{part | parts: parts, anomalies: anomalies}, state}
    end
  end

  # The parts between "--boundary" lines (RFC 2046 §5.1.1): a delimiter
  # starts a line, and may be followed by white space; "--boundary--" is
  # the last. The CRLF before a delimiter belongs to it.
  defp split_parts(body, boundary) do
    dash = "--" <> boundary

    delimiters =
      for {at, length} <- :binary.matches(body, dash),
          at == 0 or (at >= 2 and binary_part(body, at - 2, 2) == "\r\n"),
          {line_end, close} = delimiter_line(body, at + length),
          line_end != nil,
          do: {at, line_end, close}

    collect(body, delimiters, [])
  end

  # Where the delimiter's line ends, and whether it closes the multipart.
  defp delimiter_line(body, from) do
    rest = binary_part(body, from, byte_size(body) - from)

    {close, rest} =
      case rest do
        <<"--", rest::binary>> -> {true, rest}
        rest -> {false, rest}
      end

    # Transport padding: spaces and tabs.
    after_padding = skip_padding(rest)
    line_end = byte_size(body) - byte_size(after_padding)

    case after_padding do
      "" -> {line_end, close}
      <<"\r\n", _::binary>> -> {line_end + 2, close}
      _other -> {nil, close}
    end
  end

  defp skip_padding(<<c, rest::binary>>) when c in [?\s, ?\t], do: skip_padding(rest)
  defp skip_padding(rest), do: rest

  defp collect(_body, [], acc), do: {Enum.reverse(acc), false}

  defp collect(_body, [{_at, _end, true} | _], acc), do: {Enum.reverse(acc), true}

  defp collect(body, [{_at, line_end, false} | rest], acc) do
    case rest do
      [{next, _, _} | _] ->
        # Without the CRLF before the next delimiter.
        stop = max(next - 2, line_end)
        collect(body, rest, [binary_part(body, line_end, stop - line_end) | acc])

      [] ->
        {Enum.reverse([binary_part(body, line_end, byte_size(body) - line_end) | acc]), false}
    end
  end

  ## Leaves

  defp leaf(part, body, state) do
    room = max(state.limits.max_size - state.size, 0)
    # Encoded content is at most three times as long (quoted-printable):
    # no need to decode more.
    {body, cut} =
      if byte_size(body) > room * 3 + 8,
        do: {binary_part(body, 0, room * 3), true},
        else: {body, false}

    {result, decoded} = Transfer.decode(body, part.encoding)

    {decoded, cut} =
      if byte_size(decoded) > room,
        do: {binary_part(decoded, 0, room), true},
        else: {decoded, cut}

    anomalies =
      part.anomalies
      |> add_if(result == :damaged, :damaged_encoding)
      |> add_if(part.encoding not in [nil | @encodings], :unknown_encoding)
      |> add_if(cut, :size_limit)

    part = %{part | body: decoded, anomalies: anomalies}
    state = %{state | size: state.size + byte_size(decoded)}
    {text(part), state}
  end

  defp text(%{type: "text/" <> _, body: body} = part) do
    case part.params["charset"] do
      nil ->
        %{part | text: guess(body)}

      charset ->
        case Charset.to_utf8(body, charset) do
          {:ok, text} ->
            %{part | text: text}

          {:error, :unknown_charset} ->
            %{part | text: guess(body), anomalies: [:unknown_charset | part.anomalies]}
        end
    end
  end

  defp text(part), do: part

  # Without a known charset: UTF-8 when it is, else windows-1252.
  defp guess(body) do
    if String.valid?(body), do: body, else: elem(Charset.to_utf8(body, "windows-1252"), 1)
  end

  defp add_if(list, true, item), do: list ++ [item]
  defp add_if(list, false, _item), do: list

  @doc """
  A header field's value with encoded words decoded, in UTF-8 (see
  `Sovite.MIME.EncodedWord`), or `nil`.
  """
  @spec header(t(), String.t()) :: String.t() | nil
  def header(%__MODULE__{headers: fields}, name) do
    case Headers.get(fields, name) do
      nil -> nil
      value -> EncodedWord.decode(value)
    end
  end
end
