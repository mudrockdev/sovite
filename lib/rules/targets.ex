defmodule Sovite.Rules.Targets do
  @moduledoc false
  # What a rule matches (its `match` key) and the values of a message for
  # it. See Sovite.Rules.

  alias Sovite.{Analyzer, MIME}
  alias Sovite.Message.Headers
  alias Sovite.MIME.EncodedWord

  @type t ::
          {:header | :raw_header | :mime_header, String.t()}
          | :headers
          | :subject
          | :text
          | :hidden_text
          | :html
          | :body
          | :url
          | :url_host
          | :address
          | :attachment_name
          | :attachment_type
          | :attachment_hash
          | :ip
          | :hostname
          | :helo
          | :from
          | :from_domain
          | :rcpt
          | :rcpt_domain
          | :user

  @fixed %{
    "headers" => :headers,
    "subject" => :subject,
    "text" => :text,
    "hidden_text" => :hidden_text,
    "html" => :html,
    "body" => :body,
    "url" => :url,
    "url_host" => :url_host,
    "address" => :address,
    "attachment_name" => :attachment_name,
    "attachment_type" => :attachment_type,
    "attachment_hash" => :attachment_hash,
    "ip" => :ip,
    "hostname" => :hostname,
    "helo" => :helo,
    "from" => :from,
    "from_domain" => :from_domain,
    "rcpt" => :rcpt,
    "rcpt_domain" => :rcpt_domain,
    "user" => :user
  }

  @fields %{"header" => :header, "raw_header" => :raw_header, "mime_header" => :mime_header}

  @spec parse(String.t()) :: {:ok, t()} | :error
  def parse(text) do
    case String.split(text, ":", parts: 2) do
      [kind, name] when is_map_key(@fields, kind) ->
        if name =~ ~r/\A[\x21-\x39\x3b-\x7e]+\z/,
          do: {:ok, {@fields[kind], String.downcase(name, :ascii)}},
          else: :error

      [name] ->
        Map.fetch(@fixed, name)

      _ ->
        :error
    end
  end

  @doc false
  def names, do: Map.keys(@fixed) ++ Enum.map(Map.keys(@fields), &(&1 <> ":<Name>"))

  # The values of `target`: valid UTF-8, each at most `max` bytes.
  @spec values(t(), Analyzer.t(), map()) :: [String.t()]
  def values(target, analysis, input) do
    target
    |> raw_values(analysis, input)
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&cap(&1, input.max_value))
  end

  defp raw_values({:header, name}, analysis, _input), do: fields(analysis.mime, name, true)
  defp raw_values({:raw_header, name}, analysis, _input), do: fields(analysis.mime, name, false)

  defp raw_values({:mime_header, name}, analysis, _input),
    do: analysis.mime |> MIME.flatten() |> Enum.flat_map(&fields(&1, name, true))

  defp raw_values(:headers, analysis, _input),
    do: [analysis.mime.headers |> Headers.encode() |> IO.iodata_to_binary()]

  defp raw_values(:subject, analysis, _input), do: [analysis.subject]
  defp raw_values(:text, analysis, _input), do: Enum.map(analysis.texts, & &1.text)

  defp raw_values(:hidden_text, analysis, _input),
    do: for(%{hidden_text: text} <- analysis.texts, text != "", do: text)

  defp raw_values(:html, analysis, _input),
    do: for(%{type: "text/html", text: text} <- MIME.leaves(analysis.mime), do: text)

  defp raw_values(:body, _analysis, %{raw: nil}), do: []

  defp raw_values(:body, _analysis, %{raw: raw}) do
    case :binary.match(raw, ["\r\n\r\n", "\n\n"]) do
      {at, length} -> [binary_part(raw, at + length, byte_size(raw) - at - length)]
      :nomatch -> []
    end
  end

  defp raw_values(:url, analysis, _input), do: Enum.map(analysis.urls, & &1.url.url)

  defp raw_values(:url_host, analysis, _input),
    do: analysis.urls |> Enum.map(& &1.url.host) |> Enum.uniq()

  defp raw_values(:address, analysis, _input), do: analysis.addresses

  defp raw_values(:attachment_name, analysis, _input),
    do: Enum.map(analysis.attachments, & &1.filename)

  defp raw_values(:attachment_type, analysis, _input) do
    for attachment <- analysis.attachments,
        do: if(attachment.detected, do: attachment.detected.type, else: attachment.declared)
  end

  defp raw_values(:attachment_hash, analysis, _input) do
    for part <- MIME.leaves(analysis.mime),
        MIME.attachment?(part),
        do: Base.encode16(:crypto.hash(:sha256, part.body || ""), case: :lower)
  end

  defp raw_values(:from_domain, _analysis, input), do: [domain(input.envelope[:from])]

  defp raw_values(:rcpt, _analysis, input), do: input.envelope[:rcpts] || []

  defp raw_values(:rcpt_domain, _analysis, input),
    do: (input.envelope[:rcpts] || []) |> Enum.map(&domain/1) |> Enum.uniq()

  defp raw_values(key, _analysis, input) when key in [:ip, :hostname, :helo, :from, :user],
    do: [input.envelope[key]]

  defp fields(part, name, decode?) do
    for {^name, raw} <- part.headers do
      [_name, value] = :binary.split(raw, ":")
      value = value |> String.replace(~r/\r?\n(?=[ \t])/, "") |> String.trim()
      if decode?, do: EncodedWord.decode(value), else: value
    end
  end

  defp domain(nil), do: nil

  defp domain(address) do
    case String.split(address, "@") do
      [_] -> nil
      parts -> String.downcase(List.last(parts))
    end
  end

  defp cap(value, max) when byte_size(value) > max,
    do: value |> binary_part(0, max) |> String.replace_invalid()

  defp cap(value, _max), do: String.replace_invalid(value)
end
