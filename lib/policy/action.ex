defmodule Sovite.Policy.Action do
  @moduledoc """
  Policy server actions: the value of the `action` attribute of a reply,
  as in a Postfix access(5) table.

  `parse/1` turns an action into a term and `encode/1` turns a term back
  into an action. Keywords are case-insensitive and separated from their
  argument by spaces or tabs; surrounding whitespace is ignored.

  | Action | Term | Meaning |
  |---|---|---|
  | `OK` | `:ok` | Accept. |
  | all-numerical, such as `1730000000` | `:ok` | Accept (access(5); used by pop-before-smtp). |
  | `DUNNO` | `:dunno` | No decision: go on with the next restriction. |
  | `REJECT [text]` | `{:reject, text}` | Reject with the default reject code. |
  | `DEFER [text]` | `{:defer, text}` | Reject with a temporary error. |
  | `DEFER_IF_REJECT [text]` | `{:defer_if_reject, text}` | Defer if a later restriction rejects. |
  | `DEFER_IF_PERMIT [text]` | `{:defer_if_permit, text}` | Defer if a later restriction accepts. |
  | `4NN [x.y.z] [text]`, `5NN [x.y.z] [text]` | `{:reply, code, enhanced, text}` | Reject with this reply. |
  | `HOLD [text]` | `{:hold, text}` | Accept, but put the message on hold. |
  | `DISCARD [text]` | `{:discard, text}` | Accept, then discard the message. |
  | `WARN [text]` | `{:warn, text}` | Log a warning, no decision. |
  | `INFO [text]` | `{:info, text}` | Log a note, no decision. |
  | `PREPEND name: value` | `{:prepend, header}` | Add a header field to the message. |
  | `REDIRECT user@domain` | `{:redirect, address}` | Send the message to this address instead. |
  | `BCC user@domain` | `{:bcc, address}` | Send a copy to this address. |
  | `FILTER transport:destination` | `{:filter, destination}` | Deliver through this content filter. |

  An optional `text` is `nil` when absent. It may start with an RFC 3463
  enhanced status code (`REJECT 5.7.1 Go away`), which is left in the
  text. Text after `OK` and `DUNNO` is ignored.

  For `4NN` and `5NN` replies, `code` is from 400 to 599 and `enhanced`
  an enhanced status code of the same class (`"5.7.1"` for `550`), or
  `nil`. Unlike Postfix, which accepts a bare all-numerical `450` or
  `550` as `OK`, a bare reject code is a reply without text.

  Restriction names (`permit`, `reject_unauth_destination`, ...) are not
  supported. Anything else is `{:error, :invalid_action}`.
  """

  @typedoc "An optional text, `nil` when absent."
  @type text :: String.t() | nil

  @typedoc "A parsed action, see the module docs."
  @type t ::
          :ok
          | :dunno
          | {:reject, text()}
          | {:defer, text()}
          | {:defer_if_reject, text()}
          | {:defer_if_permit, text()}
          | {:reply, 400..599, enhanced :: String.t() | nil, text()}
          | {:hold, text()}
          | {:discard, text()}
          | {:warn, text()}
          | {:info, text()}
          | {:prepend, header :: String.t()}
          | {:redirect, address :: String.t()}
          | {:bcc, address :: String.t()}
          | {:filter, destination :: String.t()}

  @texts %{
    "REJECT" => :reject,
    "DEFER" => :defer,
    "DEFER_IF_REJECT" => :defer_if_reject,
    "DEFER_IF_PERMIT" => :defer_if_permit,
    "HOLD" => :hold,
    "DISCARD" => :discard,
    "WARN" => :warn,
    "INFO" => :info
  }

  @arguments %{
    "PREPEND" => :prepend,
    "REDIRECT" => :redirect,
    "BCC" => :bcc,
    "FILTER" => :filter
  }

  @keywords Map.new(Map.merge(@texts, @arguments), fn {word, kind} -> {kind, word} end)

  @header ~r/\A[\x21-\x39\x3b-\x7e]+:/
  @enhanced ~r/\A([245])\.\d{1,3}\.\d{1,3}\z/

  @doc """
  Parses an action, see the module docs.

      iex> Sovite.Policy.Action.parse("defer_if_permit Greylisted")
      {:ok, {:defer_if_permit, "Greylisted"}}

      iex> Sovite.Policy.Action.parse("550 5.7.23 SPF fail")
      {:ok, {:reply, 550, "5.7.23", "SPF fail"}}

      iex> Sovite.Policy.Action.parse("PREPEND Received-SPF: pass")
      {:ok, {:prepend, "Received-SPF: pass"}}

      iex> Sovite.Policy.Action.parse("REDIRECT")
      {:error, :invalid_action}
  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, :invalid_action}
  def parse(action) when is_binary(action) do
    {word, rest} = split(trim(action))

    case parse(String.upcase(word, :ascii), word, rest) do
      {:ok, _action} = ok -> ok
      _ -> {:error, :invalid_action}
    end
  end

  def parse(_action), do: {:error, :invalid_action}

  defp parse("OK", _word, _rest), do: {:ok, :ok}
  defp parse("DUNNO", _word, _rest), do: {:ok, :dunno}

  defp parse(upper, word, rest) do
    cond do
      Map.has_key?(@texts, upper) -> {:ok, {Map.fetch!(@texts, upper), text(rest)}}
      Map.has_key?(@arguments, upper) -> argument(Map.fetch!(@arguments, upper), rest)
      word =~ ~r/\A[45]\d\d\z/ -> reply(String.to_integer(word), rest)
      word =~ ~r/\A\d+\z/ and rest == "" -> {:ok, :ok}
      true -> :error
    end
  end

  defp argument(:prepend, header) do
    if Regex.match?(@header, header), do: {:ok, {:prepend, header}}, else: :error
  end

  defp argument(kind, address) when kind in [:redirect, :bcc] do
    if Sovite.Validators.mailbox?(address, utf8: true), do: {:ok, {kind, address}}, else: :error
  end

  defp argument(:filter, destination) do
    case :binary.split(destination, ":") do
      [transport, _next_hop] when transport != "" ->
        if String.contains?(transport, [" ", "\t"]),
          do: :error,
          else: {:ok, {:filter, destination}}

      _ ->
        :error
    end
  end

  defp reply(code, rest) do
    {first, after_first} = split(rest)

    case Regex.run(@enhanced, first) do
      [enhanced, class] ->
        if class == Integer.to_string(div(code, 100)),
          do: {:ok, {:reply, code, enhanced, text(after_first)}},
          else: :error

      nil ->
        if first =~ ~r/\A\d+\.\d+\.\d+\z/,
          do: :error,
          else: {:ok, {:reply, code, nil, text(rest)}}
    end
  end

  defp text(""), do: nil
  defp text(text), do: text

  # The first word, and the rest without its leading whitespace.
  defp split(string) do
    case Regex.run(~r/\A([^ \t]*)[ \t]*(.*)\z/s, string) do
      [_all, word, rest] -> {word, rest}
    end
  end

  defp trim(string), do: Regex.replace(~r/\A[ \t]+|[ \t]+\z/, string, "")

  @doc """
  Encodes an action term as action text, the reverse of `parse/1`.
  Carriage returns and newlines in texts are replaced by spaces.

  Raises `ArgumentError` for a term that is not an action: an unknown
  term, a reply code outside 400..599, an enhanced status code of another
  class, or a `PREPEND`, `REDIRECT`, `BCC`, or `FILTER` argument that
  `parse/1` would refuse.

      iex> Sovite.Policy.Action.encode({:reply, 450, "4.7.1", "Try later"})
      "450 4.7.1 Try later"

      iex> Sovite.Policy.Action.encode({:reject, nil})
      "REJECT"
  """
  @spec encode(t()) :: String.t()
  def encode(:ok), do: "OK"
  def encode(:dunno), do: "DUNNO"

  def encode({:reply, code, enhanced, text} = action)
      when code in 400..599 and (is_binary(enhanced) or is_nil(enhanced)) and
             (is_binary(text) or is_nil(text)) do
    encoded = join([Integer.to_string(code), enhanced, text])

    case parse(encoded) do
      {:ok, {:reply, ^code, parsed, _text}} when enhanced in [nil, parsed] -> encoded
      _ -> invalid(action)
    end
  end

  def encode({kind, text} = action) when is_atom(kind) and (is_binary(text) or is_nil(text)) do
    with {:ok, word} <- Map.fetch(@keywords, kind),
         encoded = join([word, text]),
         {:ok, {^kind, _text}} <- parse(encoded) do
      encoded
    else
      _ -> invalid(action)
    end
  end

  def encode(action), do: invalid(action)

  defp join(parts) do
    parts
    |> Enum.reject(&(&1 in [nil, ""]))
    |> Enum.join(" ")
    |> String.replace(["\r", "\n"], " ")
  end

  defp invalid(action), do: raise(ArgumentError, "not a policy action: #{inspect(action)}")
end
