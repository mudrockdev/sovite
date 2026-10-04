defmodule Sovite.Message.Trace do
  @moduledoc """
  Trace header fields and the loop checks that read them.

    * `Return-Path:` - added at final delivery with the envelope sender
      (RFC 5321 §4.4).
    * `Delivered-To:` - added at final delivery with the recipient
      (RFC 9228). A message that already carries one for the same
      recipient has been here before: a mail loop.
    * `Received:` - one per hop. Too many of them is a loop too
      (RFC 5321 §6.3).

  Header fields are as returned by `Sovite.Message.Headers.parse/1`.
  """

  alias Sovite.Message.Headers

  @doc """
  The `Return-Path:` field for `sender` (`""` for the null reverse-path).

      iex> Sovite.Message.Trace.return_path("alice@example.com")
      "Return-Path: <alice@example.com>\\r\\n"
  """
  @spec return_path(String.t()) :: String.t()
  def return_path(sender), do: "Return-Path: <#{sender}>\r\n"

  @doc """
  The `Delivered-To:` field for `recipient`.

      iex> Sovite.Message.Trace.delivered_to("bob@example.com")
      "Delivered-To: bob@example.com\\r\\n"
  """
  @spec delivered_to(String.t()) :: String.t()
  def delivered_to(recipient), do: "Delivered-To: #{recipient}\r\n"

  @doc "The number of `Received:` fields."
  @spec hops([Headers.field()]) :: non_neg_integer()
  def hops(fields), do: Enum.count(fields, &match?({"received", _}, &1))

  @doc """
  Whether a `Delivered-To:` field names `recipient`, compared without
  regard to case.
  """
  @spec delivered_to?([Headers.field()], String.t()) :: boolean()
  def delivered_to?(fields, recipient) do
    recipient = String.downcase(recipient)

    Enum.any?(fields, fn
      {"delivered-to", raw} -> String.downcase(value(raw)) == recipient
      _ -> false
    end)
  end

  defp value(raw) do
    [_name, value] = :binary.split(raw, ":")
    value |> String.replace(~r/\r\n[ \t]+/, " ") |> String.trim()
  end
end
