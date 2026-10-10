defmodule Sovite.Message.Received do
  @moduledoc """
  Builds `Received:` trace header fields (RFC 5321 §4.4).

      Received: from client.example.net ([192.0.2.7])
              by mx.example.com with ESMTP id 0Q7c3XbK2mA9fZ
              for <user@example.com>; Sun, 4 Oct 2026 12:00:00 +0000

  The `with` value is an RFC 3848 or RFC 6531 transmission type, see
  `protocol/1`.
  Values are inserted as given, so they must already be validated: the
  `EHLO` name as a domain or address literal, the recipient as a mailbox.
  """

  alias Sovite.Message.Date

  @type fields :: %{
          required(:helo) => String.t(),
          required(:remote_ip) => :inet.ip_address(),
          required(:by) => String.t(),
          required(:protocol) => String.t(),
          optional(:id) => String.t() | nil,
          optional(:for) => String.t() | nil,
          optional(:date) => DateTime.t(),
          optional(:tls) => String.t() | nil
        }

  @doc """
  Returns the complete header field, ending in CRLF.

  `:for` is the recipient to show. Leave it out for messages with several
  recipients, so they are not disclosed to each other. `:date` defaults to
  now. `:tls` describes the encryption, as `Sovite.TLS.describe/1` does,
  and is shown in a comment like Postfix does:

      Received: from client.example.net ([192.0.2.7])
              (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits))
              by mx.example.com with ESMTPS id 0Q7c3XbK2mA9fZ; ...
  """
  @spec build(fields()) :: String.t()
  def build(fields) do
    date = Map.get_lazy(fields, :date, &DateTime.utc_now/0)

    id = if fields[:id], do: " id #{fields.id}", else: ""
    recipient = if fields[:for], do: "\r\n\tfor <#{fields.for}>", else: ""

    tls = if fields[:tls], do: "\t(using #{fields.tls})\r\n", else: ""

    "Received: from #{fields.helo} (#{address_literal(fields.remote_ip)})\r\n" <>
      tls <>
      "\tby #{fields.by} with #{fields.protocol}#{id}#{recipient}; #{Date.format(date)}\r\n"
  end

  @doc """
  Returns the transmission type for a session: RFC 3848's, or with
  `utf8: true` (a transaction with `SMTPUTF8`) RFC 6531's.

      iex> Sovite.Message.Received.protocol(esmtp: true, tls: true)
      "ESMTPS"
      iex> Sovite.Message.Received.protocol(esmtp: false)
      "SMTP"
      iex> Sovite.Message.Received.protocol(lmtp: true, auth: true)
      "LMTPA"
      iex> Sovite.Message.Received.protocol(esmtp: true, tls: true, utf8: true)
      "UTF8SMTPS"
  """
  @spec protocol(keyword()) :: String.t()
  def protocol(opts) do
    base =
      cond do
        opts[:lmtp] -> "LMTP"
        opts[:esmtp] -> "ESMTP"
        true -> "SMTP"
      end

    # RFC 3848 and RFC 6531 types only exist for the extended protocols.
    if base == "SMTP",
      do: base,
      else:
        utf8(base, opts[:utf8]) <>
          if(opts[:tls], do: "S", else: "") <> if(opts[:auth], do: "A", else: "")
  end

  defp utf8("ESMTP", true), do: "UTF8SMTP"
  defp utf8("LMTP", true), do: "UTF8LMTP"
  defp utf8(base, _utf8), do: base

  @doc """
  Formats an IP address as an RFC 5321 address literal.

      iex> Sovite.Message.Received.address_literal({192, 0, 2, 7})
      "[192.0.2.7]"
      iex> Sovite.Message.Received.address_literal({8193, 3512, 0, 0, 0, 0, 0, 1})
      "[IPv6:2001:db8::1]"
  """
  @spec address_literal(:inet.ip_address()) :: String.t()
  def address_literal(ip) when tuple_size(ip) == 4, do: "[#{:inet.ntoa(ip)}]"
  def address_literal(ip), do: "[IPv6:#{:inet.ntoa(ip)}]"
end
