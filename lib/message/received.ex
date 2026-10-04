defmodule Sovite.Message.Received do
  @moduledoc """
  Builds `Received:` trace header fields (RFC 5321 §4.4).

      Received: from client.example.net ([192.0.2.7])
              by mx.example.com with ESMTP id 0Q7c3XbK2mA9fZ
              for <user@example.com>; Sun, 4 Oct 2026 12:00:00 +0000

  The `with` value is an RFC 3848 transmission type, see `protocol/1`.
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
          optional(:date) => DateTime.t()
        }

  @doc """
  Returns the complete header field, ending in CRLF.

  `:for` is the recipient to show. Leave it out for messages with several
  recipients, so they are not disclosed to each other. `:date` defaults to
  now.
  """
  @spec build(fields()) :: String.t()
  def build(fields) do
    date = Map.get_lazy(fields, :date, &DateTime.utc_now/0)

    id = if fields[:id], do: " id #{fields.id}", else: ""
    recipient = if fields[:for], do: "\r\n\tfor <#{fields.for}>", else: ""

    "Received: from #{fields.helo} (#{address_literal(fields.remote_ip)})\r\n" <>
      "\tby #{fields.by} with #{fields.protocol}#{id}#{recipient}; #{Date.format(date)}\r\n"
  end

  @doc """
  Returns the RFC 3848 transmission type for a session.

      iex> Sovite.Message.Received.protocol(esmtp: true, tls: true)
      "ESMTPS"
      iex> Sovite.Message.Received.protocol(esmtp: false)
      "SMTP"
      iex> Sovite.Message.Received.protocol(lmtp: true, auth: true)
      "LMTPA"
  """
  @spec protocol(keyword()) :: String.t()
  def protocol(opts) do
    base =
      cond do
        opts[:lmtp] -> "LMTP"
        opts[:esmtp] -> "ESMTP"
        true -> "SMTP"
      end

    # RFC 3848 types only exist for the extended protocols.
    if base == "SMTP",
      do: base,
      else: base <> if(opts[:tls], do: "S", else: "") <> if(opts[:auth], do: "A", else: "")
  end

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
