defmodule Sovite.Core.Delivery.Transaction do
  @moduledoc false
  # Runs an SMTP or LMTP transaction on an open Sovite.SMTP.Client and
  # turns the replies and errors into delivery results, for
  # Sovite.Core.Delivery and its LMTP and local transports.

  alias Sovite.Message.Received
  alias Sovite.Queue.Spool
  alias Sovite.SMTP.{Client, Reply}
  alias Sovite.TLS
  alias Sovite.Validators

  def transaction(job, client, remote) do
    body = Spool.stream_message(job.path, job.message_offset, job.message_size, job.prefix)

    opts = [
      size: job.message_size,
      body_type: job.body_type,
      requiretls: Map.get(job, :requiretls, false),
      smtputf8: smtputf8?(job),
      xforward: Map.get(job, :xforward)
    ]

    case Client.deliver(client, job.sender, job.recipients, body, opts) do
      {:ok, client, replies} ->
        results =
          Enum.map(replies, fn {rcpt, stage, reply} ->
            reply_result(rcpt, stage, reply, remote)
          end)

        {results, remote, {client, remote}}

      {:error, client, refusal} ->
        {status, text} = refusal_error(refusal, remote, job)
        {all(job, status, text, remote), remote, {client, remote}}

      {:error, {:data_end, reason}} ->
        text =
          "lost connection with #{remote} while sending end of data (#{format_reason(reason)}); " <>
            "the message may be delivered more than once"

        {all(job, "4.4.2", text, remote), remote, nil}

      {:error, {stage, reason}} ->
        {:retry,
         {"4.4.2",
          "lost connection with #{remote} #{stage_text(stage)} (#{format_reason(reason)})"}}
    end
  end

  defp reply_result(rcpt, stage, reply, remote) do
    status =
      cond do
        stage == :data_end and reply.code in 200..299 -> :delivered
        reply.code >= 500 -> :failed
        true -> :deferred
      end

    {rcpt, status, details(Reply.status(reply), Reply.to_string(reply), remote, true)}
  end

  def all(job, status, text, remote \\ nil) do
    result = if String.starts_with?(status, "5"), do: :failed, else: :deferred
    details = details(status, text, remote, false)
    Enum.map(job.recipients, &{&1, result, details})
  end

  def details(status, reply, remote, smtp),
    do: %{status: status, reply: reply, remote: remote, smtp: smtp, at: DateTime.utc_now()}

  # Whether the transaction needs SMTPUTF8 (RFC 6531): its addresses are
  # internationalized, or it came with SMTPUTF8 and has UTF-8 header
  # fields. Otherwise it is sent without, even if it came with it.
  @doc false
  def smtputf8?(job) do
    international_addresses?(job) or
      (Map.get(job, :smtputf8, false) and international_header?(job))
  end

  defp international_addresses?(job),
    do: Enum.any?([job.sender | job.recipients], &Validators.international?/1)

  defp international_header?(job) do
    case Spool.read_headers(job.path, job.message_offset, job.message_size, prefix: job.prefix) do
      {:ok, header} -> Validators.international?(header)
      {:error, _} -> true
    end
  end

  defp refusal_error({:message_too_large, limit}, remote, _job),
    do: {"5.3.4", "message size exceeds the limit of #{limit} bytes of #{remote}"}

  defp refusal_error(:eight_bit_not_supported, remote, _job),
    do: {"5.6.3", "8-bit message, but #{remote} does not support 8BITMIME"}

  defp refusal_error(:requiretls_not_supported, remote, _job),
    do: {"5.7.30", "REQUIRETLS support required, but host #{remote} does not offer it"}

  # RFC 6531 §3.2 and RFC 6533: such a message cannot be downgraded, so
  # it is returned.
  defp refusal_error(:smtputf8_not_supported, remote, job) do
    if international_addresses?(job),
      do: {"5.6.7", "non-ASCII addresses need SMTPUTF8, but host #{remote} does not support it"},
      else:
        {"5.6.9",
         "the message has UTF-8 header fields, which need SMTPUTF8, but host #{remote} does not support it"}
  end

  defp refusal_error({:invalid_address, address}, _remote, _job),
    do: {"5.1.3", "invalid address #{inspect(address)}"}

  # Port 0 is a Unix socket.
  def connect_error(remote, 0, {:connect, reason}),
    do: {"4.4.1", "connect to #{remote}: #{format_reason(reason)}"}

  def connect_error(remote, port, {:connect, reason}),
    do: {"4.4.1", "connect to #{remote}:#{port}: #{format_reason(reason)}"}

  def connect_error(remote, _port, {:tls, {:tls, reason}}),
    do: {"4.7.5", "TLS with host #{remote} failed: #{TLS.format_error(reason)}"}

  def connect_error(remote, _port, {stage, %Reply{} = reply})
      when stage in [:greeting, :ehlo, :helo, :lhlo],
      do: {"4.4.1", "host #{remote} refused to talk to me: #{Reply.to_string(reply)}"}

  def connect_error(remote, _port, {stage, reason}),
    do:
      {"4.4.2", "lost connection with #{remote} #{stage_text(stage)} (#{format_reason(reason)})"}

  def stage_text(:greeting), do: "while receiving the initial greeting"
  def stage_text(:ehlo), do: "while sending EHLO"
  def stage_text(:helo), do: "while sending HELO"
  def stage_text(:lhlo), do: "while sending LHLO"
  def stage_text(:mail), do: "while sending MAIL FROM"
  def stage_text(:rcpt), do: "while sending RCPT TO"
  def stage_text(:data), do: "while sending DATA"
  def stage_text(:data_end), do: "while sending end of data"
  def stage_text(:rset), do: "while sending RSET"
  def stage_text(:starttls), do: "while sending STARTTLS"
  def stage_text(:auth), do: "while authenticating"
  def stage_text(:xforward), do: "while sending XFORWARD"
  def stage_text(stage), do: "at #{stage}"

  def format_reason(:timeout), do: "timeout"
  def format_reason(:closed), do: "connection closed"
  def format_reason(:econnrefused), do: "Connection refused"

  def format_reason(reason) when is_atom(reason),
    do: reason |> :inet.format_error() |> to_string()

  def format_reason(reason), do: inspect(reason)

  def remote_name(host, ip) do
    literal = Received.address_literal(ip)
    if host == literal, do: literal, else: host <> literal
  end
end
