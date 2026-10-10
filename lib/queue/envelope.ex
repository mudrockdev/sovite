defmodule Sovite.Queue.Envelope do
  @moduledoc """
  The envelope of a queued message: who sent it, to whom, and how it
  arrived.

  `sender` is `""` for the null reverse-path (`MAIL FROM:<>`).
  `srs_sender`, when set, is the sender to use instead when the message
  is forwarded to another domain: an SRS address (see `Sovite.SRS`).

  `requiretls` is set when the client sent `REQUIRETLS` (RFC 8689): the
  message may only be relayed over TLS verified with DANE or MTA-STS,
  to servers that support `REQUIRETLS` too.

  `auth_user` is the login of the client that submitted the message, if
  it authenticated, so delivery failures can be traced back to it.

  `content_filter`, when set, is where every recipient's copy goes
  instead (a transport, such as `smtp:[127.0.0.1]:10024`): an
  after-queue content filter, which sends the message back once it has
  checked it.

  `notification` is set on delivery status notifications Sovite
  generates itself: `:failure`, `:delay`, or `:double_bounce` (a failed
  notification reported to the postmaster). A failed `:double_bounce` is
  never reported again, so notifications cannot loop.
  """

  @enforce_keys [:queue_id, :sender, :recipients]
  defstruct [
    :queue_id,
    :sender,
    :srs_sender,
    :recipients,
    :received_at,
    :session_id,
    :remote_ip,
    :helo,
    :protocol,
    :body_type,
    :notification,
    :auth_user,
    :content_filter,
    requiretls: false
  ]

  @type t :: %__MODULE__{
          queue_id: String.t(),
          sender: String.t(),
          srs_sender: String.t() | nil,
          recipients: [String.t(), ...],
          received_at: DateTime.t() | nil,
          session_id: String.t() | nil,
          remote_ip: :inet.ip_address() | nil,
          helo: String.t() | nil,
          protocol: String.t() | nil,
          body_type: :"7bit" | :"8bitmime" | nil,
          notification: :failure | :delay | :double_bounce | nil,
          auth_user: String.t() | nil,
          content_filter: String.t() | nil,
          requiretls: boolean()
        }

  @doc false
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = envelope) do
    %{
      "queue_id" => envelope.queue_id,
      "sender" => envelope.sender,
      "srs_sender" => envelope.srs_sender,
      "recipients" => envelope.recipients,
      "received_at" => envelope.received_at && DateTime.to_iso8601(envelope.received_at),
      "session_id" => envelope.session_id,
      "remote_ip" => envelope.remote_ip && envelope.remote_ip |> :inet.ntoa() |> to_string(),
      "helo" => envelope.helo,
      "protocol" => envelope.protocol,
      "body_type" => envelope.body_type && Atom.to_string(envelope.body_type),
      "notification" => envelope.notification && Atom.to_string(envelope.notification),
      "auth_user" => envelope.auth_user,
      "content_filter" => envelope.content_filter,
      "requiretls" => envelope.requiretls
    }
  end

  @doc false
  @spec from_map(map()) :: {:ok, t()} | {:error, :invalid_envelope}
  def from_map(%{"queue_id" => id, "sender" => sender, "recipients" => [_ | _] = rcpts} = map)
      when is_binary(id) and is_binary(sender) do
    with true <- Enum.all?(rcpts, &is_binary/1),
         true <- is_nil(map["srs_sender"]) or is_binary(map["srs_sender"]),
         true <- map["requiretls"] in [nil, true, false],
         true <- is_nil(map["auth_user"]) or is_binary(map["auth_user"]),
         true <- is_nil(map["content_filter"]) or is_binary(map["content_filter"]),
         {:ok, received_at} <- optional(map["received_at"], &parse_time/1),
         {:ok, remote_ip} <- optional(map["remote_ip"], &parse_ip/1),
         {:ok, body_type} <- optional(map["body_type"], &parse_body_type/1),
         {:ok, notification} <- optional(map["notification"], &parse_notification/1) do
      {:ok,
       %__MODULE__{
         queue_id: id,
         sender: sender,
         srs_sender: map["srs_sender"],
         recipients: rcpts,
         received_at: received_at,
         session_id: map["session_id"],
         remote_ip: remote_ip,
         helo: map["helo"],
         protocol: map["protocol"],
         body_type: body_type,
         notification: notification,
         auth_user: map["auth_user"],
         content_filter: map["content_filter"],
         requiretls: map["requiretls"] == true
       }}
    else
      _ -> {:error, :invalid_envelope}
    end
  end

  def from_map(_map), do: {:error, :invalid_envelope}

  defp optional(nil, _parse), do: {:ok, nil}
  defp optional(value, parse) when is_binary(value), do: parse.(value)
  defp optional(_value, _parse), do: :error

  defp parse_time(value) do
    case DateTime.from_iso8601(value) do
      {:ok, time, _offset} -> {:ok, time}
      {:error, _} -> :error
    end
  end

  defp parse_ip(value) do
    case :inet.parse_strict_address(String.to_charlist(value)) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> :error
    end
  end

  # Fixed table: never create atoms from file contents.
  defp parse_body_type("7bit"), do: {:ok, :"7bit"}
  defp parse_body_type("8bitmime"), do: {:ok, :"8bitmime"}
  defp parse_body_type(_), do: :error

  defp parse_notification("failure"), do: {:ok, :failure}
  defp parse_notification("delay"), do: {:ok, :delay}
  defp parse_notification("double_bounce"), do: {:ok, :double_bounce}
  defp parse_notification(_), do: :error
end
