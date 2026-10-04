defmodule Sovite.Queue.Envelope do
  @moduledoc """
  The envelope of a queued message: who sent it, to whom, and how it
  arrived.

  `sender` is `""` for the null reverse-path (`MAIL FROM:<>`).
  """

  @enforce_keys [:queue_id, :sender, :recipients]
  defstruct [
    :queue_id,
    :sender,
    :recipients,
    :received_at,
    :session_id,
    :remote_ip,
    :helo,
    :protocol,
    :body_type
  ]

  @type t :: %__MODULE__{
          queue_id: String.t(),
          sender: String.t(),
          recipients: [String.t(), ...],
          received_at: DateTime.t() | nil,
          session_id: String.t() | nil,
          remote_ip: :inet.ip_address() | nil,
          helo: String.t() | nil,
          protocol: String.t() | nil,
          body_type: :"7bit" | :"8bitmime" | nil
        }

  @doc false
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = envelope) do
    %{
      "queue_id" => envelope.queue_id,
      "sender" => envelope.sender,
      "recipients" => envelope.recipients,
      "received_at" => envelope.received_at && DateTime.to_iso8601(envelope.received_at),
      "session_id" => envelope.session_id,
      "remote_ip" => envelope.remote_ip && envelope.remote_ip |> :inet.ntoa() |> to_string(),
      "helo" => envelope.helo,
      "protocol" => envelope.protocol,
      "body_type" => envelope.body_type && Atom.to_string(envelope.body_type)
    }
  end

  @doc false
  @spec from_map(map()) :: {:ok, t()} | {:error, :invalid_envelope}
  def from_map(%{"queue_id" => id, "sender" => sender, "recipients" => [_ | _] = rcpts} = map)
      when is_binary(id) and is_binary(sender) do
    with true <- Enum.all?(rcpts, &is_binary/1),
         {:ok, received_at} <- optional(map["received_at"], &parse_time/1),
         {:ok, remote_ip} <- optional(map["remote_ip"], &parse_ip/1),
         {:ok, body_type} <- optional(map["body_type"], &parse_body_type/1) do
      {:ok,
       %__MODULE__{
         queue_id: id,
         sender: sender,
         recipients: rcpts,
         received_at: received_at,
         session_id: map["session_id"],
         remote_ip: remote_ip,
         helo: map["helo"],
         protocol: map["protocol"],
         body_type: body_type
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
end
