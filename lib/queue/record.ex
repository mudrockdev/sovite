defmodule Sovite.Queue.Record do
  @moduledoc """
  Delivery records, appended to a queue file after the message by
  `Sovite.Queue.Spool.append/3`.

  A queue file is never rewritten. Instead, each delivery attempt appends
  what happened, and `Sovite.Queue.Entry` replays the records to get the
  message's current state:

    * `{:recipient, address, status, details}` - the outcome of a delivery
      attempt for one recipient. `:delivered` and `:failed` are final;
      `:deferred` will be retried.
    * `{:notified, addresses}` - the sender was told about these failed
      recipients (or, for a null sender, it was decided not to tell
      anyone).
    * `{:retry, attempts, next_attempt}` - the message was deferred after
      `attempts` attempts, until `next_attempt`.
    * `:warned` - a delay warning was sent.
  """

  @type status :: :delivered | :failed | :deferred

  @typedoc """
  Details of a recipient outcome. `status` is the enhanced status code,
  `reply` the remote server's reply or a local diagnostic, `remote` the
  server that gave it (`"mx.example.com[192.0.2.25]"`), and `smtp` whether
  `reply` came from a remote SMTP server.
  """
  @type details :: %{
          status: String.t(),
          reply: String.t() | nil,
          remote: String.t() | nil,
          smtp: boolean(),
          at: DateTime.t()
        }

  @type t ::
          {:recipient, String.t(), status(), details()}
          | {:notified, [String.t()]}
          | {:retry, pos_integer(), DateTime.t()}
          | :warned

  @doc false
  @spec to_map(t()) :: map()
  def to_map({:recipient, address, status, details}) do
    %{
      "type" => "recipient",
      "recipient" => address,
      "status" => Atom.to_string(status),
      "code" => details.status,
      "reply" => details.reply,
      "remote" => details.remote,
      "smtp" => details.smtp,
      "at" => DateTime.to_iso8601(details.at)
    }
  end

  def to_map({:notified, addresses}), do: %{"type" => "notified", "recipients" => addresses}

  def to_map({:retry, attempts, next_attempt}),
    do: %{"type" => "retry", "attempts" => attempts, "next" => DateTime.to_iso8601(next_attempt)}

  def to_map(:warned), do: %{"type" => "warned"}

  @doc false
  @spec from_map(term()) :: {:ok, t()} | :error
  def from_map(%{"type" => "recipient", "recipient" => address, "code" => code} = map)
      when is_binary(address) and is_binary(code) do
    with {:ok, status} <- parse_status(map["status"]),
         {:ok, at} <- parse_time(map["at"]),
         true <- optional_string?(map["reply"]) and optional_string?(map["remote"]),
         true <- is_boolean(map["smtp"]) do
      details = %{
        status: code,
        reply: map["reply"],
        remote: map["remote"],
        smtp: map["smtp"],
        at: at
      }

      {:ok, {:recipient, address, status, details}}
    else
      _ -> :error
    end
  end

  def from_map(%{"type" => "notified", "recipients" => addresses}) when is_list(addresses) do
    if Enum.all?(addresses, &is_binary/1), do: {:ok, {:notified, addresses}}, else: :error
  end

  def from_map(%{"type" => "retry", "attempts" => attempts, "next" => next})
      when is_integer(attempts) and attempts > 0 do
    with {:ok, next} <- parse_time(next), do: {:ok, {:retry, attempts, next}}
  end

  def from_map(%{"type" => "warned"}), do: {:ok, :warned}
  def from_map(_map), do: :error

  # Fixed table: never create atoms from file contents.
  defp parse_status("delivered"), do: {:ok, :delivered}
  defp parse_status("failed"), do: {:ok, :failed}
  defp parse_status("deferred"), do: {:ok, :deferred}
  defp parse_status(_), do: :error

  defp parse_time(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, time, _offset} -> {:ok, time}
      {:error, _} -> :error
    end
  end

  defp parse_time(_value), do: :error

  defp optional_string?(value), do: is_nil(value) or is_binary(value)
end
