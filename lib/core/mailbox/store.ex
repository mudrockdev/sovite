defmodule Sovite.Core.Mailbox.Store do
  @moduledoc """
  The mail store of the mailbox part: Maildir folders, one per mailbox,
  from the `maildir.mailbox` template. The MTA's `mailbox` transport
  hands mail here, through `Sovite.Core.Stack.Mailbox`.

  Each recipient gets their own copy, with `Return-Path:` and
  `Delivered-To:` at the top.
  """

  alias Sovite.Core.Address
  alias Sovite.Maildir
  alias Sovite.Message.Trace

  @typedoc """
  Where and how mail is stored: the folder template (`nil` when
  `maildir.mailbox` is not set), the extension delimiter, and the host
  name for the Maildir file names.
  """
  @type opts :: %{template: String.t() | nil, delimiter: String.t(), hostname: String.t()}

  @typedoc "The outcome for one recipient: an enhanced status code and a text."
  @type result :: {recipient :: String.t(), status :: String.t(), text :: String.t()}

  @doc "The store's options from the config."
  @spec opts(Sovite.Core.Config.t()) :: opts()
  def opts(config) do
    %{
      template: config.maildir.mailbox,
      delimiter: config.routing.extension_delimiter,
      hostname: config.server.hostname
    }
  end

  @doc """
  Stores `message` (an enumerable of iodata, the message as queued) for
  each of `recipients`, from `sender`.
  """
  @spec deliver(opts(), String.t(), [String.t()], Enumerable.t()) :: [result()]
  def deliver(%{template: nil}, _sender, recipients, _message) do
    for rcpt <- recipients,
        do: {rcpt, "4.3.5", "mailbox delivery is not configured: set maildir.mailbox"}
  end

  def deliver(opts, sender, recipients, message),
    do: Enum.map(recipients, &store(opts, sender, &1, message))

  defp store(opts, sender, rcpt, message) do
    case Address.maildir(opts.template, rcpt, opts.delimiter) do
      {:ok, dir} ->
        data = Stream.concat([Trace.return_path(sender) <> Trace.delivered_to(rcpt)], message)

        case Maildir.deliver(dir, data, hostname: opts.hostname) do
          {:ok, _file} ->
            {rcpt, "2.0.0", "delivered to maildir #{dir}"}

          {:error, reason} ->
            {rcpt, file_status(reason), "cannot deliver to maildir #{dir}: #{file_error(reason)}"}
        end

      :error ->
        {rcpt, "5.1.3", "#{rcpt} cannot be used as a mailbox name"}
    end
  end

  defp file_status(:enospc), do: "4.3.1"
  defp file_status(:edquot), do: "4.2.2"
  defp file_status(_reason), do: "4.3.0"

  defp file_error({:read, exception}), do: Exception.message(exception)
  defp file_error(reason), do: reason |> :file.format_error() |> to_string()
end
