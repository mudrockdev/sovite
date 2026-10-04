defmodule Sovite.Core.SMTPHandler do
  @moduledoc """
  The MTA's `Sovite.SMTP.Server.Handler`: relay control, recipient
  checks, and durable spooling.

  Recipients are checked at `RCPT` time:

  1. `<Postmaster>` and `postmaster@` any local domain are always
     accepted (RFC 5321 §4.5.1). A bare `<Postmaster>` is queued as
     `postmaster@<server.hostname>`.
  2. Local domains (`domains.local`): accepted if `domains.local_recipients`
     is unset or lists the address, otherwise `550 5.1.1`.
  3. Relay domains (`domains.relay`): accepted.
  4. Any other destination, including address literals: accepted only from
     `smtp.trusted_networks`, otherwise `554 5.7.1 Relay access denied`.
     The default config trusts no one, so it is never an open relay.

  Domains are compared case-insensitively. Address tricks such as
  `user%remote@local` or source routes do not relay: only the domain of
  the parsed mailbox counts.

  The message is accepted with `250` only after `Sovite.Queue.Spool`
  has made it durable. A `Received:` header is added at the top.
  """

  @behaviour Sovite.SMTP.Server.Handler

  require Logger

  alias Sovite.Core.Logging
  alias Sovite.Message.Received
  alias Sovite.Net
  alias Sovite.Queue.{Envelope, ID, Spool}
  alias Sovite.SMTP.Reply

  @doc "Handler options from the running configuration."
  @spec opts(Sovite.Core.Config.t()) :: map()
  def opts(config) do
    %{
      hostname: config.server.hostname,
      queue_directory: config.queue.directory,
      local_domains: MapSet.new(config.domains.local),
      relay_domains: MapSet.new(config.domains.relay),
      local_recipients:
        config.domains.local_recipients && MapSet.new(config.domains.local_recipients),
      trusted_networks: config.smtp.trusted_networks
    }
  end

  @impl true
  def init(connection, opts) do
    Logger.metadata(
      session_id: connection.session_id,
      remote_ip: Logging.format_ip(connection.remote_ip)
    )

    state =
      Map.merge(opts, %{
        connection: connection,
        trusted: Net.in_networks?(connection.remote_ip, opts.trusted_networks),
        helo: nil,
        esmtp: false,
        writer: nil,
        queue_id: nil
      })

    {:ok, state}
  end

  @impl true
  def handle_helo(kind, name, state), do: {:ok, %{state | helo: name, esmtp: kind == :ehlo}}

  @impl true
  def handle_mail(_sender, _params, state), do: {:ok, state}

  @impl true
  def handle_rcpt(recipient, state) do
    case classify(recipient, state) do
      :postmaster -> {:ok, state}
      {:local, address} -> check_local(address, recipient, state)
      :relay -> {:ok, state}
      :remote when state.trusted -> {:ok, state}
      :remote -> {:reply, Reply.new(554, "5.7.1", "<#{recipient}>: Relay access denied"), state}
    end
  end

  defp check_local(address, recipient, state) do
    if state.local_recipients == nil or MapSet.member?(state.local_recipients, address),
      do: {:ok, state},
      else:
        {:reply,
         Reply.new(550, "5.1.1", "<#{recipient}>: Recipient address rejected: User unknown"),
         state}
  end

  @impl true
  def handle_data(transaction, state) do
    queue_id = ID.generate()
    recipients = transaction.recipients |> Enum.map(&queued_address(&1, state)) |> Enum.uniq()
    received_at = DateTime.utc_now()
    protocol = Received.protocol(esmtp: state.esmtp)

    envelope = %Envelope{
      queue_id: queue_id,
      sender: transaction.sender,
      recipients: recipients,
      received_at: received_at,
      session_id: state.connection.session_id,
      remote_ip: state.connection.remote_ip,
      helo: state.helo,
      protocol: protocol,
      body_type: transaction.params.body
    }

    received =
      Received.build(%{
        helo: state.helo,
        remote_ip: state.connection.remote_ip,
        by: state.hostname,
        protocol: protocol,
        id: queue_id,
        for: if(match?([_], recipients), do: hd(recipients)),
        date: received_at
      })

    with {:ok, writer} <- Spool.open(state.queue_directory, envelope),
         {:ok, writer} <- Spool.write(writer, received) do
      Logger.metadata(queue_id: queue_id)
      {:ok, %{state | writer: writer, queue_id: queue_id}}
    else
      {:error, reason} -> queue_error(state, reason)
    end
  end

  @impl true
  def handle_data_chunk(chunk, state) do
    case Spool.write(state.writer, chunk) do
      {:ok, writer} ->
        {:ok, %{state | writer: writer}}

      {:error, reason} ->
        Spool.abort(state.writer)
        queue_error(%{state | writer: nil}, reason)
    end
  end

  @impl true
  def handle_data_end(_transaction, state) do
    case Spool.commit(state.writer) do
      {:ok, _path, _size} ->
        state = %{state | writer: nil}
        Logger.metadata(queue_id: nil)
        {:reply, Reply.new(250, "2.0.0", "Ok: queued as #{state.queue_id}"), state}

      {:error, reason} ->
        queue_error(%{state | writer: nil}, reason)
    end
  end

  @impl true
  def handle_data_abort(_reason, state), do: abort(state)

  @impl true
  def handle_rset(state), do: abort(state)

  @impl true
  def handle_vrfy(argument, state) do
    address = argument |> String.trim_leading("<") |> String.trim_trailing(">")

    with {:local, normalized} <- classify(address, state),
         true <- state.local_recipients != nil do
      if MapSet.member?(state.local_recipients, normalized),
        do: {:reply, Reply.new(250, "2.1.5", "<#{address}>"), state},
        else: {:reply, Reply.new(550, "5.1.1", "<#{address}>: User unknown"), state}
    else
      _ -> {:ok, state}
    end
  end

  @impl true
  def terminate(_reason, state), do: abort(state)

  defp abort(%{writer: nil} = state), do: state

  defp abort(state) do
    Spool.abort(state.writer)
    Logger.metadata(queue_id: nil)
    %{state | writer: nil}
  end

  defp queue_error(state, reason) do
    Logger.error("cannot write queue file: #{:file.format_error(reason)}")
    {:reply, Reply.new(451, "4.3.0", "Error: queue file write error"), state}
  end

  ## Recipient classification

  defp classify(recipient, state) do
    case Sovite.Validators.split_mailbox(recipient) do
      {:ok, {local_part, domain}} ->
        domain = String.downcase(domain, :ascii)
        local = MapSet.member?(state.local_domains, domain)

        cond do
          local and String.downcase(local_part, :ascii) == "postmaster" -> :postmaster
          local -> {:local, String.downcase(recipient, :ascii)}
          MapSet.member?(state.relay_domains, domain) -> :relay
          true -> :remote
        end

      # Only a bare "Postmaster" gets this far without a domain.
      {:error, _} ->
        if String.downcase(recipient, :ascii) == "postmaster", do: :postmaster, else: :remote
    end
  end

  defp queued_address(recipient, state) do
    if String.downcase(recipient, :ascii) == "postmaster",
      do: "postmaster@" <> state.hostname,
      else: recipient
  end
end
