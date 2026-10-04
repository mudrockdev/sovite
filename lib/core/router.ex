defmodule Sovite.Core.Router do
  @moduledoc """
  Decides, at delivery time, where each recipient's mail goes.

    1. The address is checked (`Sovite.Core.Recipients.check/2`): unknown
       users and users who moved fail.
    2. Its domain class picks a transport: `routing.local_transport`,
       `routing.mailbox_transport`, `routing.relay_transport`, or
       `routing.remote_transport` (see `Sovite.Core.Transport`).
    3. The transports table (`sovitectl transport`) may override it.
       Patterns, in order: `user+ext@domain`, `user@domain`, `domain`,
       then each parent domain as `.parent` (subdomains only), then `*`.
    4. SMTP without a next hop goes to the relay host the sender relays
       table (`sovitectl sender-relay`) gives for the sender (by address,
       then `@domain`), else to `delivery.relayhost`, else to the MX hosts
       of the recipient's domain (or the address in an address literal).

  Local, mailbox, and LMTP delivery arrive with roadmap Phase 5; until
  then mail for them stays deferred.

  SMTP deliveries also get the source address to connect from (the
  sender relays table, else `delivery.source_address`) and, for explicit
  next hops, credentials from the sender relays table, or
  `delivery.relayhost_username` for `delivery.relayhost`.

  Recipients with the same destination are delivered together, and
  per-destination concurrency limits apply to the destination.
  """

  alias Sovite.Core.{Lookup, Recipients, Routing, Transport}
  alias Sovite.Message.Received

  @typedoc """
  A next hop:

    * `{:mx, domain}` - the MX hosts of `domain`.
    * `{:host, %{host, port, mx}}` - a relay host or transport map next
      hop; `mx: true` looks up the MX hosts of `host`.
    * `{:literal, ip}` - an address literal in the recipient.
  """
  @type nexthop ::
          {:mx, String.t()}
          | {:host, Transport.host()}
          | {:literal, :inet.ip_address()}

  @typedoc """
  Where an SMTP delivery goes: the next hop, the local addresses to
  connect from, and the credentials to log in with.
  """
  @type destination :: %{
          nexthop: nexthop(),
          source: %{optional(:ipv4 | :ipv6) => :inet.ip_address()},
          auth: %{username: String.t(), password: String.t()} | nil
        }

  @type route ::
          {:remote, destination()}
          | {:defer, String.t(), String.t()}
          | {:fail, String.t(), String.t()}
          | {:discard, String.t()}

  @doc "Routes `recipient` of a message from `sender`."
  @spec route(Routing.t(), String.t(), String.t()) :: route()
  def route(routing, sender, recipient) do
    if Routing.valid_address?(recipient),
      do: checked(routing, sender, recipient, Recipients.check(routing, recipient)),
      else: {:fail, "5.1.3", "bad recipient address syntax"}
  end

  defp checked(routing, sender, recipient, {:ok, class}) do
    case transport(routing, recipient, class) do
      {:ok, transport} -> resolve(routing, sender, recipient, transport)
      {:error, _status, _text} = error -> defer(error)
    end
  end

  defp checked(_routing, _sender, _recipient, {:reject, status, text}),
    do: {:fail, status, String.replace(text, "Recipient address rejected: ", "")}

  defp checked(_routing, _sender, _recipient, {:error, text}),
    do: {:defer, "4.3.0", "lookup error: #{text}"}

  defp defer({:error, status, text}), do: {:defer, status, text}

  defp transport(routing, recipient, class) do
    default = Routing.transport(routing, class)

    case Lookup.lookup(routing.transports, transport_keys(routing, recipient)) do
      {:ok, value, _key} ->
        case Transport.parse(value) do
          {:ok, override} ->
            {:ok, Transport.merge(default, override)}

          :error ->
            {:error, "4.3.5", "invalid transport #{inspect(value)} in the transports table"}
        end

      :error ->
        {:ok, default}

      {:error, table} ->
        {:error, "4.3.0", "lookup error: cannot read table #{table}"}
    end
  end

  defp transport_keys(routing, recipient) do
    {local, domain} = recipient |> String.downcase() |> Routing.split()
    {base, _ext} = Routing.extension(routing, local)
    labels = String.split(domain, ".")
    parents = for n <- 1..(length(labels) - 1)//1, do: "." <> Enum.join(Enum.drop(labels, n), ".")
    Enum.uniq(["#{local}@#{domain}", "#{base}@#{domain}", domain] ++ parents ++ ["*"])
  end

  defp resolve(routing, sender, recipient, %{transport: :smtp, nexthop: nexthop}) do
    with {:ok, nexthop} <- nexthop(routing, sender, recipient, nexthop),
         {:ok, source} <- source(routing, sender),
         {:ok, auth} <- auth(routing, sender, nexthop) do
      {:remote, %{nexthop: nexthop, source: source, auth: auth}}
    else
      {:error, table} -> {:defer, "4.3.0", "lookup error: cannot read table #{table}"}
      {:invalid, what} -> {:defer, "4.3.5", what}
    end
  end

  defp resolve(_routing, _sender, _recipient, %{transport: :error, nexthop: {status, text}}) do
    if String.starts_with?(status, "4"), do: {:defer, status, text}, else: {:fail, status, text}
  end

  defp resolve(_routing, _sender, _recipient, %{transport: :retry, nexthop: {status, text}}),
    do: {:defer, status, text}

  defp resolve(_routing, _sender, _recipient, %{transport: :discard, nexthop: text}),
    do: {:discard, text}

  defp resolve(_routing, _sender, _recipient, %{transport: transport}),
    do: {:defer, "4.3.2", "#{transport_name(transport)} delivery is not available yet"}

  defp transport_name(:lmtp), do: "LMTP"
  defp transport_name(:local), do: "local"
  defp transport_name(:mailbox), do: "mailbox"

  defp nexthop(_routing, _sender, _recipient, %{} = host), do: {:ok, {:host, host}}

  defp nexthop(routing, sender, recipient, nil) do
    case sender_lookup(routing, routing.sender_relayhosts, sender) do
      {:ok, value} ->
        case Transport.parse_host(String.trim(value), 25) do
          {:ok, host} -> {:ok, {:host, host}}
          :error -> {:invalid, "invalid relay host #{inspect(value)} in the sender relays table"}
        end

      :error when routing.relayhost != nil ->
        {:ok, {:host, routing.relayhost}}

      :error ->
        {:ok, direct(recipient)}

      {:error, _table} = error ->
        error
    end
  end

  defp direct(recipient) do
    {_local, domain} = Routing.split(recipient)

    case Sovite.Validators.parse_address_literal(domain) do
      {:ok, ip} -> {:literal, ip}
      {:error, _} -> {:mx, domain}
    end
  end

  defp source(routing, sender) do
    case sender_lookup(routing, routing.sender_source_addresses, sender) do
      {:ok, value} -> parse_source(value)
      :error -> {:ok, routing.source_address}
      {:error, _table} = error -> error
    end
  end

  defp parse_source(value) do
    ips = value |> String.split(~r/[\s,]+/, trim: true) |> Enum.map(&Sovite.Net.parse_ip/1)

    if ips != [] and Enum.all?(ips, &match?({:ok, _}, &1)),
      do: {:ok, Routing.source_address(Enum.map(ips, &elem(&1, 1)))},
      else: {:invalid, "invalid source address #{inspect(value)} in the sender relays table"}
  end

  defp auth(routing, sender, {:host, host} = nexthop) do
    keys =
      if(sender == "", do: [], else: sender_keys(sender)) ++ [name(nexthop)]

    case Lookup.lookup(routing.relay_credentials, keys) do
      {:ok, value, _key} ->
        case :binary.split(String.trim(value), ":") do
          [username, password] when username != "" ->
            {:ok, %{username: username, password: password}}

          _ ->
            {:invalid, "relay credentials must be username:password"}
        end

      :error ->
        {:ok, if(host == routing.relayhost, do: routing.relay_auth)}

      {:error, _table} = error ->
        error
    end
  end

  defp auth(_routing, _sender, _nexthop), do: {:ok, nil}

  defp sender_lookup(_routing, _tables, ""), do: :error

  defp sender_lookup(_routing, tables, sender) do
    case Lookup.lookup(tables, sender_keys(sender)) do
      {:ok, value, _key} -> {:ok, value}
      other -> other
    end
  end

  defp sender_keys(sender) do
    sender = String.downcase(sender)
    {_local, domain} = Routing.split(sender)
    if domain, do: [sender, "@" <> domain], else: [sender]
  end

  @doc """
  Returns a destination or next hop as text, for logs: `"example.com"`,
  `"[192.0.2.1]"`, or the host as configured (`"[smtp.example.com]:587"`).
  """
  @spec name(destination() | nexthop()) :: String.t()
  def name(%{nexthop: nexthop}), do: name(nexthop)
  def name({:mx, domain}), do: domain
  def name({:literal, ip}), do: Received.address_literal(ip)

  def name({:host, %{host: host, port: port, mx: mx}}) do
    host = if mx or String.starts_with?(host, "["), do: host, else: "[#{host}]"
    if port == 25, do: host, else: "#{host}:#{port}"
  end
end
