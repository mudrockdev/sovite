defmodule Sovite.Core.Router do
  @moduledoc """
  Decides where each recipient's mail goes.

    * Local domains (`domains.local`): `:local`. Local delivery arrives
      with roadmap Phase 5; until then such mail stays deferred.
    * Everything else goes to `delivery.relayhost` when set.
    * Otherwise to the MX hosts of the recipient's domain, or straight to
      the address in an address literal (`user@[192.0.2.1]`).

  Recipients with the same destination are delivered together, and
  per-destination concurrency limits apply to the destination.
  """

  alias Sovite.Message.Received
  alias Sovite.Validators

  @typedoc """
  A next hop:

    * `{:mx, domain}` - the MX hosts of `domain`.
    * `{:relayhost, %{host, port, mx}}` - the configured relay host.
    * `{:literal, ip}` - an address literal in the recipient.
  """
  @type destination ::
          {:mx, String.t()}
          | {:relayhost, %{host: String.t(), port: :inet.port_number(), mx: boolean()}}
          | {:literal, :inet.ip_address()}

  @type opts :: %{local_domains: MapSet.t(String.t()), relayhost: map() | nil}

  @doc "Routes `recipient`. Returns `:invalid` if it is not a valid mailbox."
  @spec route(String.t(), opts()) :: :local | :invalid | {:remote, destination()}
  def route(recipient, opts) do
    case Validators.split_mailbox(recipient) do
      {:ok, {_local_part, domain}} ->
        domain = String.downcase(domain, :ascii)

        cond do
          MapSet.member?(opts.local_domains, domain) -> :local
          opts.relayhost -> {:remote, {:relayhost, opts.relayhost}}
          true -> remote(domain)
        end

      {:error, _} ->
        :invalid
    end
  end

  defp remote(domain) do
    case Validators.parse_address_literal(domain) do
      {:ok, ip} -> {:remote, {:literal, ip}}
      {:error, _} -> {:remote, {:mx, domain}}
    end
  end

  @doc """
  Returns a destination as text, for logs: `"example.com"`,
  `"[192.0.2.1]"`, or the relay host as configured.
  """
  @spec name(destination()) :: String.t()
  def name({:mx, domain}), do: domain
  def name({:literal, ip}), do: Received.address_literal(ip)

  def name({:relayhost, %{host: host, port: port, mx: mx}}) do
    host = if mx or String.starts_with?(host, "["), do: host, else: "[#{host}]"
    if port == 25, do: host, else: "#{host}:#{port}"
  end
end
