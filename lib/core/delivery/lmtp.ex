defmodule Sovite.Core.Delivery.LMTP do
  @moduledoc false
  # LMTP delivery (RFC 2033) for Sovite.Core.Delivery: to a Unix socket,
  # or to the addresses of a host (no MX lookup). The LMTP server is
  # usually on the same machine or network, so there is no TLS and no
  # authentication, and no check for a server with this host's name.

  alias Sovite.Core.Delivery
  alias Sovite.Core.Delivery.Transaction
  alias Sovite.DNS.MX
  alias Sovite.SMTP.Client

  @spec deliver(Delivery.job(), Delivery.connection() | nil, Delivery.opts()) ::
          {[Delivery.result()], String.t() | nil, Delivery.connection() | nil}
  def deliver(job, {client, remote}, opts) do
    case Transaction.transaction(job, client, remote) do
      # The cached connection went away; start over with a fresh one.
      {:retry, _error} -> deliver(job, nil, opts)
      result -> result
    end
  end

  def deliver(job, nil, opts) do
    case addresses(job.destination.nexthop, opts) do
      {:ok, addresses} -> try_addresses(job, Enum.take(addresses, opts.max_addresses), nil, opts)
      {:error, status, text} -> {Transaction.all(job, status, text), nil, nil}
    end
  end

  defp addresses({:unix, path}, _opts), do: {:ok, [{path, {:local, path}, 0}]}

  defp addresses({:host, %{host: host, port: port}}, opts) do
    case Sovite.Validators.parse_address_literal(host) do
      {:ok, ip} ->
        {:ok, [{host, ip, port}]}

      {:error, _} ->
        case MX.addresses(opts.resolver, host, opts.families) do
          {:ok, [_ | _] = ips} ->
            {:ok, Enum.map(ips, &{Transaction.remote_name(host, &1), &1, port})}

          {:ok, []} ->
            {:error, "4.4.4", "LMTP host #{host} has no address"}

          {:error, reason} ->
            {:error, "4.4.3", "cannot resolve LMTP host #{host}: #{reason}"}
        end
    end
  end

  defp try_addresses(job, [], last_error, _opts) do
    {status, text} = last_error || {"4.4.1", "No LMTP server could be reached"}
    {Transaction.all(job, status, text), nil, nil}
  end

  defp try_addresses(job, [{remote, address, port} | rest], _last_error, opts) do
    client = opts.client |> Keyword.delete(:local_address) |> Keyword.put(:protocol, :lmtp)

    result =
      case Client.connect(address, port, client) do
        {:ok, client} -> Transaction.transaction(job, client, remote)
        {:error, error} -> {:retry, Transaction.connect_error(remote, port, error)}
      end

    case result do
      {:retry, error} -> try_addresses(job, rest, error, opts)
      result -> result
    end
  end
end
