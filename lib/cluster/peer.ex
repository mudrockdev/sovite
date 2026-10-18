defmodule Sovite.Cluster.Peer do
  @moduledoc """
  Where a cluster node accepts peers: its name, address, and port,
  written `name@host:port`.

      {:ok, peer} = Sovite.Cluster.Peer.parse("mx2@10.0.0.2:4370")
      {:ok, peer} = Sovite.Cluster.Peer.parse("mx2@[2001:db8::2]:4370")
      {:ok, peer} = Sovite.Cluster.Peer.parse("mx2@10.0.0.2", 4370)

  The node name is `name@host`. A host that is not an IP address is
  resolved when parsing. Parsing creates the node name atom, so only
  parse names from trusted sources, such as a config file.
  """

  @enforce_keys [:name, :ip, :port]
  defstruct [:name, :ip, :port]

  @type t :: %__MODULE__{name: node(), ip: :inet.ip_address(), port: :inet.port_number()}

  @name ~r/\A[A-Za-z0-9_\-]{1,64}\z/

  @doc """
  Parses `name@host:port`, or `name@host` with `default_port`. IPv6
  addresses are in brackets.
  """
  @spec parse(String.t(), :inet.port_number() | nil) :: {:ok, t()} | {:error, String.t()}
  def parse(text, default_port \\ nil) when is_binary(text) do
    with [name, rest] <- String.split(text, "@", parts: 2),
         true <- Regex.match?(@name, name),
         {:ok, host, port} <- host_port(rest, default_port),
         {:ok, ip} <- resolve(host) do
      {:ok, %__MODULE__{name: :"#{name}@#{host}", ip: ip, port: port}}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, "is not name@host:port"}
    end
  end

  @doc "Parses a node name, `name@host`, without resolving it."
  @spec node_name(String.t()) :: {:ok, node()} | {:error, String.t()}
  def node_name(text) when is_binary(text) do
    with [name, host] <- String.split(text, "@", parts: 2),
         true <- Regex.match?(@name, name),
         true <- host != "" and not String.contains?(host, ["/", " ", "@", "[", "]"]) do
      {:ok, :"#{name}@#{host}"}
    else
      _ -> {:error, "is not a node name, name@host"}
    end
  end

  @doc "Formats a peer as `name@host:port`."
  @spec format(t()) :: String.t()
  def format(%__MODULE__{} = peer), do: "#{peer.name}:#{peer.port}"

  defp host_port("[" <> rest, default_port) do
    case String.split(rest, "]", parts: 2) do
      [host, ""] when default_port != nil -> {:ok, host, default_port}
      [host, ":" <> port] -> with {:ok, port} <- port(port), do: {:ok, host, port}
      _ -> :error
    end
  end

  defp host_port(rest, default_port) do
    case String.split(rest, ":") do
      [host] when host != "" and default_port != nil -> {:ok, host, default_port}
      [host, port] when host != "" -> with {:ok, port} <- port(port), do: {:ok, host, port}
      _ -> :error
    end
  end

  defp port(text) do
    case Integer.parse(text) do
      {port, ""} when port in 1..65_535 -> {:ok, port}
      _ -> {:error, "has an invalid port"}
    end
  end

  defp resolve(host) do
    host = String.to_charlist(host)

    case :inet.parse_strict_address(host) do
      {:ok, ip} ->
        {:ok, ip}

      {:error, _} ->
        case :inet.getaddr(host, :inet) do
          {:ok, ip} -> {:ok, ip}
          {:error, _} -> {:error, "has a host that does not resolve"}
        end
    end
  end
end
