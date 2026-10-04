defmodule Sovite.Core.Transport do
  @moduledoc """
  Transport specifications: `transport:nexthop`.

    * `smtp` - SMTP to the recipient domain's MX hosts, or the relay host.
    * `smtp:example.com` / `smtp:example.com:587` - SMTP to the MX hosts
      of `example.com`.
    * `smtp:[mail.example.com]` / `smtp:[192.0.2.1]:587` - SMTP to that
      host, without an MX lookup.
    * `lmtp:unix:/run/dovecot/lmtp` / `lmtp:inet:mail.example.com:24` /
      `lmtp:[mail.example.com]:24` - LMTP. Port 24 by default.
    * `local` / `mailbox` - local and hosted mailbox delivery.
    * `error:5.1.1 text` - bounce with that status and text. The status
      is optional (`5.0.0`).
    * `retry:4.3.0 text` - keep the mail and try again later.
    * `discard:text` - drop the mail, as if delivered.

  In the transports table, an empty transport (`:[relay.example.com]`) keeps
  the transport and only changes the next hop; an empty next hop
  (`smtp:`) keeps the default next hop.
  """

  alias Sovite.Message.Received

  @typedoc "An SMTP or LMTP host: `mx: true` looks up the MX hosts of `host`."
  @type host :: %{host: String.t(), port: :inet.port_number(), mx: boolean()}

  @type t :: %{
          transport: :smtp | :lmtp | :local | :mailbox | :error | :retry | :discard | nil,
          nexthop:
            host()
            | {:unix, Path.t()}
            | {status :: String.t(), text :: String.t()}
            | String.t()
            | nil
        }

  @doc """
  Parses a specification.

      iex> Sovite.Core.Transport.parse("smtp:[mail.example.com]:587")
      {:ok, %{transport: :smtp, nexthop: %{host: "mail.example.com", port: 587, mx: false}}}
      iex> Sovite.Core.Transport.parse("lmtp:unix:/run/dovecot/lmtp")
      {:ok, %{transport: :lmtp, nexthop: {:unix, "/run/dovecot/lmtp"}}}
      iex> Sovite.Core.Transport.parse("error:5.1.1 no such user")
      {:ok, %{transport: :error, nexthop: {"5.1.1", "no such user"}}}
  """
  @spec parse(String.t()) :: {:ok, t()} | :error
  def parse(spec) when is_binary(spec) do
    {name, nexthop} =
      case :binary.split(String.trim(spec), ":") do
        [name] -> {name, ""}
        [name, nexthop] -> {name, String.trim(nexthop)}
      end

    with {:ok, transport} <- transport(String.downcase(name)),
         {:ok, nexthop} <- nexthop(transport, nexthop) do
      {:ok, %{transport: transport, nexthop: nexthop}}
    end
  end

  def parse(_spec), do: :error

  defp transport(""), do: {:ok, nil}
  defp transport("smtp"), do: {:ok, :smtp}
  defp transport("lmtp"), do: {:ok, :lmtp}
  defp transport("local"), do: {:ok, :local}
  defp transport("mailbox"), do: {:ok, :mailbox}
  defp transport("error"), do: {:ok, :error}
  defp transport("retry"), do: {:ok, :retry}
  defp transport("discard"), do: {:ok, :discard}
  defp transport(_), do: :error

  defp nexthop(transport, "") when transport in [nil, :smtp, :lmtp, :local, :mailbox],
    do: {:ok, nil}

  defp nexthop(:error, text), do: {:ok, status_text(text, "5.0.0", "delivery not permitted")}
  defp nexthop(:retry, text), do: {:ok, status_text(text, "4.0.0", "delivery deferred")}
  defp nexthop(:discard, text), do: {:ok, if(text == "", do: "discarded", else: text)}
  defp nexthop(transport, _nexthop) when transport in [:local, :mailbox], do: :error

  defp nexthop(:lmtp, "unix:" <> path) do
    if Path.type(path) == :absolute, do: {:ok, {:unix, path}}, else: :error
  end

  defp nexthop(:lmtp, "inet:" <> address), do: lmtp_host(address)
  defp nexthop(:lmtp, address), do: lmtp_host(address)
  defp nexthop(_smtp_or_nil, address), do: parse_host(address, 25)

  # LMTP never looks up MX records.
  defp lmtp_host(address) do
    with {:ok, host} <- parse_host(address, 24), do: {:ok, %{host | mx: false}}
  end

  defp status_text(text, default_status, default_text) do
    case Regex.run(~r/\A([45]\.\d{1,3}\.\d{1,3})(?:\s+(.*))?\z/s, text) do
      [_, status] -> {status, default_text}
      [_, status, rest] -> {status, rest}
      nil when text == "" -> {default_status, default_text}
      nil -> {default_status, text}
    end
  end

  @doc """
  Parses a host: `host` and `host:port` look up MX
  records, `[host]` and `[host]:port` do not. An IP address must be in
  brackets and becomes an address literal (`"[192.0.2.1]"`).

      iex> Sovite.Core.Transport.parse_host("example.com", 25)
      {:ok, %{host: "example.com", port: 25, mx: true}}
      iex> Sovite.Core.Transport.parse_host("[IPv6:2001:db8::1]:2525", 25)
      {:ok, %{host: "[IPv6:2001:db8::1]", port: 2525, mx: false}}
  """
  @spec parse_host(String.t(), :inet.port_number()) :: {:ok, host()} | :error
  def parse_host(value, default_port) do
    with {:ok, host, port, mx} <- split_host(value),
         {:ok, port} <- parse_port(port, default_port),
         {:ok, host} <- host(host, mx) do
      {:ok, %{host: host, port: port, mx: mx}}
    else
      _ -> :error
    end
  end

  defp split_host("[" <> rest) do
    case :binary.split(rest, "]") do
      [host, ""] -> {:ok, host, nil, false}
      [host, ":" <> port] -> {:ok, host, port, false}
      _ -> :error
    end
  end

  defp split_host(value) do
    case :binary.split(value, ":") do
      [host] -> {:ok, host, nil, true}
      [host, port] -> {:ok, host, port, true}
      _ -> :error
    end
  end

  defp parse_port(nil, default), do: {:ok, default}

  defp parse_port(port, _default) do
    case Integer.parse(port) do
      {port, ""} when port in 1..65_535 -> {:ok, port}
      _ -> :error
    end
  end

  defp host(host, true) do
    if Sovite.Validators.hostname?(host), do: {:ok, String.downcase(host, :ascii)}, else: :error
  end

  defp host(host, false) do
    case Sovite.Net.parse_ip(String.replace_prefix(host, "IPv6:", "")) do
      {:ok, ip} ->
        {:ok, Received.address_literal(ip)}

      {:error, _} ->
        if Sovite.Validators.hostname?(host),
          do: {:ok, String.downcase(host, :ascii)},
          else: :error
    end
  end

  @doc """
  Merges a transports table entry into a default: an empty transport or
  next hop keeps the default's.
  """
  @spec merge(t(), t()) :: t()
  def merge(default, %{transport: nil, nexthop: nexthop}), do: %{default | nexthop: nexthop}
  def merge(_default, override), do: override
end
