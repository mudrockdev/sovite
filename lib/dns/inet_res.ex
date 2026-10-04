defmodule Sovite.DNS.InetRes do
  @moduledoc """
  Default `Sovite.DNS.Resolver`, built on OTP's `:inet_res`.

  It sends queries to the nameservers configured for the VM (usually from
  `/etc/resolv.conf`). It does not cache results and does not validate
  DNSSEC itself.

  `lookup_secure/3` asks for DNSSEC data (EDNS0 with the DO bit and the
  AD bit set, RFC 6840 §5.7) and reports the AD bit of the answer. That
  bit is only meaningful from a validating resolver you trust, normally
  one on the same host (such as Unbound on `127.0.0.1`): anyone on the
  path to a remote resolver can set it.

  ## Options

    * `:nameservers` - list of `{ip, port}` tuples that override the system
      nameservers.
    * `:timeout` - per-query timeout in milliseconds. Defaults to `5000`.
    * `:retry` - number of retries per nameserver. Defaults to `2`.
  """

  @behaviour Sovite.DNS.Resolver

  @max_name 253

  @impl true
  def lookup(name, type, opts \\ [])

  # :inet_res does not know TLSA.
  def lookup(name, :tlsa, opts) do
    with {:ok, records, _authenticated} <- lookup_secure(name, :tlsa, opts), do: {:ok, records}
  end

  def lookup(name, type, opts) do
    if valid_query_name?(name) do
      res_opts =
        opts
        |> Keyword.take([:nameservers, :retry])
        |> Keyword.put_new(:retry, 2)

      timeout = Keyword.get(opts, :timeout, 5_000)

      case :inet_res.resolve(String.to_charlist(name), :in, type, res_opts, timeout) do
        {:ok, msg} -> {:ok, extract(msg, type)}
        {:error, {reason, _msg}} -> {:error, normalize_error(reason)}
        {:error, reason} -> {:error, normalize_error(reason)}
      end
    else
      {:error, :invalid_name}
    end
  end

  @impl true
  def lookup_secure(name, type, opts \\ []) do
    if valid_query_name?(name) do
      nameservers =
        Keyword.get_lazy(opts, :nameservers, fn -> :inet_db.res_option(:nameservers) end)

      timeout = Keyword.get(opts, :timeout, 5_000)
      retry = Keyword.get(opts, :retry, 2)
      query = secure_query(name, type)

      nameservers
      |> List.duplicate(retry)
      |> List.flatten()
      |> Enum.reduce_while({:error, :timeout}, &try_nameserver(&1, &2, query, type, timeout))
      |> case do
        {:error, reason} when is_atom(reason) -> {:error, normalize_error(reason)}
        result -> result
      end
    else
      {:error, :invalid_name}
    end
  end

  defp try_nameserver(nameserver, _acc, query, type, timeout) do
    case exchange(nameserver, query, timeout) do
      {:ok, packet} -> {:halt, answer(packet, type)}
      {:error, _} = error -> {:cont, error}
    end
  end

  @ad_bit 0x20

  defp secure_query(name, type) do
    id = :rand.uniform(65_536) - 1

    msg =
      :inet_dns.make_msg(
        header: :inet_dns.make_header(id: id, rd: true, opcode: :query),
        qdlist: [
          :inet_dns.make_dns_query(
            domain: String.to_charlist(name),
            type: wire_type(type),
            class: :in
          )
        ],
        arlist: [:inet_dns.make_rr(type: :opt, udp_payload_size: 1232, do: true)]
      )

    # :inet_dns has no field for AD; it is bit 5 of the fourth byte.
    <<head::binary-3, flags, rest::binary>> = :inet_dns.encode(msg)
    {id, <<head::binary, Bitwise.bor(flags, @ad_bit), rest::binary>>}
  end

  defp wire_type(:tlsa), do: 52
  defp wire_type(type), do: type

  # UDP first; TCP when the answer was truncated.
  defp exchange({ip, port}, {id, packet}, timeout) do
    family = if tuple_size(ip) == 8, do: [:inet6], else: []

    with {:ok, socket} <- :gen_udp.open(0, [:binary, active: false] ++ family) do
      try do
        :ok = :gen_udp.send(socket, ip, port, packet)

        case udp_reply(socket, ip, port, id, deadline(timeout)) do
          {:ok, <<_::binary-2, flags, _::binary>> = reply} when Bitwise.band(flags, 0x02) != 0 ->
            tcp_exchange(ip, port, packet, timeout) |> then(&(&1 || {:ok, reply}))

          other ->
            other
        end
      after
        :gen_udp.close(socket)
      end
    end
  end

  defp deadline(timeout), do: System.monotonic_time(:millisecond) + timeout

  # Ignores packets from elsewhere or with another ID (RFC 5452).
  defp udp_reply(socket, ip, port, id, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    case :gen_udp.recv(socket, 0, remaining) do
      {:ok, {^ip, ^port, <<^id::16, _::binary>> = reply}} -> {:ok, reply}
      {:ok, _other} -> udp_reply(socket, ip, port, id, deadline)
      {:error, _} = error -> error
    end
  end

  # Returns nil on any failure; the truncated UDP answer is used then.
  defp tcp_exchange(ip, port, packet, timeout) do
    case :gen_tcp.connect(ip, port, [:binary, active: false, packet: 2], timeout) do
      {:ok, socket} ->
        try do
          tcp_request(socket, packet, timeout)
        after
          :gen_tcp.close(socket)
        end

      {:error, _} ->
        nil
    end
  end

  defp tcp_request(socket, packet, timeout) do
    with :ok <- :gen_tcp.send(socket, packet),
         {:ok, reply} <- :gen_tcp.recv(socket, 0, timeout) do
      {:ok, reply}
    else
      _ -> nil
    end
  end

  defp answer(<<_::binary-3, flags, _::binary>> = packet, type) do
    authenticated = Bitwise.band(flags, @ad_bit) != 0

    case :inet_dns.decode(packet) do
      {:ok, msg} ->
        case msg |> :inet_dns.msg(:header) |> :inet_dns.header(:rcode) do
          0 -> {:ok, extract(msg, type), authenticated}
          2 -> {:error, :servfail}
          3 -> {:error, :nxdomain}
          5 -> {:error, :refused}
          _ -> {:error, :other}
        end

      {:error, _} ->
        {:error, :other}
    end
  end

  @doc false
  # Returns the data of the answer records of `type`. CNAME records that
  # lead to the answer are skipped unless CNAMEs were requested.
  @spec extract(dns_msg :: term(), Sovite.DNS.Resolver.record_type()) :: [term()]
  def extract(msg, type) do
    wire = wire_type(type)

    for rr <- :inet_dns.msg(msg, :anlist),
        :inet_dns.rr(rr, :type) == wire,
        data <- [convert(type, :inet_dns.rr(rr, :data))],
        data != nil,
        do: data
  end

  defp convert(type, ip) when type in [:a, :aaaa], do: ip
  defp convert(:mx, {preference, exchange}), do: {preference, name_to_string(exchange)}
  defp convert(:txt, strings), do: IO.iodata_to_binary(strings)
  defp convert(type, name) when type in [:ptr, :cname], do: name_to_string(name)

  defp convert(:tlsa, <<usage, selector, matching, data::binary>>),
    do: {usage, selector, matching, data}

  defp convert(:tlsa, _malformed), do: nil

  defp name_to_string(name) do
    name |> :erlang.list_to_binary() |> String.trim_trailing(".")
  end

  # Queries go out as raw octets, so only allow printable ASCII without
  # spaces. Internationalized names must be converted to A-labels first.
  defp valid_query_name?(name) when byte_size(name) in 1..@max_name do
    for <<c <- name>>, reduce: true, do: (acc -> acc and c in 33..126)
  end

  defp valid_query_name?(_), do: false

  defp normalize_error(reason) when reason in [:nxdomain, :servfail, :timeout, :refused],
    do: reason

  defp normalize_error(_), do: :other
end
