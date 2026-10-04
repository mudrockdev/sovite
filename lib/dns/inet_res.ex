defmodule Sovite.DNS.InetRes do
  @moduledoc """
  Default `Sovite.DNS.Resolver`, built on OTP's `:inet_res`.

  It sends queries to the nameservers configured for the VM (usually from
  `/etc/resolv.conf`). It does not cache results and does not validate
  DNSSEC.

  ## Options

    * `:nameservers` - list of `{ip, port}` tuples that override the system
      nameservers.
    * `:timeout` - per-query timeout in milliseconds. Defaults to `5000`.
    * `:retry` - number of retries per nameserver. Defaults to `2`.
  """

  @behaviour Sovite.DNS.Resolver

  @max_name 253

  @impl true
  def lookup(name, type, opts \\ []) do
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

  @doc false
  # Returns the data of the answer records of `type`. CNAME records that
  # lead to the answer are skipped unless CNAMEs were requested.
  @spec extract(dns_msg :: term(), Sovite.DNS.Resolver.record_type()) :: [term()]
  def extract(msg, type) do
    for rr <- :inet_dns.msg(msg, :anlist), :inet_dns.rr(rr, :type) == type do
      convert(type, :inet_dns.rr(rr, :data))
    end
  end

  defp convert(type, ip) when type in [:a, :aaaa], do: ip
  defp convert(:mx, {preference, exchange}), do: {preference, name_to_string(exchange)}
  defp convert(:txt, strings), do: IO.iodata_to_binary(strings)
  defp convert(type, name) when type in [:ptr, :cname], do: name_to_string(name)

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
