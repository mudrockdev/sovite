defmodule Sovite.SPF.Eval do
  @moduledoc false
  # Evaluates SPF records for Sovite.SPF (RFC 7208 §4-§6).
  #
  # The lookup counters are threaded through every call, since the limits
  # span nested includes and redirects. Errors are thrown as
  # {:spf_error, result, reason}: a temperror or permerror anywhere,
  # including inside an include, ends the whole check.

  alias Sovite.DNS
  alias Sovite.SPF.{Macro, Record, Result}

  # RFC 7208 §4.6.4: at most 10 MX records and 10 PTR names per term.
  @max_mx 10
  @max_ptr 10

  @spec check(DNS.resolver(), :inet.ip_address(), String.t(), String.t(), keyword()) ::
          Result.t()
  def check(resolver, ip, domain, sender, opts) do
    state = %{
      resolver: resolver,
      ip: Sovite.Net.normalize(ip),
      helo: opts[:helo],
      receiver: opts[:receiver],
      now: opts[:now] || System.os_time(:second),
      max_lookups: opts[:max_lookups],
      max_void_lookups: opts[:max_void_lookups],
      lookups: 0,
      voids: 0
    }

    {result, _state} = check_host(domain, normalize_sender(sender), state, true)
    result
  catch
    {:spf_error, result, reason} -> %Result{result: result, reason: reason}
  end

  @spec sender_domain(String.t()) :: String.t()
  def sender_domain(sender), do: sender |> String.split("@") |> List.last()

  # RFC 7208 §4.3: a sender without a local part is postmaster.
  defp normalize_sender(sender) do
    case String.split(sender, "@") do
      [domain] -> "postmaster@" <> domain
      ["", domain] -> "postmaster@" <> domain
      _ -> sender
    end
  end

  defp fail!(result, reason), do: throw({:spf_error, result, reason})

  defp check_host(domain, sender, state, explain?) do
    with true <- valid_domain?(domain),
         {:ok, terms} <- fetch_record(domain, state) do
      evaluate(terms, %{domain: domain, sender: sender}, state, explain?)
    else
      false -> {%Result{result: :none, reason: "invalid domain #{inspect(domain)}"}, state}
      :none -> {%Result{result: :none, reason: "no SPF record"}, state}
    end
  end

  # RFC 7208 §4.3: a malformed or single-label domain gives "none".
  defp valid_domain?(domain) do
    name = String.replace_suffix(domain, ".", "")
    labels = String.split(name, ".")

    byte_size(name) <= 253 and length(labels) >= 2 and
      Enum.all?(labels, &(byte_size(&1) in 1..63))
  end

  defp fetch_record(domain, state) do
    records =
      case DNS.lookup(state.resolver, domain, :txt) do
        {:ok, records} -> Enum.filter(records, &(is_binary(&1) and Record.spf?(&1)))
        {:error, :nxdomain} -> []
        {:error, reason} -> fail!(:temperror, dns_error(domain, reason))
      end

    case records do
      [] -> :none
      [record] -> parse(record)
      _ -> fail!(:permerror, "multiple SPF records")
    end
  end

  defp parse(record) do
    case Record.parse(record) do
      {:ok, terms} -> {:ok, terms}
      {:error, reason} -> fail!(:permerror, reason)
    end
  end

  defp dns_error(name, reason), do: "DNS error for #{name}: #{reason}"

  ## Evaluation (RFC 7208 §4.6, §6)

  defp evaluate(terms, scope, state, explain?) do
    directives = for {_qualifier, _mechanism, _text} = directive <- terms, do: directive

    case match_directives(directives, scope, state) do
      {{qualifier, _mechanism, text}, state} ->
        explanation =
          if qualifier == :fail and explain?, do: explain(find(terms, :exp), scope, state)

        {%Result{result: qualifier, mechanism: text, explanation: explanation}, state}

      {nil, state} ->
        case find(terms, :redirect) do
          nil -> {%Result{result: :neutral}, state}
          spec -> redirect(spec, scope, state, explain?)
        end
    end
  end

  defp find(terms, modifier) do
    Enum.find_value(terms, fn
      {^modifier, spec} -> spec
      _ -> nil
    end)
  end

  defp match_directives([], _scope, state), do: {nil, state}

  defp match_directives([{_qualifier, mechanism, _text} = directive | rest], scope, state) do
    case match(mechanism, scope, state) do
      {true, state} -> {directive, state}
      {false, state} -> match_directives(rest, scope, state)
    end
  end

  # RFC 7208 §6.1: the redirect target's result is the result, and its
  # own exp= gives the explanation.
  defp redirect(spec, scope, state, explain?) do
    state = count_lookup(state)
    {target, state} = expand_domain(spec, scope, state)

    case check_host(target, scope.sender, state, explain?) do
      {%Result{result: :none}, _state} ->
        fail!(:permerror, "no SPF record at redirect target #{target}")

      {result, state} ->
        {result, state}
    end
  end

  ## Mechanisms (RFC 7208 §5)

  defp match(:all, _scope, state), do: {true, state}

  defp match({:ip4, network, length}, _scope, state),
    do: {in_prefix?(state.ip, network, length), state}

  defp match({:ip6, network, length}, _scope, state),
    do: {in_prefix?(state.ip, network, length), state}

  defp match({:include, spec}, scope, state) do
    state = count_lookup(state)
    {target, state} = expand_domain(spec, scope, state)

    # RFC 7208 §5.2: the included record's exp= is never used.
    case check_host(target, scope.sender, state, false) do
      {%Result{result: :pass}, state} ->
        {true, state}

      {%Result{result: result}, state} when result in [:fail, :softfail, :neutral] ->
        {false, state}

      {%Result{result: :none}, _state} ->
        fail!(:permerror, "no SPF record at include target #{target}")
    end
  end

  defp match({:a, spec, cidr}, scope, state) do
    state = count_lookup(state)
    {target, state} = target(spec, scope, state)
    {addresses, state} = query(state, target, address_type(state.ip))
    {any_in_cidr?(addresses, cidr, state), state}
  end

  defp match({:mx, spec, cidr}, scope, state) do
    state = count_lookup(state)
    {target, state} = target(spec, scope, state)
    {records, state} = query(state, target, :mx)

    if length(records) > @max_mx, do: fail!(:permerror, "too many MX records for #{target}")

    hosts = for {_preference, host} <- records, host not in ["", "."], do: host
    {mx_match?(hosts, cidr, state), state}
  end

  defp match({:ptr, spec}, scope, state) do
    state = count_lookup(state)
    {target, state} = target(spec, scope, state)
    {names, state} = ptr_names(state)

    matched =
      names
      |> Enum.filter(&subdomain?(&1, target))
      |> Enum.any?(&validated?(&1, state))

    {matched, state}
  end

  defp match({:exists, spec}, scope, state) do
    state = count_lookup(state)
    {target, state} = expand_domain(spec, scope, state)
    # RFC 7208 §5.7: always an A lookup, even for IPv6 clients.
    {addresses, state} = query(state, target, :a)
    {addresses != [], state}
  end

  # The MX hosts' address lookups do not count toward the limits. A host
  # that fails to resolve is a temperror unless another host matches.
  defp mx_match?(hosts, cidr, state) do
    result =
      Enum.reduce_while(hosts, nil, fn host, error ->
        case mx_host(host, cidr, state) do
          :match -> {:halt, :match}
          :no_match -> {:cont, error}
          {:error, reason} -> {:cont, error || reason}
        end
      end)

    case result do
      :match -> true
      nil -> false
      reason -> fail!(:temperror, reason)
    end
  end

  defp mx_host(host, cidr, state) do
    case DNS.lookup(state.resolver, host, address_type(state.ip)) do
      {:ok, addresses} -> if any_in_cidr?(addresses, cidr, state), do: :match, else: :no_match
      {:error, :nxdomain} -> :no_match
      {:error, reason} -> {:error, dns_error(host, reason)}
    end
  end

  defp address_type({_, _, _, _}), do: :a
  defp address_type(_ip), do: :aaaa

  defp any_in_cidr?(addresses, cidr, state),
    do: Enum.any?(addresses, &in_cidr?(state.ip, &1, cidr))

  defp in_cidr?(ip, address, {ip4, _ip6}) when tuple_size(ip) == 4,
    do: in_prefix?(ip, address, ip4)

  defp in_cidr?(ip, address, {_ip4, ip6}), do: in_prefix?(ip, address, ip6)

  defp in_prefix?(ip, network, length) when tuple_size(ip) == tuple_size(network),
    do: prefix(ip, length) == prefix(network, length)

  defp in_prefix?(_ip, _network, _length), do: false

  defp prefix(ip, length) do
    size = if tuple_size(ip) == 4, do: 8, else: 16
    bits = for part <- Tuple.to_list(ip), into: <<>>, do: <<part::size(size)>>
    <<prefix::bitstring-size(^length), _::bitstring>> = bits
    prefix
  end

  ## DNS lookups and limits (RFC 7208 §4.6.4)

  defp count_lookup(state) do
    lookups = state.lookups + 1
    if lookups > state.max_lookups, do: fail!(:permerror, "too many DNS lookups")
    %{state | lookups: lookups}
  end

  defp count_void(state) do
    voids = state.voids + 1
    if voids > state.max_void_lookups, do: fail!(:permerror, "too many void DNS lookups")
    %{state | voids: voids}
  end

  # A lookup made by a term: NXDOMAIN and NODATA are void, other errors
  # are temperrors. A name with an empty or too long label cannot exist.
  defp query(state, name, type) do
    if valid_name?(name) do
      case DNS.lookup(state.resolver, name, type) do
        {:ok, [_ | _] = records} -> {records, state}
        {:ok, []} -> {[], count_void(state)}
        {:error, :nxdomain} -> {[], count_void(state)}
        {:error, reason} -> fail!(:temperror, dns_error(name, reason))
      end
    else
      {[], state}
    end
  end

  defp valid_name?(name) do
    name
    |> String.replace_suffix(".", "")
    |> String.split(".")
    |> Enum.all?(&(byte_size(&1) in 1..63))
  end

  # RFC 7208 §5.5: a DNS error on the PTR lookup is no match, not a
  # temperror.
  defp ptr_names(state) do
    case DNS.lookup(state.resolver, reverse_name(state.ip), :ptr) do
      {:ok, [_ | _] = names} -> {Enum.take(names, @max_ptr), state}
      {:ok, []} -> {[], count_void(state)}
      {:error, :nxdomain} -> {[], count_void(state)}
      {:error, _reason} -> {[], state}
    end
  end

  defp validated?(name, state) do
    case DNS.lookup(state.resolver, name, address_type(state.ip)) do
      {:ok, addresses} -> state.ip in addresses
      {:error, _reason} -> false
    end
  end

  defp reverse_name(ip) do
    suffix = if tuple_size(ip) == 4, do: "in-addr.arpa", else: "ip6.arpa"
    labels = ip |> Macro.dotted() |> String.split(".") |> Enum.reverse()
    Enum.join(labels ++ [suffix], ".")
  end

  defp subdomain?(name, domain) do
    name = normalize(name)
    domain = normalize(domain)
    name == domain or String.ends_with?(name, "." <> domain)
  end

  defp normalize(name), do: name |> String.trim_trailing(".") |> String.downcase(:ascii)

  ## Macros (RFC 7208 §7)

  defp target(nil, scope, state), do: {scope.domain, state}
  defp target(spec, scope, state), do: expand_domain(spec, scope, state)

  defp expand_domain(spec, scope, state) do
    {context, state} = context(spec, scope, state)
    {Macro.expand_domain(spec, context), state}
  end

  defp context(macro, scope, state) do
    context = %{
      sender: scope.sender,
      domain: scope.domain,
      ip: state.ip,
      helo: state.helo,
      receiver: state.receiver,
      now: state.now
    }

    if Macro.uses_ptr?(macro) do
      state = count_lookup(state)
      {name, state} = ptr_name(scope.domain, state)
      {Map.put(context, :ptr, name), state}
    else
      {context, state}
    end
  end

  # RFC 7208 §7.3: prefer a validated name in the current domain.
  defp ptr_name(domain, state) do
    {names, state} = ptr_names(state)
    {preferred, others} = Enum.split_with(names, &subdomain?(&1, domain))
    {Enum.find(preferred ++ others, "unknown", &validated?(&1, state)), state}
  end

  # RFC 7208 §6.2: any problem with the explanation leaves it out; it
  # never changes the result.
  defp explain(nil, _scope, _state), do: nil

  defp explain(spec, scope, state) do
    {name, state} = expand_domain(spec, scope, state)

    with true <- valid_name?(name),
         {:ok, [text]} when is_binary(text) <- DNS.lookup(state.resolver, name, :txt),
         {:ok, macro} <- Macro.parse(text, :explanation) do
      {context, _state} = context(macro, scope, state)
      Macro.expand(macro, context)
    else
      _ -> nil
    end
  catch
    {:spf_error, _result, _reason} -> nil
  end
end
