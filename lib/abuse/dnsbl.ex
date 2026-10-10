defmodule Sovite.Abuse.DNSBL do
  @moduledoc """
  Scores a client address or a domain against DNS block and allow lists
  (RFC 5782): IP lists (DNSBL, DNSWL) and domain lists (RHSBL).

      lists = [
        %{zone: "zen.spamhaus.org", weight: 3, codes: []},
        %{zone: "b.barracudacentral.org", weight: 2, codes: []},
        %{zone: "list.dnswl.org", weight: -2, codes: [pattern]}
      ]

      DNSBL.score(resolver, {:ip, ip}, lists)
      #=> %{score: 3, hits: [%{zone: "zen.spamhaus.org", weight: 3, codes: [{127, 0, 0, 2}]}], errors: []}

  Each list that lists the target adds its weight to the score. A
  negative weight makes an allow list. `codes` holds reply-code patterns
  from `parse_code/1`: the list counts only if one of its answers matches
  one of them. With no patterns, any answer counts. Lists of the same
  zone share one query, so one zone can be scored per reply code.

  Lists that fail or time out add nothing to the score and are reported
  in `errors`.

  ## Options

    * `:timeout` - milliseconds for all queries together. Defaults to
      10 seconds.

  ## Telemetry

    * `[:sovite, :abuse, :dnsbl, :listed]` - `%{weight}`, `%{zone, query,
      codes}`, for each list that lists the target. `query` is the IP
      address or the domain, and `codes` the matching answers.
    * `[:sovite, :abuse, :dnsbl, :error]` - `%{}`, `%{zone, query,
      reason}`, for each query that failed. `reason` is `:timeout` if it
      timed out.
  """

  import Kernel, except: [match?: 2]

  alias Sovite.DNS

  @default_timeout 10_000
  # How long a background scoring waits for await/2 beyond its timeout.
  @await_grace 5_000

  @typedoc """
  A reply-code pattern, from `parse_code/1`. Treat it as opaque.
  """
  @type pattern :: {octet_spec(), octet_spec(), octet_spec(), octet_spec()}

  @typep octet_spec :: [{byte(), byte()}, ...]

  @typedoc "A list zone, the weight it adds, and the reply codes it counts."
  @type list_spec :: %{zone: String.t(), weight: integer(), codes: [pattern()]}

  @typedoc "What to look up: a client address or a domain."
  @type target :: {:ip, :inet.ip_address()} | {:domain, String.t()}

  @typedoc "A list that lists the target, and its matching answers."
  @type hit :: %{zone: String.t(), weight: integer(), codes: [:inet.ip4_address(), ...]}

  @typedoc "The result of `score/4`."
  @type result :: %{score: integer(), hits: [hit()], errors: [String.t()]}

  @typedoc "A background scoring started by `async_score/4`."
  @opaque handle :: %{pid: pid()}

  @octet_spec ~S"(\d{1,3}|\[[^\[\]]*\])"
  @code_regex Regex.compile!(
                "\\A#{@octet_spec}\\.#{@octet_spec}\\.#{@octet_spec}\\.#{@octet_spec}\\z"
              )

  @doc """
  Parses a reply-code pattern, in Postfix postscreen syntax.

  A pattern is four dot-separated octets. Each is a number from 0 to
  255, or a bracketed list of numbers and `N..M` ranges separated by
  `;`. The error is a message for the administrator.

      iex> {:ok, pattern} = Sovite.Abuse.DNSBL.parse_code("127.0.0.[2..11;20]")
      iex> Sovite.Abuse.DNSBL.match?([{127, 0, 0, 20}], [pattern])
      true
  """
  @spec parse_code(String.t()) :: {:ok, pattern()} | {:error, String.t()}
  def parse_code(code) when is_binary(code) do
    with [_ | octets] <- Regex.run(@code_regex, code) || :error,
         {:ok, specs} <- parse_octets(octets) do
      {:ok, List.to_tuple(specs)}
    else
      :error ->
        {:error,
         "invalid reply code #{inspect(code)}: expected four dot-separated octets, " <>
           "such as 127.0.0.2 or 127.0.0.[2..11;20]"}

      {:error, reason} ->
        {:error, "invalid reply code #{inspect(code)}: #{reason}"}
    end
  end

  defp parse_octets(octets), do: map_ok(octets, &parse_octet/1)

  defp parse_octet("[" <> rest),
    do: rest |> String.trim_trailing("]") |> String.split(";") |> map_ok(&parse_range/1)

  defp parse_octet(number), do: with({:ok, range} <- parse_range(number), do: {:ok, [range]})

  defp parse_range(item) do
    case item |> String.split("..") |> map_ok(&parse_number/1) do
      {:ok, [n]} -> {:ok, {n, n}}
      {:ok, [n, m]} when n <= m -> {:ok, {n, m}}
      {:ok, [_n, _m]} -> {:error, "empty range #{item}"}
      {:ok, _numbers} -> {:error, "invalid range #{inspect(item)}"}
      error -> error
    end
  end

  defp parse_number(string) do
    with true <- string =~ ~r/\A\d{1,3}\z/,
         n when n <= 255 <- String.to_integer(string) do
      {:ok, n}
    else
      false -> {:error, "invalid number #{inspect(string)}"}
      _n -> {:error, "#{string} is not between 0 and 255"}
    end
  end

  defp map_ok(items, fun) do
    Enum.reduce_while(items, {:ok, []}, fn item, {:ok, results} ->
      case fun.(item) do
        {:ok, result} -> {:cont, {:ok, results ++ [result]}}
        error -> {:halt, error}
      end
    end)
  end

  @doc """
  Returns the name to query for `ip` in an IP list `zone`: the octets
  reversed for IPv4 (RFC 5782 §2.1), or the 32 nibbles reversed for IPv6
  (§2.4). IPv4-mapped IPv6 addresses are queried as IPv4.

      iex> Sovite.Abuse.DNSBL.query_name({192, 0, 2, 99}, "dnsbl.example.")
      "99.2.0.192.dnsbl.example"
  """
  @spec query_name(:inet.ip_address(), String.t()) :: String.t()
  def query_name(ip, zone), do: reversed(Sovite.Net.normalize(ip)) <> "." <> normalize(zone)

  defp reversed({_, _, _, _} = ip), do: ip |> Tuple.to_list() |> Enum.reverse() |> Enum.join(".")

  defp reversed(ip) do
    bytes = for part <- Tuple.to_list(ip), into: <<>>, do: <<part::16>>
    bytes |> Base.encode16(case: :lower) |> String.graphemes() |> Enum.reverse() |> Enum.join(".")
  end

  @doc """
  Returns the name to query for `domain` in a domain list `zone` (RFC
  5782 §2.3), or `:error` if `domain` is empty, an address literal, or
  too long for the result to be a domain name.

      iex> Sovite.Abuse.DNSBL.domain_query_name("Example.COM.", "rhsbl.example")
      {:ok, "example.com.rhsbl.example"}
  """
  @spec domain_query_name(String.t(), String.t()) :: {:ok, String.t()} | :error
  def domain_query_name(domain, zone) when is_binary(domain) do
    case normalize(domain) do
      "" -> :error
      "[" <> _ -> :error
      domain -> fit(domain <> "." <> normalize(zone))
    end
  end

  defp fit(name) when byte_size(name) <= 253, do: {:ok, name}
  defp fit(_name), do: :error

  defp normalize(name), do: name |> String.trim_trailing(".") |> String.downcase(:ascii)

  @doc """
  Looks up `name` in a list.

  A name that is not listed returns `{:ok, []}`. Only answers in
  127.0.0.0/8 are returned (RFC 5782 §2.1). Answers in 127.255.255.0/24
  are errors from the list operator, such as Spamhaus refusing queries
  from public resolvers, and return `{:error, {:list_error, ip}}`.
  """
  @spec lookup(DNS.resolver(), String.t()) ::
          {:ok, [:inet.ip4_address()]} | {:error, term()}
  def lookup(resolver, name) do
    case DNS.lookup(resolver, name, :a) do
      {:ok, records} -> answers(records)
      {:error, :nxdomain} -> {:ok, []}
      {:error, reason} -> {:error, reason}
    end
  end

  defp answers(records) do
    case Enum.find(records, &Kernel.match?({127, 255, 255, _}, &1)) do
      nil -> {:ok, for({127, _, _, _} = ip <- records, do: ip)}
      ip -> {:error, {:list_error, ip}}
    end
  end

  @doc """
  Returns whether any of `addresses` matches any of the `codes` patterns.
  With no patterns, any address matches.
  """
  @spec match?([:inet.ip4_address()], [pattern()]) :: boolean()
  def match?(addresses, codes), do: matching(addresses, codes) != []

  defp matching(addresses, []), do: addresses
  defp matching(addresses, codes), do: Enum.filter(addresses, &matches_any?(&1, codes))

  defp matches_any?(address, codes), do: Enum.any?(codes, &matches?(address, &1))

  defp matches?({a, b, c, d}, {sa, sb, sc, sd}),
    do: in_spec?(a, sa) and in_spec?(b, sb) and in_spec?(c, sc) and in_spec?(d, sd)

  defp in_spec?(n, spec), do: Enum.any?(spec, fn {first, last} -> n >= first and n <= last end)

  @doc """
  Looks up `target` in all `lists` at once and adds up the weights of the
  lists that list it. See the module documentation for the options.

  A domain that cannot be queried (see `domain_query_name/2`) scores 0.
  """
  @spec score(DNS.resolver(), target(), [list_spec()], keyword()) :: result()
  def score(resolver, target, lists, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    named = for list <- lists, {:ok, name} <- [name(target, list.zone)], do: {name, list}
    queries = Enum.uniq_by(named, fn {name, _list} -> name end)
    results = run(resolver, queries, timeout)

    for {name, list} <- queries, {:error, reason} <- [Map.fetch!(results, name)] do
      :telemetry.execute([:sovite, :abuse, :dnsbl, :error], %{}, %{
        zone: list.zone,
        query: query(target),
        reason: reason
      })
    end

    result =
      Enum.reduce(named, %{score: 0, hits: [], errors: []}, fn {name, list}, acc ->
        add(acc, list, Map.fetch!(results, name), target)
      end)

    %{
      result
      | hits: Enum.reverse(result.hits),
        errors: result.errors |> Enum.reverse() |> Enum.uniq()
    }
  end

  defp name({:ip, ip}, zone), do: {:ok, query_name(ip, zone)}
  defp name({:domain, domain}, zone), do: domain_query_name(domain, zone)

  defp query({_kind, query}), do: query

  defp run(_resolver, [], _timeout), do: %{}

  defp run(resolver, queries, timeout) do
    queries
    |> Task.async_stream(fn {name, _list} -> lookup(resolver, name) end,
      timeout: timeout,
      on_timeout: :kill_task,
      max_concurrency: length(queries)
    )
    |> Enum.zip_with(queries, fn
      {:ok, result}, {name, _list} -> {name, result}
      {:exit, :timeout}, {name, _list} -> {name, {:error, :timeout}}
    end)
    |> Map.new()
  end

  defp add(acc, list, {:error, _reason}, _target), do: %{acc | errors: [list.zone | acc.errors]}

  defp add(acc, list, {:ok, addresses}, target) do
    case matching(addresses, list.codes) do
      [] ->
        acc

      codes ->
        :telemetry.execute([:sovite, :abuse, :dnsbl, :listed], %{weight: list.weight}, %{
          zone: list.zone,
          query: query(target),
          codes: codes
        })

        hit = %{zone: list.zone, weight: list.weight, codes: codes}
        %{acc | score: acc.score + list.weight, hits: [hit | acc.hits]}
    end
  end

  @doc """
  Starts `score/4` in the background, for example when a client
  connects, and returns a handle for `await/2`, for example at `RCPT`.

  The background process is not linked to the caller and sends it
  nothing until `await/2` asks, so it suits a process that traps exits.
  It exits when the caller exits, and on its own if `await/2` has not
  asked within 5 seconds after the `:timeout` option.
  """
  @spec async_score(DNS.resolver(), target(), [list_spec()], keyword()) :: handle()
  def async_score(resolver, target, lists, opts \\ []) do
    caller = self()
    deadline = now() + Keyword.get(opts, :timeout, @default_timeout) + @await_grace

    pid =
      spawn(fn ->
        server = self()

        worker =
          spawn_link(fn ->
            send(server, {:result, self(), score(resolver, target, lists, opts)})
          end)

        serve(
          %{caller: Process.monitor(caller), worker: worker, result: nil, from: nil},
          deadline
        )
      end)

    %{pid: pid}
  end

  # Waits for the result and for await/2, in either order, then replies
  # once and exits. Exiting with :shutdown also stops the linked worker.
  defp serve(%{result: {:ok, result}, from: {pid, ref}}, _deadline), do: send(pid, {ref, result})

  defp serve(%{worker: worker, caller: caller_ref} = state, deadline) do
    receive do
      {:result, ^worker, result} ->
        serve(%{state | result: {:ok, result}}, deadline)

      {:await, pid, ref} ->
        serve(%{state | from: {pid, ref}}, deadline)

      {:DOWN, ^caller_ref, :process, _pid, _reason} ->
        exit(:shutdown)
    after
      max(deadline - now(), 0) -> exit(:shutdown)
    end
  end

  defp now, do: System.monotonic_time(:millisecond)

  @doc """
  Waits up to `timeout` milliseconds for the result of `async_score/4`.

  Returns `{:error, :timeout}` if the result is not ready in time or the
  background process is gone. The background process is then killed,
  and no message from it is left in the caller's mailbox. Each handle
  can be awaited only once.
  """
  @spec await(handle(), timeout()) :: {:ok, result()} | {:error, :timeout}
  def await(%{pid: pid}, timeout) do
    ref = Process.monitor(pid)
    send(pid, {:await, self(), ref})

    receive do
      {^ref, result} ->
        Process.demonitor(ref, [:flush])
        {:ok, result}

      {:DOWN, ^ref, :process, _pid, _reason} ->
        {:error, :timeout}
    after
      timeout ->
        Process.exit(pid, :kill)

        # The process's messages all arrive before its :DOWN, so a reply
        # sent just before it died is flushed here.
        receive do
          {:DOWN, ^ref, :process, _pid, _reason} -> :ok
        end

        receive do
          {^ref, _result} -> :ok
        after
          0 -> :ok
        end

        {:error, :timeout}
    end
  end
end
