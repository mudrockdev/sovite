defmodule Sovite.Test.FakeNameserver do
  @moduledoc """
  A UDP DNS server on localhost that answers from a static table. Use it
  to test real resolver code (such as `Sovite.DNS.InetRes`) without
  network access. For code that only needs a resolver, use
  `Sovite.Test.FakeDNS`.

      {:ok, ns} = FakeNameserver.start_link(%{
        {"example.com", :mx} => [{10, ~c"mx.example.com"}],
        {"down.example", :a} => :servfail
      })

      InetRes.lookup("example.com", :mx, nameservers: [FakeNameserver.address(ns)])

  Record data uses `:inet_dns` formats (charlists for names). An entry can
  also be `:servfail` or `:refused`. Names missing from the table get
  NXDOMAIN, and names present with other types get NODATA.
  """

  use GenServer

  @rcodes %{servfail: 2, nxdomain: 3, refused: 5}

  def start_link(records), do: GenServer.start_link(__MODULE__, records)

  @doc "Returns the `{ip, port}` the server listens on."
  def address(server), do: GenServer.call(server, :address)

  @impl true
  def init(records) do
    {:ok, socket} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}, active: true])
    {:ok, port} = :inet.port(socket)

    records =
      Map.new(records, fn {{name, type}, data} -> {{String.downcase(name), type}, data} end)

    {:ok, %{socket: socket, port: port, records: records}}
  end

  @impl true
  def handle_call(:address, _from, state), do: {:reply, {{127, 0, 0, 1}, state.port}, state}

  @impl true
  def handle_info({:udp, socket, ip, port, packet}, state) do
    with {:ok, query} <- :inet_dns.decode(packet) do
      :ok = :gen_udp.send(socket, ip, port, :inet_dns.encode(answer(query, state.records)))
    end

    {:noreply, state}
  end

  defp answer(query, records) do
    [question] = :inet_dns.msg(query, :qdlist)
    name = question |> :inet_dns.dns_query(:domain) |> List.to_string() |> String.downcase()
    type = :inet_dns.dns_query(question, :type)

    {rcode, answers} =
      case Map.fetch(records, {name, type}) do
        {:ok, error} when is_atom(error) -> {Map.fetch!(@rcodes, error), []}
        {:ok, data} -> {0, Enum.map(data, &rr(name, type, &1))}
        :error -> if known_name?(records, name), do: {0, []}, else: {@rcodes.nxdomain, []}
      end

    header =
      query
      |> :inet_dns.msg(:header)
      |> :inet_dns.make_header(qr: true, aa: true, ra: true, rcode: rcode)

    :inet_dns.make_msg(header: header, qdlist: [question], anlist: answers)
  end

  defp known_name?(records, name), do: Enum.any?(Map.keys(records), &match?({^name, _}, &1))

  defp rr(name, type, data),
    do:
      :inet_dns.make_rr(
        domain: String.to_charlist(name),
        type: type,
        class: :in,
        ttl: 60,
        data: data
      )
end
