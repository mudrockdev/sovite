defmodule Sovite.Test.FakeLDAP do
  @moduledoc """
  A tiny LDAP server for tests, using OTP's `ELDAPv3` codec.

      {:ok, ldap} = FakeLDAP.start_link(
        entries: [{"uid=alice,ou=people,dc=test", %{"mail" => ["alice@example.com"], "objectClass" => ["person"]}}],
        passwords: %{"uid=alice,ou=people,dc=test" => "secret", "cn=svc,dc=test" => "svcpw"}
      )

  Supports simple bind, search (equality, presence, and, or, not; the
  requested attributes are returned), StartTLS
  (with `tls: ssl_server_opts`), and unbind. Every search filter is sent
  to the owner as `{:fake_ldap, :search, filter}`, every bind as
  `{:fake_ldap, :bind, dn}`.
  """

  use GenServer

  @starttls ~c"1.3.6.1.4.1.1466.20037"

  def start_link(opts) do
    opts = Keyword.put_new(opts, :owner, self())
    GenServer.start_link(__MODULE__, opts)
  end

  def port(server), do: GenServer.call(server, :port)

  @impl true
  def init(opts) do
    {:ok, listen} =
      :gen_tcp.listen(0, [
        :binary,
        ip: {127, 0, 0, 1},
        active: false,
        packet: :asn1,
        reuseaddr: true
      ])

    {:ok, port} = :inet.port(listen)
    config = Map.new(opts)
    spawn_link(fn -> accept(listen, config) end)
    {:ok, %{listen: listen, port: port}}
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, state.port, state}

  defp accept(listen, config) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        pid = spawn(fn -> receive(do: (:go -> serve({:gen_tcp, socket}, config, nil))) end)
        :gen_tcp.controlling_process(socket, pid)
        send(pid, :go)
        accept(listen, config)

      _ ->
        :ok
    end
  end

  defp serve({transport, socket} = conn, config, bound) do
    case transport.recv(socket, 0, 10_000) do
      {:ok, data} ->
        {:ok, {:LDAPMessage, id, op, _}} = :ELDAPv3.decode(:LDAPMessage, data)
        handle(op, id, conn, config, bound)

      _ ->
        transport.close(socket)
    end
  end

  defp handle(
         {:bindRequest, {:BindRequest, 3, dn, {:simple, password}}},
         id,
         conn,
         config,
         _bound
       ) do
    dn = to_string(dn)
    send(config.owner, {:fake_ldap, :bind, dn})

    code =
      cond do
        dn == "" -> :success
        Map.get(config.passwords, dn) == to_string(password) -> :success
        true -> :invalidCredentials
      end

    reply(
      conn,
      id,
      {:bindResponse, {:BindResponse, code, ~c"", ~c"", :asn1_NOVALUE, :asn1_NOVALUE}}
    )

    serve(conn, config, if(code == :success, do: dn))
  end

  defp handle({:searchRequest, request}, id, conn, config, bound) do
    {:SearchRequest, _base, _scope, _deref, _size, _time, _types, filter, wanted} = request
    send(config.owner, {:fake_ldap, :search, filter})

    if Map.get(config, :require_bind, false) and bound in [nil, ""] do
      reply(conn, id, {:searchResDone, result(:insufficientAccessRights)})
    else
      for {dn, attrs} <- config.entries, matches?(filter, attrs) do
        reply(
          conn,
          id,
          {:searchResEntry,
           {:SearchResultEntry, String.to_charlist(dn), attributes(attrs, wanted)}}
        )
      end

      reply(conn, id, {:searchResDone, result(:success)})
    end

    serve(conn, config, bound)
  end

  defp handle(
         {:extendedReq, {:ExtendedRequest, @starttls, _}},
         id,
         {:gen_tcp, socket} = conn,
         config,
         bound
       ) do
    reply(
      conn,
      id,
      {:extendedResp,
       {:ExtendedResponse, :success, ~c"", ~c"", :asn1_NOVALUE, @starttls, :asn1_NOVALUE}}
    )

    {:ok, ssl} = :ssl.handshake(socket, config.tls, 5_000)
    serve({:ssl, ssl}, config, bound)
  end

  defp handle({:unbindRequest, _}, _id, {transport, socket}, _config, _bound),
    do: transport.close(socket)

  # The requested attributes the entry has, as PartialAttributes.
  defp attributes(attrs, wanted) do
    for name <- wanted,
        values = Map.get(attrs, to_string(name)),
        values != nil,
        do: {:PartialAttribute, name, Enum.map(values, &String.to_charlist/1)}
  end

  defp result(code), do: {:LDAPResult, code, ~c"", ~c"", :asn1_NOVALUE}

  defp reply({transport, socket}, id, op) do
    {:ok, bytes} = :ELDAPv3.encode(:LDAPMessage, {:LDAPMessage, id, op, :asn1_NOVALUE})
    transport.send(socket, bytes)
  end

  defp matches?({:and, filters}, attrs), do: Enum.all?(filters, &matches?(&1, attrs))
  defp matches?({:or, filters}, attrs), do: Enum.any?(filters, &matches?(&1, attrs))
  defp matches?({:not, filter}, attrs), do: not matches?(filter, attrs)
  defp matches?({:present, attr}, attrs), do: Map.has_key?(attrs, to_string(attr))

  defp matches?({:equalityMatch, {:AttributeValueAssertion, attr, value}}, attrs) do
    value = value |> to_string() |> String.downcase()
    attrs |> Map.get(to_string(attr), []) |> Enum.any?(&(String.downcase(&1) == value))
  end

  defp matches?(_filter, _attrs), do: false
end
