defmodule Sovite.BackendsFuzzTest do
  # Fuzzing of what authentication backends answer: Dovecot's auth
  # protocol, an OAuth token introspection endpoint, and an LDAP server.
  # Whatever they send, a login ends in a result or an error, and never
  # takes the SMTP session down.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.SASL.Backend.{Introspection, LDAP}
  alias Sovite.SASL.Dovecot
  alias Sovite.Test.{FakeHTTP, Fuzz}

  @moduletag :fuzz
  # `mix fuzz` runs each property many times.
  @moduletag timeout: :infinity

  @handshake "VERSION\t1\t2\nMECH\tPLAIN\tplaintext\nMECH\tLOGIN\tplaintext\nSPID\t1\nCUID\t7\nCOOKIE\tc0ffee\nDONE\n"

  @dovecot_results [
    "OK\t1\tuser=alice\n",
    "CONT\t1\tVXNlcm5hbWU6\n",
    "CONT\t1\t\n",
    "FAIL\t1\tuser=bob\treason=Password mismatch\n",
    "FAIL\t1\tuser=tempfail\ttemp\n",
    "FAIL\t1\tcode=temp_fail\n",
    "OK\t1\tuser=a\x01nb\x01tc\n"
  ]

  property "Dovecot exchanges end in a result or an error" do
    line = fn seeds -> Fuzz.input(seeds, ["\t", "\n", "\x01", "=", "1"]) end

    check all(
            handshake <- line.([@handshake]),
            results <- list_of(line.(@dovecot_results), min_length: 1, max_length: 4),
            mechanism <- member_of(["PLAIN", "LOGIN"]),
            initial <- member_of([nil, "", <<0, "alice", 0, "secret">>]),
            max_runs: Fuzz.runs()
          ) do
      {port, server} = Fuzz.serve([handshake | results])
      opts = [socket: {"127.0.0.1", port}, timeout: 30, client: %{remote_ip: {192, 0, 2, 1}}]

      result = Fuzz.quick(fn -> exchange(Dovecot.start(mechanism, initial, opts), 3) end, 5_000)
      assert dovecot_result?(result), inspect(result)
      Task.shutdown(server, :brutal_kill)
    end
  end

  property "token introspection answers give a user, invalid, or a temporary error" do
    seeds = [
      ~s({"active":true,"username":"alice","exp":4102444800,"scope":"openid smtp"}),
      ~s({"active":true,"sub":"s1","username":"a\\r\\nb"}),
      ~s({"active":false}),
      ~s({"active":true,"username":42,"exp":"never"}),
      ~s([true])
    ]

    check all(
            body <- Fuzz.input(seeds, ["\"", ":", ",", "{", "}", "\\u0000", "true"]),
            status <- member_of([200, 200, 200, 401, 500]),
            max_runs: Fuzz.runs()
          ) do
      {:ok, http} =
        FakeHTTP.start_link(fn _request ->
          {status, [{"content-type", "application/json"}], body}
        end)

      opts = [url: FakeHTTP.url(http, "/introspect"), timeout: 1_000, required_scope: "smtp"]

      case Fuzz.quick(fn -> Introspection.verify_token("alice", "token", opts) end, 5_000) do
        {:ok, user} -> assert is_binary(user) and user != ""
        {:error, :invalid} -> :ok
        {:error, {:temporary, _reason}} -> :ok
      end

      GenServer.stop(http)
    end
  end

  property "LDAP answers give the user, invalid, unknown, or a temporary error" do
    dn = ~c"uid=alice,ou=people,dc=test"

    responses = %{
      bind: [result(:bindResponse, :success), result(:bindResponse, :invalidCredentials)],
      search: [
        [{:searchResEntry, {:SearchResultEntry, dn, []}}, result(:searchResDone, :success)],
        [result(:searchResDone, :success)],
        [
          {:searchResEntry, {:SearchResultEntry, dn, []}},
          {:searchResEntry, {:SearchResultEntry, ~c"uid=twin,dc=test", []}},
          result(:searchResDone, :success)
        ],
        [result(:searchResDone, :sizeLimitExceeded)]
      ]
    }

    check all(
            script <- ldap_script(responses),
            max_runs: Fuzz.runs()
          ) do
      {port, server} = Fuzz.serve_with(&ldap_loop(&1, script), packet: :asn1)

      opts = [
        servers: ["127.0.0.1"],
        port: port,
        security: :none,
        base: "dc=test",
        bind_dn: "cn=svc,dc=test",
        bind_password: "svcpw",
        timeout: 200
      ]

      case Fuzz.quick(fn -> LDAP.verify_password("alice@example.com", "secret", opts) end, 5_000) do
        {:ok, "alice@example.com"} -> :ok
        {:error, reason} when reason in [:invalid, :unknown_user] -> :ok
        {:error, {:temporary, _reason}} -> :ok
      end

      Task.shutdown(server, :brutal_kill)
    end
  end

  defp exchange({:challenge, data, conn}, steps) when steps > 0 do
    assert is_binary(data)
    exchange(Dovecot.step(conn, "secret"), steps - 1)
  end

  defp exchange({:challenge, _data, conn} = result, 0) do
    Dovecot.abort(conn)
    result
  end

  defp exchange(result, _steps), do: result

  defp dovecot_result?({:ok, identity}), do: is_binary(identity) and identity != ""
  defp dovecot_result?({:challenge, data, _conn}), do: is_binary(data)

  defp dovecot_result?({:error, reason, user}),
    do:
      reason in [:invalid_credentials, :temporary, :malformed] and
        (user == nil or is_binary(user))

  defp dovecot_result?(_result), do: false

  defp result(:bindResponse, code),
    do: {:bindResponse, {:BindResponse, code, ~c"", ~c"", :asn1_NOVALUE, :asn1_NOVALUE}}

  defp result(op, code), do: {op, {:LDAPResult, code, ~c"", ~c"", :asn1_NOVALUE}}

  # For each request (service bind, search, user bind), the responses,
  # each encoded and sometimes mutated: as functions of the message ID.
  defp ldap_script(responses) do
    response = fn ops ->
      gen all(
            ops <- member_of(ops),
            mutation <- frequency([{4, constant(nil)}, {1, Fuzz.bytes(max_length: 4)}]),
            cut <- integer(0..40)
          ) do
        {List.wrap(ops), mutation, cut}
      end
    end

    fixed_list([
      response.(responses.bind),
      response.(responses.search),
      response.(responses.bind)
    ])
  end

  defp encode(id, {ops, mutation, cut}) do
    bytes =
      Enum.map_join(ops, fn op ->
        {:ok, bytes} = :ELDAPv3.encode(:LDAPMessage, {:LDAPMessage, id, op, :asn1_NOVALUE})
        IO.iodata_to_binary(bytes)
      end)

    case mutation do
      nil ->
        bytes

      bytes_in ->
        at = rem(cut, byte_size(bytes) + 1)
        <<before::binary-size(^at), rest::binary>> = bytes
        before <> bytes_in <> rest
    end
  end

  defp ldap_loop(socket, [next | script]) do
    with {:ok, data} <- :gen_tcp.recv(socket, 0, 500),
         {:ok, {:LDAPMessage, id, op, _}} <- :ELDAPv3.decode(:LDAPMessage, data),
         false <- match?({:unbindRequest, _}, op) do
      :gen_tcp.send(socket, encode(id, next))
      ldap_loop(socket, script)
    else
      _ -> :gen_tcp.close(socket)
    end
  end

  defp ldap_loop(socket, []), do: :gen_tcp.close(socket)
end
