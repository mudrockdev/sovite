defmodule Sovite.SASL.DovecotTest do
  use ExUnit.Case, async: true

  alias Sovite.SASL.Dovecot
  alias Sovite.Test.FakeDovecot

  setup do
    # Unix socket paths are limited to ~100 bytes: keep it short.
    path = "/tmp/sovite-dovecot-#{System.unique_integer([:positive])}.sock"
    start_supervised!({FakeDovecot, path: path, owner: self(), users: %{"alice" => "secret"}})
    on_exit(fn -> File.rm(path) end)

    client = %{
      remote_ip: {192, 0, 2, 7},
      local_ip: {127, 0, 0, 1},
      remote_port: 4000,
      local_port: 587,
      secured: true
    }

    %{opts: [socket: path, client: client, timeout: 2_000]}
  end

  test "lists Dovecot's mechanisms", %{opts: opts} do
    assert Dovecot.mechanisms(opts) == {:ok, ["PLAIN", "LOGIN"]}
  end

  test "authenticates with PLAIN and an initial response", %{opts: opts} do
    assert Dovecot.start("PLAIN", <<0, "alice", 0, "secret">>, opts) == {:ok, "alice"}

    assert_received {:dovecot, :auth,
                     [
                       "AUTH",
                       "1",
                       "PLAIN",
                       "service=smtp",
                       "secured",
                       "rip=192.0.2.7",
                       "lip=127.0.0.1",
                       "rport=4000",
                       "lport=587",
                       "resp=" <> _
                     ]}

    assert Dovecot.start("PLAIN", <<0, "alice", 0, "nope">>, opts) ==
             {:error, :invalid_credentials, "alice"}
  end

  test "relays challenges", %{opts: opts} do
    assert {:challenge, "Username:", conn} = Dovecot.start("LOGIN", nil, opts)
    assert {:challenge, "Password:", conn} = Dovecot.step(conn, "alice")
    assert Dovecot.step(conn, "secret") == {:ok, "alice"}

    assert {:challenge, "", conn} = Dovecot.start("PLAIN", nil, opts)
    assert Dovecot.abort(conn) == :ok
  end

  test "reports temporary failures", %{opts: opts} do
    assert Dovecot.start("PLAIN", <<0, "tempfail", 0, "x">>, opts) ==
             {:error, :temporary, "tempfail"}

    assert Dovecot.start("PLAIN", <<0, "a", 0, "b">>, socket: "/tmp/nonexistent-sovite.sock") ==
             {:error, :temporary, nil}
  end
end
