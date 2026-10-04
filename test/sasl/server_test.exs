defmodule Sovite.SASL.ServerTest do
  use ExUnit.Case, async: true

  alias Sovite.SASL.{Login, OAuthBearer, Password, Plain, ScramSHA256, Server}

  defmodule Backend do
    @moduledoc false
    @behaviour Sovite.SASL.Backend

    @users %{
      "alice" => Password.hash("secret", :scram_sha256),
      "bob" => Password.hash("hunter2", :sha512_crypt)
    }

    @impl true
    def verify_password("down", _password, _opts), do: {:error, {:temporary, :timeout}}

    def verify_password(user, password, _opts) do
      with {:ok, hash} <- Map.fetch(@users, String.downcase(user)),
           :ok <- Password.verify(hash, password) do
        {:ok, String.downcase(user)}
      else
        _ -> {:error, :invalid}
      end
    end

    @impl true
    def scram_credentials("down", _opts), do: {:error, {:temporary, :timeout}}

    def scram_credentials(user, _opts) do
      case Map.fetch(@users, user) do
        {:ok, hash} ->
          case Password.scram_credentials(hash) do
            {:ok, credentials} -> {:ok, credentials, user}
            :error -> {:error, :unavailable}
          end

        :error ->
          {:error, :unknown_user}
      end
    end

    @impl true
    def verify_token(_user, "good-token", _opts), do: {:ok, "alice"}
    def verify_token(_user, "down-token", _opts), do: {:error, {:temporary, :econnrefused}}
    def verify_token(_user, _token, _opts), do: {:error, :invalid}
  end

  defmodule PasswordOnly do
    @moduledoc false
    @behaviour Sovite.SASL.Backend
    @impl true
    def verify_password(_user, _password, _opts), do: {:error, :invalid}
  end

  @opts [backend: {Backend, []}]

  # Runs a client module against the server until the exchange ends.
  defp exchange(mechanism, client, credentials, opts \\ @opts) do
    {:ok, initial, state} = client.client_start(credentials)
    run(Server.start(mechanism, initial, opts), client, state)
  end

  defp run({:challenge, data, server}, client, state) do
    case client.client_step(state, data) do
      {:ok, response, state} -> run(Server.step(server, response), client, state)
      {:error, reason} -> {:client_error, reason}
    end
  end

  defp run(result, _client, _state), do: result

  test "lists the mechanisms the backends support" do
    assert Server.mechanisms(@opts) == ["SCRAM-SHA-256", "PLAIN", "LOGIN", "OAUTHBEARER"]
    assert Server.mechanisms(backend: {PasswordOnly, []}) == ["PLAIN", "LOGIN"]

    assert Server.mechanisms(@opts ++ [mechanisms: ["LOGIN", "PLAIN", "CRAM-MD5"]]) == [
             "LOGIN",
             "PLAIN"
           ]

    assert Server.start("SCRAM-SHA-256", nil, backend: {PasswordOnly, []}) ==
             {:error, :unsupported_mechanism, nil}

    assert Server.start("CRAM-MD5", nil, @opts) == {:error, :unsupported_mechanism, nil}
  end

  describe "PLAIN" do
    test "authenticates with an initial response" do
      assert Server.start("PLAIN", <<0, "Alice", 0, "secret">>, @opts) == {:ok, "alice"}
      assert Server.start("PLAIN", <<"alice", 0, "alice", 0, "secret">>, @opts) == {:ok, "alice"}
      assert Server.start("PLAIN", <<0, "bob", 0, "hunter2">>, @opts) == {:ok, "bob"}
    end

    test "asks for the credentials without one" do
      assert {:challenge, "", server} = Server.start("PLAIN", nil, @opts)
      assert Server.step(server, <<0, "alice", 0, "secret">>) == {:ok, "alice"}
      assert exchange("PLAIN", Plain, %{username: "alice", password: "secret"}) == {:ok, "alice"}
    end

    test "fails on wrong credentials, other identities, and bad syntax" do
      assert Server.start("PLAIN", <<0, "alice", 0, "wrong">>, @opts) ==
               {:error, :invalid_credentials, "alice"}

      assert Server.start("PLAIN", <<"bob", 0, "alice", 0, "secret">>, @opts) ==
               {:error, :authorization_failed, "alice"}

      for message <- [
            "alice",
            <<0, "alice">>,
            <<0, 0, "secret">>,
            <<0, "a", 0, "b", 0, "c">>,
            <<0, "a", 0>>,
            <<0, 255, 0, "x">>
          ] do
        assert Server.start("PLAIN", message, @opts) == {:error, :malformed, nil},
               inspect(message)
      end

      assert Server.start("PLAIN", <<0, "down", 0, "x">>, @opts) == {:error, :temporary, "down"}
    end
  end

  describe "LOGIN" do
    test "asks for user name and password" do
      assert {:challenge, "Username:", server} = Server.start("LOGIN", nil, @opts)
      assert {:challenge, "Password:", server} = Server.step(server, "alice")
      assert Server.step(server, "secret") == {:ok, "alice"}
      assert exchange("LOGIN", Login, %{username: "bob", password: "hunter2"}) == {:ok, "bob"}
    end

    test "takes an initial response as the user name" do
      assert {:challenge, "Password:", server} = Server.start("LOGIN", "alice", @opts)
      assert Server.step(server, "nope") == {:error, :invalid_credentials, "alice"}
    end
  end

  describe "SCRAM-SHA-256" do
    test "authenticates both ways" do
      assert exchange("SCRAM-SHA-256", ScramSHA256, %{username: "alice", password: "secret"}) ==
               {:ok, "alice"}
    end

    test "fails a wrong password the same way as an unknown user" do
      assert exchange("SCRAM-SHA-256", ScramSHA256, %{username: "alice", password: "nope"}) ==
               {:error, :invalid_credentials, "alice"}

      assert exchange("SCRAM-SHA-256", ScramSHA256, %{username: "nobody", password: "x"}) ==
               {:error, :invalid_credentials, "nobody"}

      # The fake salt is stable per name, like a real one.
      salt = fn user ->
        {:challenge, first, _} = Server.start("SCRAM-SHA-256", "n,,n=#{user},r=abc", @opts)
        Regex.run(~r/s=([^,]+)/, first) |> List.last()
      end

      assert salt.("nobody") == salt.("nobody")
      assert salt.("nobody") != salt.("someone")
    end

    test "fails users without SCRAM values" do
      assert exchange("SCRAM-SHA-256", ScramSHA256, %{username: "bob", password: "hunter2"}) ==
               {:error, :no_scram_credentials, "bob"}
    end

    test "matches the RFC 7677 example on the client side" do
      state =
        {:first,
         %{
           bare: "n=user,r=rOprNGfwEbeRWgbNEkqO",
           nonce: "rOprNGfwEbeRWgbNEkqO",
           password: "pencil"
         }}

      server_first =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"

      assert {:ok, final, state} = ScramSHA256.client_step(state, server_first)

      assert final ==
               "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="

      assert {:ok, "", :done} =
               ScramSHA256.client_step(state, "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")

      assert {:error, :server_signature_mismatch} =
               ScramSHA256.client_step(state, "v=" <> Base.encode64(:binary.copy(<<0>>, 32)))
    end

    test "the client rejects a server that does not extend its nonce" do
      {:ok, _, state} = ScramSHA256.client_start(%{username: "u", password: "p"})
      assert {:error, _} = ScramSHA256.client_step(state, "r=other,s=c2FsdA==,i=4096")
    end

    test "rejects protocol violations" do
      for first <- [
            "p=tls-unique,,n=alice,r=abc",
            "n,,n=alice",
            "n,,r=abc",
            "n,,m=ext,n=alice,r=abc",
            "n,,n=al=ice,r=abc",
            "x,,n=alice,r=abc"
          ] do
        assert {:error, :malformed, _} = Server.start("SCRAM-SHA-256", first, @opts), first
      end

      assert {:error, :authorization_failed, "alice"} =
               Server.start("SCRAM-SHA-256", "n,a=bob,n=alice,r=abc", @opts)

      {:challenge, first, server} = Server.start("SCRAM-SHA-256", "n,,n=alice,r=abc", @opts)
      [_, nonce] = Regex.run(~r/r=([^,]+)/, first)

      for final <- [
            "c=biws,r=#{nonce}",
            "c=eSws,r=#{nonce},p=" <> Base.encode64(:binary.copy("x", 32)),
            "c=biws,r=wrong,p=" <> Base.encode64(:binary.copy("x", 32)),
            "c=biws,r=#{nonce},p=short"
          ] do
        assert {:error, :malformed, "alice"} = Server.step(server, final), final
      end
    end

    test "requires an empty response to the server's final message" do
      {:ok, initial, state} = ScramSHA256.client_start(%{username: "alice", password: "secret"})
      {:challenge, first, server} = Server.start("SCRAM-SHA-256", initial, @opts)
      {:ok, final, _} = ScramSHA256.client_step(state, first)
      {:challenge, "v=" <> _, server} = Server.step(server, final)
      assert Server.step(server, "extra") == {:error, :malformed, nil}
    end

    test "reports backend failures as temporary" do
      assert Server.start("SCRAM-SHA-256", "n,,n=down,r=abc", @opts) ==
               {:error, :temporary, "down"}
    end

    test "escapes names" do
      {:ok, initial, _} = ScramSHA256.client_start(%{username: "a,b=c", password: "p"})
      assert initial =~ "n=a=2Cb=3Dc,"
    end
  end

  describe "OAUTHBEARER" do
    test "authenticates with a valid token" do
      assert exchange("OAUTHBEARER", OAuthBearer, %{
               username: "alice",
               token: "good-token",
               host: "mx.test",
               port: 587
             }) ==
               {:ok, "alice"}

      assert Server.start("OAUTHBEARER", "n,,\x01auth=Bearer good-token\x01\x01", @opts) ==
               {:ok, "alice"}
    end

    test "sends an error challenge for a bad token, then fails" do
      assert {:challenge, ~s({"status":"invalid_token"}), server} =
               Server.start("OAUTHBEARER", "n,a=alice,\x01auth=Bearer bad\x01\x01", @opts)

      assert Server.step(server, "\x01") == {:error, :invalid_credentials, "alice"}

      assert exchange("OAUTHBEARER", OAuthBearer, %{username: "alice", token: "bad"}) ==
               {:error, :invalid_credentials, "alice"}
    end

    test "refuses a token for another user" do
      assert {:challenge, _, _} =
               Server.start("OAUTHBEARER", "n,a=bob,\x01auth=Bearer good-token\x01\x01", @opts)
    end

    test "reports backend failures and rejects malformed messages" do
      assert Server.start("OAUTHBEARER", "n,,\x01auth=Bearer down-token\x01\x01", @opts) ==
               {:error, :temporary, nil}

      for message <- [
            "n,,auth=Bearer x",
            "n,,\x01auth=Bearer x\x01",
            "n,,\x01auth=Basic eA==\x01\x01",
            "n,,\x01host=x\x01\x01",
            "q,,\x01auth=Bearer x\x01\x01"
          ] do
        assert Server.start("OAUTHBEARER", message, @opts) == {:error, :malformed, nil},
               inspect(message)
      end
    end
  end
end
