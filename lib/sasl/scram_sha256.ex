defmodule Sovite.SASL.ScramSHA256 do
  @moduledoc """
  The `SCRAM-SHA-256` mechanism (RFC 5802, RFC 7677).

  The password never crosses the wire, the server stores only derived
  keys (see `Sovite.SASL.Password`), and both sides prove they know the
  password. Channel binding (`-PLUS`) is not supported, so a client that
  requires it is refused.

  In SMTP the server's final message, which proves the server knows the
  password, is sent as one more `334` challenge, answered by an empty
  line (RFC 4954 §4).

  For an unknown user the server answers with a salt derived from the
  name and fails at the end, so the exchange does not reveal which users
  exist.
  """

  alias Sovite.SASL
  alias Sovite.SASL.Credentials

  @nonce_bytes 18
  @max_iterations 1_000_000

  ## Server

  @doc false
  def server_start(nil, _context), do: {:challenge, "", :initial}
  def server_start(message, context), do: client_first(message, context)

  @doc false
  def server_step(:initial, message, context), do: client_first(message, context)

  def server_step({:final, exchange}, message, _context), do: client_final(exchange, message)

  def server_step({:done, identity}, "", _context), do: {:ok, identity}
  def server_step({:done, _identity}, _message, _context), do: {:error, :malformed, nil}

  defp client_first(message, context) do
    with {:ok, gs2, bare} <- split_gs2(message),
         {:ok, authzid} <- gs2_authzid(gs2),
         {:ok, username, client_nonce} <- parse_first_bare(bare) do
      if authzid == nil or authzid == username,
        do: server_first(context, gs2, bare, username, client_nonce),
        else: {:error, :authorization_failed, username}
    else
      _ -> {:error, :malformed, nil}
    end
  end

  defp server_first(context, gs2, bare, username, client_nonce) do
    {credentials, identity, failure} =
      case Credentials.scram_credentials(context, username) do
        {:ok, credentials, identity} -> {credentials, identity, nil}
        {:fake, credentials, reason} -> {credentials, nil, reason}
        {:error, :temporary} -> {nil, nil, :temporary}
      end

    if credentials do
      nonce = client_nonce <> nonce()
      first = "r=#{nonce},s=#{Base.encode64(credentials.salt)},i=#{credentials.iterations}"

      exchange = %{
        gs2: gs2,
        auth_prefix: bare <> "," <> first,
        nonce: nonce,
        credentials: credentials,
        username: username,
        identity: identity,
        failure: failure
      }

      {:challenge, first, {:final, exchange}}
    else
      {:error, :temporary, username}
    end
  end

  defp client_final(exchange, message) do
    with [without_proof, proof] <- split_proof(message),
         {:ok, attrs} <- attributes(without_proof),
         {:ok, cbind} <- Map.fetch(attrs, "c"),
         {:ok, ^cbind} <- {:ok, Base.encode64(exchange.gs2)},
         {:ok, nonce} <- Map.fetch(attrs, "r"),
         true <- nonce == exchange.nonce,
         {:ok, proof} <- Base.decode64(proof),
         32 <- byte_size(proof) do
      auth_message = exchange.auth_prefix <> "," <> without_proof
      %{stored_key: stored_key, server_key: server_key} = exchange.credentials
      signature = hmac(stored_key, auth_message)
      client_key = :crypto.exor(proof, signature)

      cond do
        exchange.failure != nil ->
          {:error, exchange.failure, exchange.username}

        SASL.secure_compare(:crypto.hash(:sha256, client_key), stored_key) ->
          final = "v=" <> Base.encode64(hmac(server_key, auth_message))
          {:challenge, final, {:done, exchange.identity}}

        true ->
          {:error, :invalid_credentials, exchange.username}
      end
    else
      _ -> {:error, :malformed, exchange.username}
    end
  end

  defp split_proof(message) do
    case :binary.matches(message, ",p=") do
      [] ->
        :error

      matches ->
        {index, _} = List.last(matches)

        [
          binary_part(message, 0, index),
          binary_part(message, index + 3, byte_size(message) - index - 3)
        ]
    end
  end

  # gs2-header = gs2-cbind-flag "," [authzid] ","
  defp split_gs2(message) do
    with [flag, authzid, bare] <- :binary.split(message, ",", [:global]) |> rejoin(),
         true <- flag in ["n", "y"] do
      {:ok, flag <> "," <> authzid <> ",", bare}
    else
      _ -> :error
    end
  end

  # Splits into the first two fields and the rest.
  defp rejoin([a, b | rest]) when rest != [], do: [a, b, Enum.join(rest, ",")]
  defp rejoin(_parts), do: :error

  defp gs2_authzid(gs2) do
    case :binary.split(gs2, ",", [:global]) do
      [_flag, "", ""] -> {:ok, nil}
      [_flag, "a=" <> name, ""] -> decode_name(name)
      _ -> :error
    end
  end

  defp parse_first_bare(bare) do
    with {:ok, attrs} <- attributes(bare),
         false <- Map.has_key?(attrs, "m"),
         {:ok, name} <- Map.fetch(attrs, "n"),
         {:ok, nonce} <- Map.fetch(attrs, "r"),
         true <- valid_nonce?(nonce),
         {:ok, name} <- decode_name(name),
         {:ok, username} <- SASL.saslprep(name),
         true <- username != "" do
      {:ok, username, nonce}
    else
      _ -> :error
    end
  end

  defp attributes(message) do
    message
    |> String.split(",")
    |> Enum.reduce_while({:ok, %{}}, fn
      <<key, "=", value::binary>>, {:ok, acc} when key in ?a..?z ->
        {:cont, {:ok, Map.put_new(acc, <<key>>, value)}}

      _, _ ->
        {:halt, :error}
    end)
  end

  defp valid_nonce?(nonce),
    do:
      nonce != "" and
        for(<<c <- nonce>>, reduce: true, do: (acc -> acc and c in 0x21..0x7E and c != ?,))

  # saslname: "," and "=" are escaped as "=2C" and "=3D".
  defp decode_name(name) do
    if String.valid?(name) and Regex.match?(~r/\A(?:[^=,]|=2C|=3D)*\z/, name),
      do: {:ok, name |> String.replace("=2C", ",") |> String.replace("=3D", "=")},
      else: :error
  end

  defp encode_name(name), do: name |> String.replace("=", "=3D") |> String.replace(",", "=2C")

  defp nonce, do: @nonce_bytes |> :crypto.strong_rand_bytes() |> Base.encode64()

  defp hmac(key, data), do: :crypto.mac(:hmac, :sha256, key, data)

  ## Client

  @doc """
  Starts the client side. Returns the client-first message.
  `credentials` has `:username` and `:password`.
  """
  @spec client_start(%{username: String.t(), password: String.t()}) :: {:ok, binary(), term()}
  def client_start(%{username: username, password: password}) do
    nonce = nonce()
    bare = "n=#{encode_name(username)},r=#{nonce}"
    {:ok, "n,," <> bare, {:first, %{bare: bare, nonce: nonce, password: password}}}
  end

  @doc """
  Answers the server-first message, then checks the server-final one.
  Returns `{:error, reason}` if the server is not who it claims.
  """
  @spec client_step(term(), binary()) :: {:ok, binary(), term()} | {:error, term()}
  def client_step({:first, state}, server_first) do
    with {:ok, attrs} <- attributes(server_first),
         {:ok, nonce} <- Map.fetch(attrs, "r"),
         true <- String.starts_with?(nonce, state.nonce) and nonce != state.nonce,
         {:ok, salt} <- Map.fetch(attrs, "s"),
         {:ok, salt} <- Base.decode64(salt),
         {:ok, iterations} <- Map.fetch(attrs, "i"),
         {iterations, ""} when iterations in 1..@max_iterations <- Integer.parse(iterations) do
      salted = :crypto.pbkdf2_hmac(:sha256, prepared(state.password), salt, iterations, 32)
      client_key = hmac(salted, "Client Key")
      stored_key = :crypto.hash(:sha256, client_key)
      without_proof = "c=biws,r=#{nonce}"
      auth_message = state.bare <> "," <> server_first <> "," <> without_proof
      proof = :crypto.exor(client_key, hmac(stored_key, auth_message))
      expected = hmac(hmac(salted, "Server Key"), auth_message)
      {:ok, without_proof <> ",p=" <> Base.encode64(proof), {:verify, expected}}
    else
      _ -> {:error, :malformed_server_message}
    end
  end

  def client_step({:verify, expected}, "v=" <> signature) do
    case Base.decode64(signature) do
      {:ok, signature} ->
        if SASL.secure_compare(signature, expected),
          do: {:ok, "", :done},
          else: {:error, :server_signature_mismatch}

      :error ->
        {:error, :malformed_server_message}
    end
  end

  def client_step({:verify, _expected}, "e=" <> error), do: {:error, {:server_error, error}}
  def client_step(_state, _challenge), do: {:error, :malformed_server_message}

  defp prepared(password) do
    case SASL.saslprep(password) do
      {:ok, prepared} -> prepared
      :error -> password
    end
  end
end
