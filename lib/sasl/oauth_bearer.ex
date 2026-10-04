defmodule Sovite.SASL.OAuthBearer do
  @moduledoc """
  The `OAUTHBEARER` mechanism (RFC 7628): the client sends an OAuth 2.0
  bearer token (RFC 6750) instead of a password.

      n,a=user@example.com,^Aauth=Bearer <token>^Ahost=...^Aport=...^A^A

  (`^A` is the byte `0x01`.) The token is checked by the backend's
  `verify_token/3`. When it is rejected, the server sends a JSON error
  as a challenge, the client answers with `0x01`, and the exchange fails
  (RFC 7628 §3.2.3).
  """

  alias Sovite.SASL.Server

  @kvsep <<1>>

  ## Server

  @doc false
  def server_start(nil, _context), do: {:challenge, "", :initial}
  def server_start(message, context), do: check(message, context)

  @doc false
  def server_step(:initial, message, context), do: check(message, context)

  def server_step({:failed, username}, _response, _context),
    do: {:error, :invalid_credentials, username}

  defp check(message, context) do
    with {:ok, username, pairs} <- parse(message),
         {:ok, "Bearer " <> token} <- Map.fetch(pairs, "auth"),
         true <- token != "" and token =~ ~r/\A[A-Za-z0-9\-._~+\/]+=*\z/ do
      case Server.verify_token(context, username, token) do
        {:ok, identity} -> {:ok, identity}
        {:error, :temporary} -> {:error, :temporary, username}
        {:error, :invalid} -> {:challenge, context.oauth_error, {:failed, username}}
      end
    else
      _ -> {:error, :malformed, nil}
    end
  end

  # gs2-header kvsep *(key "=" value kvsep) kvsep
  defp parse(message) do
    with [gs2, rest] <- :binary.split(message, @kvsep),
         {:ok, username} <- gs2_authzid(gs2),
         true <- String.ends_with?(rest, @kvsep <> @kvsep) or rest == @kvsep,
         {:ok, pairs} <- pairs(binary_part(rest, 0, byte_size(rest) - 1)) do
      {:ok, username, pairs}
    else
      _ -> :error
    end
  end

  defp gs2_authzid(gs2) when gs2 in ["n,,", "y,,"], do: {:ok, nil}

  defp gs2_authzid(<<flag, ",a=", rest::binary>>) when flag in [?n, ?y] do
    case String.split(rest, ",") do
      [name, ""] when name != "" ->
        if String.valid?(name),
          do: {:ok, name |> String.replace("=2C", ",") |> String.replace("=3D", "=")},
          else: :error

      _ ->
        :error
    end
  end

  defp gs2_authzid(_gs2), do: :error

  defp pairs(data) do
    data
    |> :binary.split(@kvsep, [:global, :trim])
    |> Enum.reduce_while({:ok, %{}}, fn pair, {:ok, acc} ->
      case :binary.split(pair, "=") do
        [key, value] when key != "" -> {:cont, {:ok, Map.put_new(acc, key, value)}}
        _ -> {:halt, :error}
      end
    end)
  end

  ## Client

  @doc """
  Starts the client side. `credentials` has `:username` and `:token`,
  and optionally `:host` and `:port` of the server.
  """
  @spec client_start(map()) :: {:ok, binary(), term()}
  def client_start(%{username: username, token: token} = credentials) do
    name = username |> String.replace("=", "=3D") |> String.replace(",", "=2C")

    extra =
      for key <- [:host, :port], value = credentials[key], into: "" do
        "#{key}=#{value}" <> @kvsep
      end

    message = "n,a=#{name}," <> @kvsep <> "auth=Bearer #{token}" <> @kvsep <> extra <> @kvsep
    {:ok, message, :sent}
  end

  @doc "Answers the server's error challenge with `0x01`, as RFC 7628 requires."
  @spec client_step(term(), binary()) :: {:ok, binary(), term()}
  def client_step(:sent, _error), do: {:ok, @kvsep, :failed}
  def client_step(:failed, _challenge), do: {:ok, @kvsep, :failed}
end
