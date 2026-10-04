defmodule Sovite.SASL.Credentials do
  @moduledoc false
  # Backend calls for the mechanism modules, with errors mapped to
  # Sovite.SASL.Server's. Kept apart from the server so mechanisms do not
  # depend on it.

  @type context :: map()
  @type error :: atom()

  @doc false
  @spec verify_password(context(), String.t(), String.t()) ::
          {:ok, String.t()} | {:error, error(), String.t()}
  def verify_password(%{backend: {module, opts}}, username, password) do
    case module.verify_password(username, password, opts) do
      {:ok, identity} -> {:ok, identity}
      {:error, {:temporary, _}} -> {:error, :temporary, username}
      {:error, _} -> {:error, :invalid_credentials, username}
    end
  end

  @doc false
  @spec verify_token(context(), String.t() | nil, String.t()) ::
          {:ok, String.t()} | {:error, :invalid | :temporary}
  def verify_token(%{token_backend: {module, opts}}, username, token) do
    case module.verify_token(username, token, opts) do
      {:ok, identity} ->
        if username == nil or String.downcase(username) == String.downcase(identity),
          do: {:ok, identity},
          else: {:error, :invalid}

      {:error, {:temporary, _}} ->
        {:error, :temporary}

      {:error, _} ->
        {:error, :invalid}
    end
  end

  @doc false
  @spec scram_credentials(context(), String.t()) ::
          {:ok, Sovite.SASL.Password.scram(), String.t()}
          | {:fake, Sovite.SASL.Password.scram(), error()}
          | {:error, :temporary}
  def scram_credentials(%{backend: {module, opts}} = context, username) do
    case module.scram_credentials(username, opts) do
      {:ok, credentials, identity} ->
        {:ok, credentials, identity}

      {:error, {:temporary, _}} ->
        {:error, :temporary}

      {:error, :unavailable} ->
        {:fake, fake_credentials(context, username), :no_scram_credentials}

      {:error, _} ->
        {:fake, fake_credentials(context, username), :invalid_credentials}
    end
  end

  # Same salt for the same name every time, as a real user would have.
  defp fake_credentials(context, username) do
    salt = :crypto.mac(:hmac, :sha256, context.scram_secret, username) |> binary_part(0, 16)

    %{
      salt: salt,
      iterations: 4096,
      stored_key: :crypto.strong_rand_bytes(32),
      server_key: :crypto.strong_rand_bytes(32)
    }
  end
end
