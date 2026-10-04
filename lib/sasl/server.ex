defmodule Sovite.SASL.Server do
  @moduledoc """
  Runs the server side of a SASL exchange against a `Sovite.SASL.Backend`.

      opts = [backend: {Sovite.SASL.Backend.Static, file: "/etc/sovite/users"}]

      Sovite.SASL.Server.mechanisms(opts)
      #=> ["PLAIN", "LOGIN", "SCRAM-SHA-256"]

      case Sovite.SASL.Server.start("PLAIN", initial_response, opts) do
        {:ok, identity} -> ...
        {:challenge, data, server} -> # send data, then Sovite.SASL.Server.step(server, response)
        {:error, reason, username} -> ...
      end

  ## Options

    * `:backend` - `{module, opts}` for passwords and `SCRAM-SHA-256`.
      Required.
    * `:token_backend` - `{module, opts}` for `OAUTHBEARER`. Defaults to
      `:backend`.
    * `:mechanisms` - mechanisms to allow, in order of preference.
      Defaults to all the backends support. Unknown names are ignored.
    * `:scram_secret` - a secret to derive fake salts for unknown users,
      so `SCRAM-SHA-256` does not reveal which users exist. Defaults to a
      random value per VM.
    * `:oauth_error` - the JSON sent when an `OAUTHBEARER` token is
      rejected (RFC 7628 §3.2.2). Defaults to
      `{"status":"invalid_token"}`.

  ## Errors

  `reason` is `:invalid_credentials`, `:malformed` (the client broke the
  protocol), `:authorization_failed` (the client asked to act as another
  user), `:temporary` (the backend failed), `:unsupported_mechanism`, or
  `:no_scram_credentials` (the user has no `SCRAM-SHA-256` values; the
  client sees the same reply as for a wrong password). `username` is the
  name the client gave, if any, for logs.
  """

  alias Sovite.SASL.{Login, OAuthBearer, Plain, ScramSHA256}

  @mechanisms [
    {"SCRAM-SHA-256", ScramSHA256, :scram_credentials, 2, :backend},
    {"PLAIN", Plain, :verify_password, 3, :backend},
    {"LOGIN", Login, :verify_password, 3, :backend},
    {"OAUTHBEARER", OAuthBearer, :verify_token, 3, :token_backend}
  ]

  @enforce_keys [:module, :state, :context]
  defstruct [:module, :state, :context]

  @opaque t :: %__MODULE__{}

  @type error ::
          :invalid_credentials
          | :malformed
          | :authorization_failed
          | :temporary
          | :unsupported_mechanism
          | :no_scram_credentials

  @type result ::
          {:ok, identity :: String.t()}
          | {:challenge, binary(), t()}
          | {:error, error(), username :: String.t() | nil}

  @typedoc false
  @type context :: %{
          backend: {module(), keyword()},
          token_backend: {module(), keyword()},
          scram_secret: binary(),
          oauth_error: String.t()
        }

  @doc "Returns the mechanisms the backends support, filtered by `:mechanisms`."
  @spec mechanisms(keyword()) :: [String.t()]
  def mechanisms(opts) do
    context = context(opts)

    supported =
      for {name, _module, callback, arity, key} <- @mechanisms,
          {module, _} = Map.fetch!(context, key),
          Code.ensure_loaded?(module) and function_exported?(module, callback, arity),
          do: name

    case Keyword.get(opts, :mechanisms) do
      nil -> supported
      wanted -> Enum.filter(wanted, &(&1 in supported))
    end
  end

  @doc """
  Starts an exchange. `initial` is the client's initial response, `""`
  for an empty one, or `nil` for none.
  """
  @spec start(String.t(), binary() | nil, keyword()) :: result()
  def start(mechanism, initial, opts) do
    context = context(opts)

    case List.keyfind(@mechanisms, mechanism, 0) do
      {_name, module, _callback, _arity, _key} ->
        if mechanism in mechanisms(opts),
          do: module.server_start(initial, context) |> wrap(module, context),
          else: {:error, :unsupported_mechanism, nil}

      nil ->
        {:error, :unsupported_mechanism, nil}
    end
  end

  @doc "Continues an exchange with the client's response to the last challenge."
  @spec step(t(), binary()) :: result()
  def step(%__MODULE__{module: module, state: state, context: context}, response) do
    module.server_step(state, response, context) |> wrap(module, context)
  end

  defp wrap({:challenge, data, state}, module, context),
    do: {:challenge, data, %__MODULE__{module: module, state: state, context: context}}

  defp wrap(result, _module, _context), do: result

  defp context(opts) do
    backend = Keyword.fetch!(opts, :backend)

    %{
      backend: backend,
      token_backend: Keyword.get(opts, :token_backend) || backend,
      scram_secret: Keyword.get_lazy(opts, :scram_secret, &default_secret/0),
      oauth_error: Keyword.get(opts, :oauth_error, ~s({"status":"invalid_token"}))
    }
  end

  defp default_secret do
    case :persistent_term.get({__MODULE__, :secret}, nil) do
      nil ->
        secret = :crypto.strong_rand_bytes(32)
        :persistent_term.put({__MODULE__, :secret}, secret)
        secret

      secret ->
        secret
    end
  end

  ## Backend calls, for the mechanism modules

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
