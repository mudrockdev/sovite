defmodule Sovite.SASL.Backend do
  @moduledoc """
  Behaviour for credential backends used by `Sovite.SASL.Server`.

  A backend implements what it can:

    * `verify_password/3` enables `PLAIN` and `LOGIN`.
    * `scram_credentials/2` enables `SCRAM-SHA-256`.
    * `verify_token/3` enables `OAUTHBEARER`.

  Every callback gets the backend's options last, as given in the
  `{module, opts}` tuple. The identity returned on success is the
  canonical user name, which may differ from the one the client typed
  (for example lower-cased).

  Errors:

    * `:invalid` - wrong password or token, or unknown user. Backends
      should not tell these apart to the client.
    * `:unknown_user` - the user does not exist. Treated like `:invalid`;
      `Sovite.SASL.Server` uses it only to hide the difference.
    * `:unavailable` - the user exists but has no credentials for this
      mechanism, such as a crypt hash for `SCRAM-SHA-256`.
    * `{:temporary, reason}` - the backend cannot answer now (database
      down, timeout). The client is told to try again later.
  """

  @type error :: :invalid | :unknown_user | :unavailable | {:temporary, term()}

  @callback verify_password(username :: String.t(), password :: String.t(), opts :: keyword()) ::
              {:ok, identity :: String.t()} | {:error, error()}

  @callback scram_credentials(username :: String.t(), opts :: keyword()) ::
              {:ok, Sovite.SASL.Password.scram(), identity :: String.t()} | {:error, error()}

  @doc """
  Checks an OAuth 2.0 bearer token. `username` is the authorization
  identity the client named, or `nil`; when given, the token must belong
  to that user.
  """
  @callback verify_token(username :: String.t() | nil, token :: String.t(), opts :: keyword()) ::
              {:ok, identity :: String.t()} | {:error, error()}

  @optional_callbacks verify_password: 3, scram_credentials: 2, verify_token: 3
end
