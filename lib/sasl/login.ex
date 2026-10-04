defmodule Sovite.SASL.Login do
  @moduledoc """
  The `LOGIN` mechanism (draft-murchison-sasl-login): the server asks for
  `Username:` then `Password:`. Obsolete, but some clients (older Outlook
  versions) offer nothing else. Only safe over TLS.

  An initial response is taken as the user name, as some clients send it.
  """

  alias Sovite.SASL.Credentials

  @max_field 255

  ## Server

  @doc false
  def server_start(nil, _context), do: {:challenge, "Username:", :username}
  def server_start(username, context), do: server_step(:username, username, context)

  @doc false
  def server_step(:username, username, _context) do
    if valid?(username),
      do: {:challenge, "Password:", {:password, username}},
      else: {:error, :malformed, nil}
  end

  def server_step({:password, username}, password, context) do
    if valid?(password),
      do: Credentials.verify_password(context, username, password),
      else: {:error, :malformed, username}
  end

  defp valid?(field), do: byte_size(field) in 1..@max_field and String.valid?(field)

  ## Client

  @doc "Starts the client side. Sends no initial response."
  @spec client_start(%{username: String.t(), password: String.t()}) :: {:ok, nil, term()}
  def client_start(credentials), do: {:ok, nil, {:username, credentials}}

  @doc "Answers `Username:`, then `Password:`, whatever the prompts say."
  @spec client_step(term(), binary()) :: {:ok, binary(), term()}
  def client_step({:username, credentials}, _challenge),
    do: {:ok, credentials.username, {:password, credentials}}

  def client_step({:password, credentials}, _challenge),
    do: {:ok, credentials.password, {:password, credentials}}
end
