defmodule Sovite.SASL.Plain do
  @moduledoc """
  The `PLAIN` mechanism (RFC 4616): `[authzid] NUL authcid NUL password`
  in one message. Only safe over TLS.

  An authorization identity is accepted only when it equals the
  authentication identity: one user cannot act as another.
  """

  alias Sovite.SASL.Credentials

  @max_field 255

  ## Server

  @doc false
  def server_start(nil, _context), do: {:challenge, "", :waiting}
  def server_start(message, context), do: check(message, context)

  @doc false
  def server_step(:waiting, message, context), do: check(message, context)

  defp check(message, context) do
    with [authzid, authcid, password] <- :binary.split(message, <<0>>, [:global]),
         true <-
           valid_field?(authzid, 0) and valid_field?(authcid, 1) and valid_field?(password, 1) do
      if authzid == "" or String.downcase(authzid) == String.downcase(authcid),
        do: Credentials.verify_password(context, authcid, password),
        else: {:error, :authorization_failed, authcid}
    else
      _ -> {:error, :malformed, nil}
    end
  end

  defp valid_field?(field, min),
    do: byte_size(field) in min..@max_field and String.valid?(field)

  ## Client

  @doc """
  Starts the client side. Returns the initial response.
  `credentials` has `:username` and `:password`.
  """
  @spec client_start(%{username: String.t(), password: String.t()}) :: {:ok, binary(), term()}
  def client_start(%{username: username, password: password}) do
    message = <<0, username::binary, 0, password::binary>>
    {:ok, message, message}
  end

  @doc "Answers a challenge (only an empty one is expected)."
  @spec client_step(term(), binary()) :: {:ok, binary(), term()}
  def client_step(message, _challenge), do: {:ok, message, message}
end
