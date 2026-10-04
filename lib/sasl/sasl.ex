defmodule Sovite.SASL do
  @moduledoc """
  SASL authentication (RFC 4422), server and client side.

  Mechanisms:

    * `PLAIN` (RFC 4616) - `Sovite.SASL.Plain`
    * `LOGIN` (draft-murchison-sasl-login, for old clients) - `Sovite.SASL.Login`
    * `SCRAM-SHA-256` (RFC 5802, RFC 7677) - `Sovite.SASL.ScramSHA256`
    * `OAUTHBEARER` (RFC 7628) - `Sovite.SASL.OAuthBearer`

  `Sovite.SASL.Server` runs the server side against a
  `Sovite.SASL.Backend`, which checks the credentials. Backends:

    * `Sovite.SASL.Backend.Static` - a passwd-style file.
    * `Sovite.SASL.Backend.SQL` - a query on PostgreSQL or MySQL.
    * `Sovite.SASL.Backend.LDAP` - bind as the user.
    * `Sovite.SASL.Backend.Introspection` - OAuth 2.0 token
      introspection (RFC 7662), for `OAUTHBEARER`.

  `Sovite.SASL.Dovecot` hands the whole exchange to a Dovecot auth
  server instead. `Sovite.SASL.Password` hashes and checks stored
  passwords.
  """

  @doc """
  Prepares a password or user name for comparison, a close approximation
  of SASLprep (RFC 4013): non-ASCII spaces become spaces, characters
  "commonly mapped to nothing" are removed, and the result is NFKC
  normalized. Returns `:error` for invalid UTF-8 or prohibited
  characters (controls).

      iex> Sovite.SASL.saslprep("I\\u00ADX")
      {:ok, "IX"}
      iex> Sovite.SASL.saslprep("\\u2168")
      {:ok, "IX"}
      iex> Sovite.SASL.saslprep("a\\u0007")
      :error
  """
  @spec saslprep(binary()) :: {:ok, String.t()} | :error
  def saslprep(string) do
    if String.valid?(string) do
      mapped =
        for <<c::utf8 <- string>>, not nothing?(c), into: "", do: <<space(c)::utf8>>

      normalized = :unicode.characters_to_nfkc_binary(mapped)

      if is_binary(normalized) and not prohibited?(normalized),
        do: {:ok, normalized},
        else: :error
    else
      :error
    end
  end

  # RFC 3454 table B.1
  defp nothing?(c),
    do:
      c in [0xAD, 0x34F, 0x1806, 0x180B, 0x180C, 0x180D, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF] or
        c in 0xFE00..0xFE0F

  # RFC 3454 table C.1.2
  defp space(c) when c in [0xA0, 0x1680, 0x202F, 0x205F, 0x3000] or c in 0x2000..0x200B, do: 0x20
  defp space(c), do: c

  # Control characters (C.2), private use (C.3), and non-characters.
  defp prohibited?(string) do
    for <<c::utf8 <- string>>, reduce: false do
      true -> true
      false -> c < 0x20 or c in 0x7F..0x9F or c in 0xE000..0xF8FF or c in 0xFFFE..0xFFFF
    end
  end

  @doc """
  Compares two binaries in constant time (for equal sizes).
  """
  @spec secure_compare(binary(), binary()) :: boolean()
  def secure_compare(a, b) when byte_size(a) == byte_size(b), do: :crypto.hash_equals(a, b)
  def secure_compare(_a, _b), do: false
end
