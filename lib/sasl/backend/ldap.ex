defmodule Sovite.SASL.Backend.LDAP do
  @moduledoc """
  A `Sovite.SASL.Backend` that checks passwords by binding to an LDAP
  directory as the user.

  The user's entry is found with a search (as a service account, or
  anonymously), then the server is asked to bind as that entry with the
  given password. Alternatively `:dn_template` builds the DN directly and
  skips the search.

  Only `PLAIN` and `LOGIN` work: the password must be sent to the
  directory, so `SCRAM-SHA-256` is not possible.

  An empty password is always refused: LDAP treats a bind with one as an
  anonymous bind, which would succeed (RFC 4513 §5.1.2).

  ## Options

  The connection options of `Sovite.LDAP.connect/1` (`:servers`, `:port`,
  `:security`, `:tls_options`), and:

    * `:base` - search base DN. Required unless `:dn_template` is given.
    * `:filter` - an RFC 4515 filter (`Sovite.LDAP.Filter`) with
      placeholders: `%u` the whole user name, `%n` the part before the
      last `@`, `%d` the part after it. Defaults to `"(mail=%u)"`.
    * `:dn_template` - a DN with the same placeholders, such as
      `"uid=%n,ou=people,dc=example,dc=com"`. Values are escaped (RFC 4514).
    * `:bind_dn` / `:bind_password` - service account for the search.
      Anonymous if not given.
    * `:timeout` - milliseconds for the whole check. Defaults to 10 seconds.
  """

  @behaviour Sovite.SASL.Backend

  alias Sovite.LDAP
  alias Sovite.LDAP.Filter

  @impl true
  def verify_password(_username, "", _opts), do: {:error, :invalid}

  def verify_password(username, password, opts) do
    timeout = Keyword.get(opts, :timeout, 10_000)

    # Isolated, so a dropped LDAP connection cannot take the caller (an
    # SMTP session) down.
    case LDAP.isolated(fn -> check(username, password, opts) end, timeout) do
      {:error, :timeout} -> {:error, {:temporary, :timeout}}
      {:error, {:exit, reason}} -> {:error, {:temporary, reason}}
      result -> result
    end
  end

  defp check(username, password, opts) do
    case LDAP.connect(opts) do
      {:ok, handle} ->
        try do
          with {:ok, dn} <- find_dn(handle, username, opts) do
            bind_user(handle, dn, password, username)
          end
        after
          LDAP.close(handle)
        end

      {:error, reason} ->
        {:error, {:temporary, reason}}
    end
  end

  defp find_dn(handle, username, opts) do
    case Keyword.fetch(opts, :dn_template) do
      {:ok, template} -> {:ok, dn_from_template(template, username)}
      :error -> search(handle, username, opts)
    end
  end

  defp search(handle, username, opts) do
    with :ok <- service_bind(handle, opts),
         {:ok, filter} <- Filter.parse(Keyword.get(opts, :filter, "(mail=%u)")) do
      filter = Filter.build(filter, LDAP.user_values(username))

      # Exactly one entry: anything else is ambiguous or unknown.
      case LDAP.search(handle, Keyword.fetch!(opts, :base), filter, ["1.1"], 2) do
        {:ok, [{dn, _attrs}]} -> {:ok, dn}
        {:ok, []} -> {:error, :unknown_user}
        {:ok, _entries} -> {:error, :invalid}
        {:error, :sizeLimitExceeded} -> {:error, :invalid}
        {:error, reason} -> {:error, {:temporary, reason}}
      end
    else
      :error -> {:error, {:temporary, :invalid_filter}}
      {:error, _} = error -> error
    end
  end

  defp service_bind(handle, opts) do
    case Keyword.fetch(opts, :bind_dn) do
      {:ok, dn} ->
        case LDAP.bind(handle, dn, Keyword.get(opts, :bind_password, "")) do
          :ok -> :ok
          {:error, reason} -> {:error, {:temporary, {:service_bind, reason}}}
        end

      :error ->
        :ok
    end
  end

  defp bind_user(handle, dn, password, username) do
    case LDAP.bind(handle, dn, password) do
      :ok -> {:ok, username}
      {:error, :invalidCredentials} -> {:error, :invalid}
      {:error, :inappropriateAuthentication} -> {:error, :invalid}
      {:error, :unwillingToPerform} -> {:error, :invalid}
      {:error, reason} -> {:error, {:temporary, reason}}
    end
  end

  @doc false
  # Builds a DN from a template, escaping the values (RFC 4514 §2.4).
  def dn_from_template(template, username), do: LDAP.dn(template, LDAP.user_values(username))
end
