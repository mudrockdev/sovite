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

    * `:servers` - host names, tried in order. Required.
    * `:port` - defaults to 389, or 636 with `security: :ldaps`.
    * `:security` - `:starttls` (default), `:ldaps`, or `:none`.
    * `:tls_options` - `:ssl` client options. Default: verify the server
      against the system CAs and its name.
    * `:base` - search base DN. Required unless `:dn_template` is given.
    * `:filter` - an RFC 4515 filter with placeholders, see
      `Sovite.SASL.Backend.LDAP.Filter`. Defaults to `"(mail=%u)"`.
    * `:dn_template` - a DN with the same placeholders, such as
      `"uid=%n,ou=people,dc=example,dc=com"`. Values are escaped (RFC 4514).
    * `:bind_dn` / `:bind_password` - service account for the search.
      Anonymous if not given.
    * `:timeout` - milliseconds for the whole check. Defaults to 10 seconds.
  """

  @behaviour Sovite.SASL.Backend

  alias Sovite.SASL.Backend.LDAP.Filter

  @impl true
  def verify_password(_username, "", _opts), do: {:error, :invalid}

  def verify_password(username, password, opts) do
    timeout = Keyword.get(opts, :timeout, 10_000)
    isolated(fn -> check(username, password, opts) end, timeout)
  end

  # :eldap links its connection process to the caller. Run it in a
  # process of its own, so a dropped LDAP connection cannot take the
  # caller (an SMTP session) down.
  defp isolated(fun, timeout) do
    {pid, ref} = spawn_monitor(fn -> exit({:result, fun.()}) end)

    receive do
      {:DOWN, ^ref, :process, ^pid, {:result, result}} -> result
      {:DOWN, ^ref, :process, ^pid, reason} -> {:error, {:temporary, reason}}
    after
      timeout ->
        Process.exit(pid, :kill)

        receive do
          {:DOWN, ^ref, :process, ^pid, _} -> :ok
        end

        {:error, {:temporary, :timeout}}
    end
  end

  defp check(username, password, opts) do
    case connect(opts) do
      {:ok, handle} ->
        try do
          with {:ok, dn} <- find_dn(handle, username, opts) do
            bind_user(handle, dn, password, username)
          end
        after
          :eldap.close(handle)
        end

      {:error, reason} ->
        {:error, {:temporary, reason}}
    end
  end

  defp connect(opts) do
    security = Keyword.get(opts, :security, :starttls)
    port = Keyword.get(opts, :port, if(security == :ldaps, do: 636, else: 389))
    timeout = Keyword.get(opts, :timeout, 10_000)
    servers = opts |> Keyword.fetch!(:servers) |> Enum.map(&String.to_charlist/1)

    open_opts =
      [port: port, timeout: timeout] ++
        if(security == :ldaps, do: [ssl: true, sslopts: tls_options(opts, hd(servers))], else: [])

    with {:ok, handle} <- :eldap.open(servers, open_opts) do
      if security == :starttls,
        do: start_tls(handle, tls_options(opts, hd(servers)), timeout),
        else: {:ok, handle}
    end
  end

  defp start_tls(handle, tls_options, timeout) do
    case :eldap.start_tls(handle, tls_options, timeout) do
      :ok ->
        {:ok, handle}

      {:error, reason} ->
        :eldap.close(handle)
        {:error, {:starttls, reason}}
    end
  end

  defp tls_options(opts, server) do
    Keyword.get_lazy(opts, :tls_options, fn ->
      [
        verify: :verify_peer,
        cacerts: :public_key.cacerts_get(),
        server_name_indication: server,
        customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
      ]
    end)
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
      result =
        :eldap.search(handle,
          base: String.to_charlist(Keyword.fetch!(opts, :base)),
          filter: Filter.build(filter, username),
          scope: :eldap.wholeSubtree(),
          attributes: [~c"1.1"],
          size_limit: 2
        )

      case result do
        # Exactly one entry: anything else is ambiguous or unknown.
        {:ok, {:eldap_search_result, [{:eldap_entry, dn, _attrs}], _refs, _controls}} -> {:ok, dn}
        {:ok, {:eldap_search_result, [], _refs, _controls}} -> {:error, :unknown_user}
        {:ok, {:eldap_search_result, _entries, _refs, _controls}} -> {:error, :invalid}
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
        case :eldap.simple_bind(
               handle,
               String.to_charlist(dn),
               String.to_charlist(Keyword.get(opts, :bind_password, ""))
             ) do
          :ok -> :ok
          {:error, reason} -> {:error, {:temporary, {:service_bind, reason}}}
        end

      :error ->
        :ok
    end
  end

  defp bind_user(handle, dn, password, username) do
    case :eldap.simple_bind(handle, dn, :binary.bin_to_list(password)) do
      :ok -> {:ok, username}
      {:error, :invalidCredentials} -> {:error, :invalid}
      {:error, :inappropriateAuthentication} -> {:error, :invalid}
      {:error, :unwillingToPerform} -> {:error, :invalid}
      {:error, reason} -> {:error, {:temporary, reason}}
    end
  end

  @doc false
  # Builds a DN from a template, escaping the values (RFC 4514 §2.4).
  def dn_from_template(template, username) do
    {local, domain} =
      case String.split(username, "@") do
        [name] -> {name, ""}
        parts -> {parts |> Enum.drop(-1) |> Enum.join("@"), List.last(parts)}
      end

    Regex.replace(~r/%[und%]/, template, fn
      "%u" -> escape_dn(username)
      "%n" -> escape_dn(local)
      "%d" -> escape_dn(domain)
      "%%" -> "%"
    end)
    |> :binary.bin_to_list()
  end

  defp escape_dn(value) do
    value
    |> String.replace(~r/[\\,+"<>;=\x00]/, fn c -> "\\" <> Base.encode16(c) end)
    |> String.replace(~r/\A[ #]|[ ]\z/, fn c -> "\\" <> c end)
  end
end
