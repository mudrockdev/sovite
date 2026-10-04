defmodule Sovite.LDAP do
  @moduledoc """
  A small layer over OTP's `:eldap`: connecting with StartTLS or LDAPS,
  binding, searching, and running all of it in a process of its own.

      Sovite.LDAP.isolated(fn ->
        with {:ok, handle} <- Sovite.LDAP.connect(servers: ["ldap.example.com"]) do
          try do
            Sovite.LDAP.search(handle, "dc=example,dc=com", filter, ["mail"])
          after
            Sovite.LDAP.close(handle)
          end
        end
      end, 10_000)

  ## Connection options

    * `:servers` - host names, tried in order. Required.
    * `:port` - defaults to 389, or 636 with `security: :ldaps`.
    * `:security` - `:starttls` (default), `:ldaps`, or `:none`.
    * `:tls_options` - `:ssl` client options. Default: verify the server
      against the system CAs and its name.
    * `:timeout` - milliseconds per request. Defaults to 10 seconds.
  """

  require Record

  alias Sovite.LDAP.Filter

  Record.defrecordp(
    :eldap_search,
    Record.extract(:eldap_search, from_lib: "eldap/include/eldap.hrl")
  )

  @typedoc "An open connection."
  @type handle :: pid()

  @typedoc "A search result: the DN and the attributes asked for."
  @type entry :: {dn :: charlist(), %{String.t() => [binary()]}}

  @doc """
  Runs `fun` in a process of its own and returns its result, or
  `{:error, :timeout}` / `{:error, {:exit, reason}}`.

  `:eldap` links its connection process to the caller, so a dropped
  connection would otherwise take the caller down with it.
  """
  @spec isolated((-> result), timeout()) :: result | {:error, :timeout | {:exit, term()}}
        when result: term()
  def isolated(fun, timeout) do
    {pid, ref} = spawn_monitor(fn -> exit({:result, fun.()}) end)

    receive do
      {:DOWN, ^ref, :process, ^pid, {:result, result}} -> result
      {:DOWN, ^ref, :process, ^pid, reason} -> {:error, {:exit, reason}}
    after
      timeout ->
        Process.exit(pid, :kill)

        receive do
          {:DOWN, ^ref, :process, ^pid, _} -> :ok
        end

        {:error, :timeout}
    end
  end

  @doc "Opens a connection, see the options above."
  @spec connect(keyword()) :: {:ok, handle()} | {:error, term()}
  def connect(opts) do
    security = Keyword.get(opts, :security, :starttls)
    port = Keyword.get(opts, :port) || if(security == :ldaps, do: 636, else: 389)
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

  @doc "Closes a connection."
  @spec close(handle()) :: :ok
  def close(handle) do
    :eldap.close(handle)
    :ok
  end

  @doc """
  Binds as `dn` with `password`. A bind with an empty password is
  refused here: LDAP would treat it as anonymous (RFC 4513 §5.1.2).
  """
  @spec bind(handle(), String.t() | charlist(), binary()) :: :ok | {:error, term()}
  def bind(_handle, _dn, ""), do: {:error, :empty_password}

  def bind(handle, dn, password) do
    :eldap.simple_bind(handle, to_charlist_bytes(dn), :binary.bin_to_list(password))
  end

  @doc """
  Searches the subtree under `base` with a filter from `Sovite.LDAP.Filter.build/2`
  and returns at most `size_limit` entries with `attributes`. Use
  `["1.1"]` for no attributes.
  """
  @spec search(handle(), String.t(), term(), [String.t()], pos_integer()) ::
          {:ok, [entry()]} | {:error, term()}
  def search(handle, base, filter, attributes, size_limit \\ 100) do
    # A record, not a keyword list: :eldap's type for the list form
    # leaves out size_limit.
    search =
      eldap_search(
        base: String.to_charlist(base),
        filter: filter,
        size_limit: size_limit,
        scope: :eldap.wholeSubtree(),
        attributes: Enum.map(attributes, &String.to_charlist/1)
      )

    result = :eldap.search(handle, search)

    case result do
      {:ok, {:eldap_search_result, entries, _refs, _controls}} ->
        {:ok, Enum.map(entries, &entry/1)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp entry({:eldap_entry, dn, attrs}) do
    {dn,
     Map.new(attrs, fn {name, values} ->
       {String.downcase(to_string(name)), Enum.map(values, &:binary.list_to_bin/1)}
     end)}
  end

  @doc """
  The placeholder values for a user name, for filters and DN templates:
  `u` the whole name, `n` the part before the last `@`, `d` the part
  after it (empty if none).
  """
  @spec user_values(String.t()) :: %{String.t() => String.t()}
  def user_values(username) do
    {local, domain} = split(username)
    %{"u" => username, "n" => local, "d" => domain}
  end

  @doc false
  def split(name) do
    case String.split(name, "@") do
      [name] -> {name, ""}
      parts -> {parts |> Enum.drop(-1) |> Enum.join("@"), List.last(parts)}
    end
  end

  @doc """
  Fills the placeholders of a DN template, escaping the values (RFC 4514
  §2.4), and returns the DN as `:eldap` wants it.
  """
  @spec dn(String.t(), %{String.t() => String.t()}) :: charlist()
  def dn(template, values),
    do: template |> Filter.substitute(values, &escape_dn/1) |> :binary.bin_to_list()

  defp escape_dn(value) do
    value
    |> String.replace(~r/[\\,+"<>;=\x00]/, fn c -> "\\" <> Base.encode16(c) end)
    |> String.replace(~r/\A[ #]|[ ]\z/, fn c -> "\\" <> c end)
  end

  defp to_charlist_bytes(dn) when is_list(dn), do: dn
  defp to_charlist_bytes(dn), do: :binary.bin_to_list(dn)
end
