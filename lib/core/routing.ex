defmodule Sovite.Core.Routing do
  @moduledoc """
  The routing configuration (`[domains]`, `[routing]`, and the next-hop
  settings of `[delivery]`) together with Sovite's routing tables in the
  database, and the address helpers shared by rewriting
  (`Sovite.Core.Rewrite`), recipient expansion (`Sovite.Core.Recipients`),
  and next-hop selection (`Sovite.Core.Router`).

  ## Domain classes

  Every recipient domain is in one class, set in the `[domains]` config
  section or with `sovitectl domain`:

    * `:local` - this server's own domains.
    * `:aliased` - every address must be an alias (`sovitectl alias`).
    * `:hosted` - mailboxes hosted here (`sovitectl mailbox`).
    * `:relay` - domains this server relays for, such as a backup MX.
    * `:remote` - everything else.
  """

  alias Sovite.Core.{Config, Lookup}

  alias Sovite.Core.Repo.Tables.{
    AddressRewrites,
    Aliases,
    BccRules,
    DomainCache,
    Mailboxes,
    RelocatedUsers,
    SenderRelays,
    Transports
  }

  defstruct hostname: "localhost",
            local_domains: MapSet.new(),
            relay_domains: MapSet.new(),
            aliased_domains: MapSet.new(),
            hosted_domains: MapSet.new(),
            local_recipients: nil,
            domain_cache: nil,
            delimiter: "",
            aliases: [],
            mailboxes: [],
            moved_users: [],
            sender_rewrites: [],
            recipient_rewrites: [],
            hide_subdomains: [],
            hide_subdomains_exceptions: MapSet.new(),
            always_bcc: nil,
            sender_bcc: [],
            recipient_bcc: [],
            transports: [],
            class_transports: %{
              local: %{transport: :local, nexthop: nil},
              hosted: %{transport: :mailbox, nexthop: nil},
              relay: %{transport: :smtp, nexthop: nil},
              remote: %{transport: :smtp, nexthop: nil}
            },
            relayhost: nil,
            relay_auth: nil,
            sender_relayhosts: [],
            source_address: %{},
            sender_source_addresses: [],
            relay_credentials: [],
            rewrite_headers: true

  @type class :: :local | :aliased | :hosted | :relay | :remote
  @type t :: %__MODULE__{}

  @doc """
  Builds the routing configuration from `config`, reading the routing
  tables from Sovite's database `repo`. Without a database (`nil`), there
  are no table entries.
  """
  @spec new(Config.t(), Sovite.Core.Repo.t() | nil) :: t()
  def new(%Config{} = config, repo \\ nil) do
    routing = config.routing
    table = fn name, module, handle -> tables(repo, name, module, handle) end

    %__MODULE__{
      hostname: config.server.hostname,
      local_domains: MapSet.new(config.domains.local),
      relay_domains: MapSet.new(config.domains.relay),
      aliased_domains: MapSet.new(config.domains.aliased),
      hosted_domains: MapSet.new(config.domains.hosted),
      local_recipients:
        config.domains.local_recipients && MapSet.new(config.domains.local_recipients),
      domain_cache: repo && DomainCache.id(repo),
      delimiter: routing.extension_delimiter,
      aliases: table.("aliases", Aliases, %{}),
      mailboxes: table.("mailboxes", Mailboxes, %{}),
      moved_users: table.("moved_users", RelocatedUsers, %{}),
      # Rewrites for one kind come first, then those for both.
      sender_rewrites:
        table.("address_rewrites", AddressRewrites, %{kind: :sender}) ++
          table.("address_rewrites", AddressRewrites, %{kind: :both}),
      recipient_rewrites:
        table.("address_rewrites", AddressRewrites, %{kind: :recipient}) ++
          table.("address_rewrites", AddressRewrites, %{kind: :both}),
      hide_subdomains: routing.hide_subdomains,
      hide_subdomains_exceptions: MapSet.new(routing.hide_subdomains_exceptions),
      always_bcc: routing.always_bcc,
      sender_bcc: table.("bcc_rules", BccRules, %{kind: :sender}),
      recipient_bcc: table.("bcc_rules", BccRules, %{kind: :recipient}),
      transports: table.("transports", Transports, %{}),
      class_transports: %{
        local: routing.local_transport,
        hosted: routing.mailbox_transport,
        relay: routing.relay_transport,
        remote: routing.remote_transport
      },
      relayhost: config.delivery.relayhost,
      relay_auth:
        config.delivery.relayhost_username &&
          %{
            username: config.delivery.relayhost_username,
            password: config.delivery.relayhost_password || ""
          },
      sender_relayhosts: table.("sender_relays", SenderRelays, %{field: :relayhost}),
      source_address: source_address(config.delivery.source_address),
      sender_source_addresses: table.("sender_relays", SenderRelays, %{field: :source_address}),
      relay_credentials: table.("sender_relays", SenderRelays, %{field: :credentials}),
      rewrite_headers: routing.rewrite_headers
    }
  end

  defp tables(nil, _name, _module, _handle), do: []
  defp tables(repo, name, module, handle), do: [{name, {module, Map.put(handle, :repo, repo)}}]

  @doc """
  Turns a list of IP addresses (at most one per family) into
  `%{ipv4: ip, ipv6: ip}`, leaving out missing families.
  """
  @spec source_address([:inet.ip_address()]) :: %{optional(:ipv4 | :ipv6) => :inet.ip_address()}
  def source_address(ips) do
    Map.new(ips || [], fn
      ip when tuple_size(ip) == 4 -> {:ipv4, ip}
      ip -> {:ipv6, ip}
    end)
  end

  @doc """
  The class of `domain` (lower-case): from the `[domains]` config
  section, else from the domains in the database.
  """
  @spec class(t(), String.t()) :: class()
  def class(routing, domain) do
    cond do
      MapSet.member?(routing.local_domains, domain) -> :local
      MapSet.member?(routing.aliased_domains, domain) -> :aliased
      MapSet.member?(routing.hosted_domains, domain) -> :hosted
      MapSet.member?(routing.relay_domains, domain) -> :relay
      routing.domain_cache -> Map.get(DomainCache.classes(routing.domain_cache), domain, :remote)
      true -> :remote
    end
  end

  @doc "Whether `domain` is one this server accepts mail for without relaying."
  @spec hosted?(t(), String.t()) :: boolean()
  def hosted?(routing, domain), do: class(routing, domain) != :remote

  @doc """
  Splits an address into its local part and lower-cased domain. A bare
  local part (`"postmaster"`) has domain `nil`.
  """
  @spec split(String.t()) :: {String.t(), String.t() | nil}
  def split(address) do
    case :binary.matches(address, "@") do
      [] ->
        {address, nil}

      matches ->
        {at, 1} = List.last(matches)
        local = binary_part(address, 0, at)
        domain = binary_part(address, at + 1, byte_size(address) - at - 1)
        {local, String.downcase(domain, :ascii)}
    end
  end

  @doc """
  Splits the extension off a local part: `"alice+lists"` is `{"alice",
  "+lists"}` with delimiter `"+"`. With several delimiter characters, the
  first one found counts. Returns `{local, nil}` without an extension.
  """
  @spec extension(t() | String.t(), String.t()) :: {String.t(), String.t() | nil}
  def extension(%__MODULE__{delimiter: delimiter}, local), do: extension(delimiter, local)
  def extension(delimiter, local) when delimiter in [nil, ""], do: {local, nil}

  def extension(delimiter, local) do
    case :binary.match(local, String.graphemes(delimiter)) do
      {at, _} when at > 0 ->
        {binary_part(local, 0, at), binary_part(local, at, byte_size(local) - at)}

      _ ->
        {local, nil}
    end
  end

  @doc """
  Looks up an address in `tables`, trying, in order:

    1. `user+ext@domain`
    2. `user@domain`
    3. `user+ext` and `user`, with `local_part: true`
    4. `@domain`, with `catchall: true`

  Keys are lower-cased. Returns the value with how it matched:
  `:address` for the first key, otherwise `:base`, `:local_part`, or
  `:catchall`, and the extension, so the caller can propagate it.
  """
  @spec lookup(t(), Lookup.tables(), String.t(), keyword()) ::
          {:ok, String.t(), atom(), String.t() | nil} | :error | {:error, String.t()}
  def lookup(routing, tables, address, opts \\ [])
  def lookup(_routing, [], _address, _opts), do: :error

  def lookup(routing, tables, address, opts) do
    {local, domain} = split(String.downcase(address))
    {base, ext} = extension(routing, local)

    keys =
      [{"#{local}@#{domain}", :address}] ++
        if(ext, do: [{"#{base}@#{domain}", :base}], else: []) ++
        if(opts[:local_part], do: [{local, :local_part}, {base, :local_part}], else: []) ++
        if(opts[:catchall], do: [{"@#{domain}", :catchall}], else: [])

    keys = if domain == nil, do: [{local, :local_part}, {base, :local_part}], else: keys
    keys = Enum.uniq_by(keys, &elem(&1, 0))

    case Lookup.lookup(tables, Enum.map(keys, &elem(&1, 0))) do
      {:ok, value, key} ->
        {_key, kind} = List.keyfind(keys, key, 0)
        {:ok, value, kind, if(String.contains?(key, ext || "\0"), do: nil, else: ext)}

      other ->
        other
    end
  end

  @doc """
  Adds an extension to the local part of `address`, unless it already has
  one.
  """
  @spec add_extension(t(), String.t(), String.t() | nil) :: String.t()
  def add_extension(_routing, address, nil), do: address

  def add_extension(routing, address, ext) do
    case split(address) do
      {local, nil} ->
        local

      {local, domain} ->
        case extension(routing, local) do
          {_base, nil} -> "#{local}#{ext}@#{original_domain(address, domain)}"
          _has_one -> address
        end
    end
  end

  defp original_domain(address, domain) do
    case String.split(address, "@") do
      [_] -> domain
      parts -> List.last(parts)
    end
  end

  @doc "Splits a list of addresses separated by commas or whitespace."
  @spec addresses(String.t()) :: [String.t()]
  def addresses(value) do
    value
    |> String.split(~r/[\s,]+/, trim: true)
    |> Enum.map(fn address ->
      address |> String.trim_leading("<") |> String.trim_trailing(">")
    end)
  end

  @doc "Whether `address` is a usable mailbox: `local@domain`, or `local@[literal]`."
  @spec valid_address?(String.t()) :: boolean()
  def valid_address?(address), do: match?({:ok, _}, Sovite.Validators.split_mailbox(address))

  @doc "The transport for domain class `class` (`:local`, `:hosted`, `:relay`, `:remote`)."
  @spec transport(t(), class()) :: Sovite.Core.Transport.t()
  def transport(routing, class), do: Map.fetch!(routing.class_transports, class)
end
