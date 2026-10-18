defmodule Sovite.Core.Tenants do
  @moduledoc """
  Tenants (`[[tenant]]`), for hosting the mail of several customers on
  one server or cluster, each with its own limits, signing keys, and
  outbound IP pool.

      [[tenant]]
      name = "acme"
      domains = ["acme.example"]
      users = ["relay-user"]
      ip_pool = "acme"
      messages = "10000/1d"
      recipients = "50000/1d"
      max_message_size = "10M"
      max_recipients = 500

  ## Which tenant a message belongs to

  Mail a client submits belongs to a tenant when the client logged in
  as one of the tenant's `users`, or with a login in one of its
  `domains` (`user@acme.example`, or a subdomain), or else, for clients
  that logged in or are in `smtp.trusted_networks`, when the sender's
  domain is one of its domains. Mail from anyone else, such as mail
  arriving from the internet, belongs to no tenant. The tenant is kept
  with the queued message.

  ## What a tenant gets

    * Limits, on top of the server's: `messages` and `recipients` per
      period for the whole tenant (rate limits, shared by the cluster),
      and `max_message_size` and `max_recipients` per message.
    * DKIM keys: the keys of a tenant's domains (`[[dkim.key]]`) sign
      only that tenant's mail, so one customer cannot sign as another.
    * An IP pool (`ip_pool`, see `Sovite.Core.IPPools`) to send from,
      instead of `delivery.ip_pool`. An address the sender relays table
      gives for a sender comes first.

  ## Telemetry

    * `[:sovite, :tenant, :limited]` - `%{}`, `%{tenant, limit}`, when a
      tenant limit refuses a message or recipient: `limit` is
      `:messages`, `:recipients`, `:max_message_size`, or
      `:max_recipients`.
  """

  alias Sovite.Abuse.RateLimit

  @doc "Tenant options for sessions, or `nil` without tenants."
  @spec opts(Sovite.Core.Config.t(), atom() | nil) :: map() | nil
  def opts(%{tenant: []}, _rate_limit), do: nil

  def opts(config, rate_limit) do
    tenants =
      Enum.map(config.tenant, fn tenant ->
        %{
          tenant
          | domains: Enum.map(tenant.domains, &String.downcase(&1, :ascii)),
            users: Enum.map(tenant.users, &String.downcase/1)
        }
      end)

    %{tenants: tenants, rate_limit: rate_limit}
  end

  @doc """
  The tenant of a message from a client logged in as `identity` (or
  `nil`), from `sender`, by a client that is `trusted` or not.
  """
  @spec find(map() | nil, String.t() | nil, String.t(), boolean()) :: map() | nil
  def find(nil, _identity, _sender, _trusted), do: nil

  def find(%{tenants: tenants}, identity, sender, trusted) do
    login = identity && String.downcase(identity)

    (login && Enum.find(tenants, &(login in &1.users))) ||
      (login && by_domain(tenants, domain(login))) ||
      if((login != nil or trusted) and sender != "", do: by_domain(tenants, domain(sender)))
  end

  @doc "The tenant named `name` (from a queued message), if it is still configured."
  @spec get([Sovite.Core.Config.tenant()], String.t() | nil) :: map() | nil
  def get(_tenants, nil), do: nil
  def get(tenants, name), do: Enum.find(tenants, &(&1.name == name))

  @doc """
  The tenant that owns `domain` or its closest parent domain, if any:
  the one whose DKIM keys for the domain may sign.
  """
  @spec owner([Sovite.Core.Config.tenant()], String.t()) :: String.t() | nil
  def owner(tenants, domain) do
    case by_domain(tenants, String.downcase(domain, :ascii)) do
      nil -> nil
      tenant -> tenant.name
    end
  end

  defp by_domain(_tenants, nil), do: nil

  defp by_domain(tenants, domain) do
    tenants
    |> Enum.flat_map(fn tenant ->
      for owned <- tenant.domains, in_domain?(domain, owned), do: {byte_size(owned), tenant}
    end)
    |> Enum.max_by(&elem(&1, 0), fn -> nil end)
    |> case do
      nil -> nil
      {_size, tenant} -> tenant
    end
  end

  defp in_domain?(domain, owned),
    do: domain == owned or String.ends_with?(domain, "." <> owned)

  defp domain(address) do
    case String.split(address, "@") do
      [_local, domain] when domain != "" -> String.downcase(domain, :ascii)
      _ -> nil
    end
  end

  @doc """
  Counts a message of `tenant` with `size` bytes (or `nil` when not
  known yet). Returns `:ok`, or `{:limited, limit}`.
  """
  @spec message(map() | nil, map() | nil, non_neg_integer() | nil) ::
          :ok | {:limited, :messages | :max_message_size}
  def message(_opts, nil, _size), do: :ok

  def message(opts, tenant, size) do
    cond do
      size != nil and tenant.max_message_size != nil and size > tenant.max_message_size ->
        limited(tenant, :max_message_size)

      hit(opts, tenant, :messages) == :limited ->
        limited(tenant, :messages)

      true ->
        :ok
    end
  end

  @doc """
  Counts the `count`th recipient of a message of `tenant`. Returns `:ok`
  or `{:limited, limit}`.
  """
  @spec recipient(map() | nil, map() | nil, pos_integer()) ::
          :ok | {:limited, :recipients | :max_recipients}
  def recipient(_opts, nil, _count), do: :ok

  def recipient(opts, tenant, count) do
    cond do
      tenant.max_recipients != nil and count > tenant.max_recipients ->
        limited(tenant, :max_recipients)

      hit(opts, tenant, :recipients) == :limited ->
        limited(tenant, :recipients)

      true ->
        :ok
    end
  end

  @doc "Whether a message of `size` bytes is too large for `tenant`."
  @spec too_large?(map() | nil, non_neg_integer()) :: boolean()
  def too_large?(nil, _size), do: false
  def too_large?(%{max_message_size: nil}, _size), do: false

  def too_large?(tenant, size) do
    if size > tenant.max_message_size do
      limited(tenant, :max_message_size)
      true
    else
      false
    end
  end

  defp hit(%{rate_limit: nil}, _tenant, _limit), do: :ok

  defp hit(opts, tenant, limit) do
    case Map.fetch!(tenant, limit) do
      nil ->
        :ok

      {count, window} ->
        RateLimit.hit(opts.rate_limit, {:tenant, limit, tenant.name}, count, window)
    end
  end

  defp limited(tenant, limit) do
    :telemetry.execute([:sovite, :tenant, :limited], %{}, %{tenant: tenant.name, limit: limit})
    {:limited, limit}
  end
end
