defmodule Sovite.Core.Config.ClusterRules do
  @moduledoc false
  # Cross-key checks for [cluster], [[tenant]], [[ip_pool]], and
  # delivery.ip_pool.

  alias Sovite.Core.Config.Error

  @spec errors(map()) :: [Error.t() | false]
  def errors(values) do
    cluster_errors(values.cluster) ++
      tenant_errors(values.tenant, pool_names(values)) ++
      pool_errors(values.ip_pool, values.cluster) ++
      [
        (values.delivery.ip_pool != nil and values.delivery.ip_pool not in pool_names(values)) &&
          %Error{
            path: ["delivery", "ip_pool"],
            reason: "no [[ip_pool]] is named #{inspect(values.delivery.ip_pool)}"
          }
      ]
  end

  defp pool_names(values), do: Enum.map(values.ip_pool, & &1.name)

  defp cluster_errors(%{enabled: false}), do: []

  defp cluster_errors(cluster) do
    required =
      for key <- [:node_name, :address, :cert_file, :key_file, :ca_file],
          Map.fetch!(cluster, key) == nil,
          do: %Error{
            path: ["cluster", Atom.to_string(key)],
            reason: "is required when the cluster is enabled"
          }

    required ++
      [
        cluster.address in [{0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}] &&
          %Error{
            path: ["cluster", "address"],
            reason: "must be an address the other nodes can reach: they are told it"
          }
      ]
  end

  defp tenant_errors(tenants, pools) do
    duplicates(tenants, :name, "tenant", "another tenant") ++
      Enum.flat_map(Enum.with_index(tenants), fn {tenant, index} ->
        [
          (tenant.ip_pool != nil and tenant.ip_pool not in pools) &&
            %Error{
              path: ["tenant", "[#{index}]", "ip_pool"],
              reason: "no [[ip_pool]] is named #{inspect(tenant.ip_pool)}"
            }
        ]
      end) ++
      shared_members(tenants, :domains) ++
      shared_members(tenants, :users)
  end

  # A domain or user belongs to one tenant only.
  defp shared_members(tenants, key) do
    tenants
    |> Enum.with_index()
    |> Enum.flat_map(fn {tenant, index} ->
      tenant |> Map.fetch!(key) |> Enum.map(&{String.downcase(&1), index})
    end)
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Enum.flat_map(fn
      {_member, [_]} ->
        []

      {member, [first | others]} ->
        for index <- Enum.uniq(others) -- [first],
            do: %Error{
              path: ["tenant", "[#{index}]", Atom.to_string(key)],
              reason: "#{inspect(member)} is in tenant[#{first}] already"
            }
    end)
  end

  defp pool_errors(pools, cluster) do
    names = Enum.map(pools, & &1.name)

    duplicates(pools, :name, "ip_pool", "another pool") ++
      Enum.flat_map(Enum.with_index(pools), fn {pool, index} ->
        path = ["ip_pool", "[#{index}]"]

        [
          (pool.overflow != nil and pool.overflow not in names) &&
            %Error{
              path: path ++ ["overflow"],
              reason: "no [[ip_pool]] is named #{inspect(pool.overflow)}"
            },
          pool.overflow == pool.name &&
            %Error{path: path ++ ["overflow"], reason: "must name another pool"},
          pool.address == [] && %Error{path: path ++ ["address"], reason: "must not be empty"}
        ] ++ address_errors(pool, path, cluster)
      end) ++ overflow_cycles(pools)
  end

  defp address_errors(pool, path, cluster) do
    pool.address
    |> Enum.with_index()
    |> Enum.flat_map(fn {address, index} ->
      path = path ++ ["address", "[#{index}]"]

      [
        (address.node != nil and not cluster.enabled) &&
          %Error{path: path ++ ["node"], reason: "needs the cluster to be enabled"},
        (address.warmup != [] and address.warmup_start == nil) &&
          %Error{path: path ++ ["warmup_start"], reason: "is required with warmup"}
      ]
    end)
  end

  # Overflow pools must not lead back to the first.
  defp overflow_cycles(pools) do
    overflow = Map.new(pools, &{&1.name, &1.overflow})

    pools
    |> Enum.with_index()
    |> Enum.flat_map(fn {pool, index} ->
      if pool.overflow != pool.name and cycle?(overflow, pool.overflow, MapSet.new([pool.name])),
        do: [
          %Error{
            path: ["ip_pool", "[#{index}]", "overflow"],
            reason: "leads back to #{inspect(pool.name)}"
          }
        ],
        else: []
    end)
  end

  defp cycle?(_overflow, nil, _seen), do: false

  defp cycle?(overflow, name, seen) do
    MapSet.member?(seen, name) or cycle?(overflow, overflow[name], MapSet.put(seen, name))
  end

  defp duplicates(items, key, section, what) do
    items
    |> Enum.with_index()
    |> Enum.group_by(fn {item, _index} -> Map.fetch!(item, key) end, &elem(&1, 1))
    |> Enum.flat_map(fn
      {_name, [_]} ->
        []

      {name, [_ | others]} ->
        for index <- others,
            do: %Error{
              path: [section, "[#{index}]", Atom.to_string(key)],
              reason: "#{inspect(name)} names #{what} already"
            }
    end)
  end
end
