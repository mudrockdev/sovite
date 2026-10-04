defmodule Sovite.Core.Config.RoutingRules do
  @moduledoc false
  # Cross-key checks for [domains], [restrictions], [routing], and the
  # routing settings of [delivery].

  alias Sovite.Core.Config.Error
  alias Sovite.Core.Restrictions

  @spec errors(map()) :: [Error.t()]
  def errors(values) do
    domain_errors(values.domains) ++
      restriction_errors(values.restrictions) ++
      source_errors(values.delivery.source_address) ++
      pipe_errors(values.routing, values.pipe)
  end

  # A pipe transport must name a [pipe.<name>] section.
  defp pipe_errors(routing, pipes) do
    for key <- [:local_transport, :mailbox_transport, :relay_transport, :remote_transport],
        %{transport: :pipe, nexthop: name} <- [Map.fetch!(routing, key)],
        not Map.has_key?(pipes, name),
        do: %Error{
          path: ["routing", Atom.to_string(key)],
          reason: "there is no [pipe.#{name}] section"
        }
  end

  # A domain can only be in one class.
  defp domain_errors(domains) do
    classes = [
      {"local", domains.local},
      {"relay", domains.relay},
      {"aliased", domains.aliased},
      {"hosted", domains.hosted}
    ]

    for {{a, list_a}, i} <- Enum.with_index(classes),
        {{b, list_b}, j} <- Enum.with_index(classes),
        i < j,
        domain <- list_a,
        domain in list_b,
        do: %Error{path: ["domains", b], reason: "#{inspect(domain)} is also in domains.#{a}"}
  end

  defp restriction_errors(restrictions) do
    for stage <- Restrictions.stages(),
        {name, index} <- Enum.with_index(Map.fetch!(restrictions, stage)),
        not Restrictions.allowed?(name, stage),
        do: %Error{
          path: ["restrictions", Atom.to_string(stage), "[#{index}]"],
          reason: "#{name} cannot be used in the #{stage} stage"
        }
  end

  defp source_errors(ips) do
    {v4, v6} = Enum.split_with(ips, &(tuple_size(&1) == 4))

    if length(v4) > 1 or length(v6) > 1,
      do: [
        %Error{
          path: ["delivery", "source_address"],
          reason: "at most one IPv4 and one IPv6 address"
        }
      ],
      else: []
  end
end
