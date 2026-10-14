defmodule Sovite.Core.RouteInfo do
  @moduledoc """
  Shows how the routing tables resolve an address, for `sovitectl route`
  and the admin API: the steps a recipient goes through when it is
  received (`Sovite.Core.Rewrite`, `Sovite.Core.Recipients`) and when it
  is delivered (`Sovite.Core.Router`).

    1. Recipient rewriting (canonical and recipient rewrite rules).
    2. The domain's class.
    3. Alias expansion, with BCC copies left out.
    4. For each address it expands to: where its mail goes (transport and
       next hop, or why it is deferred, refused, or discarded), and for
       SMTP the source address and whether the next hop gets a login.

  Nothing is looked up in DNS: an MX next hop is shown as its domain.
  """

  alias Sovite.Core.{Recipients, Rewrite, Router, Routing}

  @doc "Resolves `address`, as mail from `sender` would be."
  @spec resolve(Routing.t(), String.t(), String.t()) :: map()
  def resolve(routing, address, sender \\ "") do
    case Rewrite.recipient(routing, address) do
      {:ok, rewritten} ->
        {_local, domain} = rewritten |> String.downcase() |> Routing.split()
        domain = domain || ""

        base = %{
          address: address,
          rewritten: if(rewritten != address, do: rewritten),
          domain: domain,
          class: Atom.to_string(Routing.class(routing, domain))
        }

        case Recipients.expand(routing, rewritten) do
          {:ok, addresses} ->
            Map.merge(base, %{
              expanded: if(addresses != [rewritten], do: addresses),
              recipients: Enum.map(addresses, &route(routing, sender, &1))
            })

          {:error, :temporary, text} ->
            Map.merge(base, %{error: "alias expansion failed: " <> text, recipients: []})
        end

      {:error, text} ->
        %{address: address, error: "rewriting failed: " <> text, recipients: []}
    end
  end

  defp route(routing, sender, address) do
    case Router.route(routing, sender, address) do
      {:deliver, destination} ->
        Map.merge(
          %{
            address: address,
            result: "deliver",
            transport: Atom.to_string(destination.transport),
            nexthop: Router.name(destination)
          },
          smtp_details(destination)
        )

      {:defer, status, text} ->
        %{address: address, result: "defer", status: status, text: text}

      {:fail, status, text} ->
        %{address: address, result: "fail", status: status, text: text}

      {:discard, text} ->
        %{address: address, result: "discard", text: text}
    end
  end

  defp smtp_details(%{transport: :smtp} = destination) do
    %{
      source:
        for(
          {family, ip} <- destination.source,
          into: %{},
          do: {family, ip |> :inet.ntoa() |> List.to_string()}
        ),
      login: if(destination.auth, do: destination.auth.username)
    }
  end

  defp smtp_details(_destination), do: %{}

  @doc "Formats a result of `resolve/3` as text."
  @spec format(map()) :: String.t()
  def format(info) do
    head =
      [
        "address: #{info.address}",
        info[:rewritten] && "rewritten to: #{info.rewritten}",
        info[:class] && "domain: #{info.domain} (#{info.class})",
        info[:expanded] && "expands to: #{Enum.join(info.expanded, ", ")}",
        info[:error] && "error: #{info.error}"
      ]
      |> Enum.filter(& &1)

    recipients =
      Enum.map(info.recipients, fn recipient ->
        "  #{recipient.address}: " <> describe(recipient)
      end)

    Enum.join(head ++ recipients, "\n") <> "\n"
  end

  defp describe(%{result: "deliver"} = recipient) do
    via =
      case recipient.transport do
        transport when transport in ["local", "mailbox"] -> transport
        transport -> "#{transport} to #{recipient.nexthop}"
      end

    extras =
      [
        recipient[:source] not in [nil, %{}] &&
          "from " <> Enum.map_join(recipient.source, ", ", &elem(&1, 1)),
        recipient[:login] && "login #{recipient.login}"
      ]
      |> Enum.filter(& &1)

    if extras == [],
      do: "deliver via " <> via,
      else: "deliver via #{via} (#{Enum.join(extras, ", ")})"
  end

  defp describe(%{result: "discard"} = recipient), do: "discard: #{recipient.text}"
  defp describe(recipient), do: "#{recipient.result} #{recipient.status}: #{recipient.text}"
end
