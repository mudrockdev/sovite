defmodule Sovite.Core.Filter.Actions do
  @moduledoc """
  The filter's actions (see `Sovite.Rules.Actions`), with the thresholds
  of the mail they are for. The thresholds for an address come from, the
  first that sets one first:

    1. the database, for the address (`sovitectl filter threshold set
       user@example.com ...`);
    2. the database, for its domain (`@example.com`);
    3. its tenant's `[tenant.filter_actions]`: the tenant given, or the
       one that owns the address's domain;
    4. `[filter.actions]`.

  Each may set a threshold or turn the action off.

  A message for several recipients gets the least severe of their
  actions (`Sovite.Rules.Actions.least_severe/1`), so that no recipient
  loses mail their own thresholds would keep.
  """

  alias Sovite.Core.{Config, Repo, Tenants}
  alias Sovite.Core.Repo.Tables.FilterThresholds
  alias Sovite.Rules.Actions

  @doc """
  The thresholds for mail to (or from) `address`, with `:tenant`, the
  name of the tenant, instead of the owner of its domain. Without a
  database (`repo` is `nil`), those of the tenant and the config.
  """
  @spec thresholds(Config.t(), Repo.t() | nil, String.t(), keyword()) ::
          {:ok, Actions.thresholds()} | {:error, {:database, String.t()}}
  def thresholds(config, repo, address, opts \\ []) do
    domain = domain(address)

    tenant =
      case Keyword.fetch(opts, :tenant) do
        {:ok, name} -> Tenants.get(config.tenant, name)
        :error -> domain && Tenants.get(config.tenant, Tenants.owner(config.tenant, domain))
      end

    base =
      config.filter.actions
      |> Map.new(fn {action, score} -> {action, score || false} end)
      |> override(tenant && tenant.filter_actions)

    with {:ok, rows} <- rows(repo, address, domain) do
      {domain_rows, address_rows} = Enum.split_with(rows, &match?({"@" <> _, _, _}, &1))
      {:ok, base |> Map.merge(scores(domain_rows)) |> Map.merge(scores(address_rows))}
    end
  end

  defp scores(rows),
    do: Map.new(rows, fn {_pattern, action, score} -> {action, score || false} end)

  defp override(thresholds, nil), do: thresholds

  defp override(thresholds, overrides) do
    Enum.reduce(overrides, thresholds, fn
      {_action, nil}, thresholds -> thresholds
      {action, score}, thresholds -> Map.put(thresholds, action, score)
    end)
  end

  defp rows(nil, _address, _domain), do: {:ok, []}

  defp rows(repo, address, domain) do
    patterns = if domain, do: [address, "@" <> domain], else: [address]
    {:ok, FilterThresholds.lookup(repo, patterns)}
  rescue
    error -> {:error, {:database, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:database, inspect(reason)}}
  end

  @doc """
  The action for a message with `score` for `recipients`: each
  recipient's, and the one for the message.
  """
  @spec decide(Config.t(), Repo.t() | nil, number(), [String.t()], keyword()) ::
          {:ok, Actions.action(), %{String.t() => Actions.action()}}
          | {:error, {:database, String.t()}}
  def decide(config, repo, score, recipients, opts \\ []) do
    Enum.reduce_while(recipients, {:ok, %{}}, fn recipient, {:ok, actions} ->
      case thresholds(config, repo, recipient, opts) do
        {:ok, thresholds} ->
          {:cont, {:ok, Map.put(actions, recipient, Actions.decide(score, thresholds))}}

        error ->
          {:halt, error}
      end
    end)
    |> case do
      {:ok, actions} -> {:ok, Actions.least_severe(Map.values(actions)), actions}
      error -> error
    end
  end

  @doc """
  A subject marked by `rewrite_subject`: `[filter] subject` with
  `{subject}` replaced by the message's subject (decoded).

      iex> Sovite.Core.Filter.Actions.subject("***SPAM*** {subject}", "Hello")
      "***SPAM*** Hello"
  """
  @spec subject(String.t(), String.t() | nil) :: String.t()
  def subject(template, subject), do: String.replace(template, "{subject}", subject || "")

  defp domain(address) do
    case String.split(address, "@") do
      [_] -> nil
      parts -> parts |> List.last() |> String.downcase()
    end
  end
end
