defmodule Sovite.Core.Repo.Tables.MTASTSPolicies do
  @moduledoc """
  The MTA-STS policies of recipient domains, cached by
  `Sovite.Core.MTASTS`: one per domain.
  """

  import Ecto.Query, only: [from: 2]

  alias Sovite.Core.Repo
  alias Sovite.Core.Repo.Schemas.MTASTSPolicy

  @doc "The cached policy of `domain`, if any."
  @spec get(Repo.t(), String.t()) :: MTASTSPolicy.t() | nil
  def get(repo, domain), do: Repo.run(repo, & &1.get_by(MTASTSPolicy, domain: domain))

  @doc "Stores the policy of `attrs.domain`, replacing the one cached before."
  @spec put(Repo.t(), map()) :: {:ok, MTASTSPolicy.t()} | {:error, Ecto.Changeset.t()}
  def put(repo, attrs) do
    Repo.run(repo, fn module ->
      (module.get_by(MTASTSPolicy, domain: attrs.domain) || %MTASTSPolicy{})
      |> MTASTSPolicy.changeset(attrs)
      |> module.insert_or_update()
    end)
  end

  @doc "Forgets the policy of `domain`."
  @spec delete(Repo.t(), String.t()) :: non_neg_integer()
  def delete(repo, domain) do
    query = from(p in MTASTSPolicy, where: p.domain == ^domain)
    Repo.run(repo, fn module -> elem(module.delete_all(query), 0) end)
  end

  @doc "All cached policies, by domain."
  @spec list(Repo.t()) :: [MTASTSPolicy.t()]
  def list(repo), do: Repo.run(repo, & &1.all(from(p in MTASTSPolicy, order_by: p.domain)))
end
