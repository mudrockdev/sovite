defmodule Sovite.Core.Repo.Data do
  @moduledoc false
  # Helpers shared by the routing data contexts (Sovite.Core.Repo.Tables.Domains,
  # Aliases, Mailboxes, ...): key normalization, pattern validation, and
  # table lookups that turn database failures into temporary errors.

  import Ecto.Changeset

  alias Sovite.Core.Repo
  alias Sovite.Validators

  @doc "Keys are stored and looked up trimmed and lower-cased."
  @spec fold(String.t()) :: String.t()
  def fold(value), do: value |> String.trim() |> String.downcase()

  @typedoc "What an address pattern may be."
  @type form :: :address | :catchall | :local_part | :domain | :subdomains | :wildcard

  @doc "Whether `pattern` has form `form`."
  @spec form?(String.t(), form()) :: boolean()
  def form?(pattern, :wildcard), do: pattern == "*"
  def form?("@" <> domain, :catchall), do: Validators.domain?(domain)
  def form?("." <> domain, :subdomains), do: Validators.domain?(domain)
  def form?(pattern, :address), do: Validators.mailbox?(pattern)

  def form?(pattern, :domain),
    do: not String.contains?(pattern, "@") and Validators.domain?(pattern)

  def form?(pattern, :local_part),
    do: not String.contains?(pattern, "@") and Validators.local_part?(pattern)

  def form?(_pattern, _form), do: false

  @doc "Validates that `field` has one of `forms`."
  @spec validate_pattern(Ecto.Changeset.t(), atom(), [form()], String.t()) :: Ecto.Changeset.t()
  def validate_pattern(changeset, field, forms, message) do
    validate_change(changeset, field, fn ^field, value ->
      if Enum.any?(forms, &form?(value, &1)), do: [], else: [{field, message}]
    end)
  end

  @doc "Normalizes `fields` with `fold/1`."
  @spec fold_fields(Ecto.Changeset.t(), [atom()]) :: Ecto.Changeset.t()
  def fold_fields(changeset, fields),
    do: Enum.reduce(fields, changeset, &update_change(&2, &1, fn value -> fold(value) end))

  @doc """
  Inserts or updates the row of `schema` matching `clauses`, applying
  `changeset` (a function of the existing or new struct).
  """
  @spec upsert(Repo.t(), module(), keyword(), (struct() -> Ecto.Changeset.t())) ::
          {:ok, struct()} | {:error, Ecto.Changeset.t()}
  def upsert(repo, schema, clauses, changeset) do
    Repo.run(repo, fn module ->
      module.transaction(fn -> upsert_row(module, schema, clauses, changeset) end)
    end)
  end

  defp upsert_row(module, schema, clauses, changeset) do
    row = module.get_by(schema, clauses) || struct(schema)

    case module.insert_or_update(changeset.(row)) do
      {:ok, row} -> row
      {:error, changeset} -> module.rollback(changeset)
    end
  end

  @doc "Deletes the rows matching `query`; `{:error, :not_found}` if none."
  @spec delete(Repo.t(), Ecto.Queryable.t()) :: :ok | {:error, :not_found}
  def delete(repo, query) do
    case Repo.run(repo, & &1.delete_all(query)) do
      {0, _} -> {:error, :not_found}
      {_, _} -> :ok
    end
  end

  @doc "Sets `enabled` on the row of `schema` matching `clauses`."
  @spec set_enabled(Repo.t(), module(), keyword(), boolean()) ::
          {:ok, struct()} | {:error, :not_found | Ecto.Changeset.t()}
  def set_enabled(repo, schema, clauses, enabled) do
    Repo.run(repo, fn module ->
      case module.get_by(schema, clauses) do
        nil -> {:error, :not_found}
        row -> row |> change(enabled: enabled) |> module.update()
      end
    end)
  end

  @doc """
  Runs a lookup query for `Sovite.Core.Lookup`: `nil` is "not found", a
  database failure is `{:error, {:database, message}}`.
  """
  @spec lookup(Repo.t(), (module() -> String.t() | nil)) :: Sovite.Core.Lookup.result()
  def lookup(repo, fun) do
    case Repo.run(repo, fun) do
      nil -> :error
      "" -> :error
      value -> {:ok, value}
    end
  rescue
    error -> {:error, {:database, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:database, inspect(reason)}}
  end
end
