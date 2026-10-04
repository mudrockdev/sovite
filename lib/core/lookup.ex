defmodule Sovite.Core.Lookup do
  @moduledoc """
  The interface routing uses to read Sovite's database tables
  (`Sovite.Core.Repo.Tables.*`): a key goes in, a string value or nothing
  comes out.

  A table is `{module, handle}`, where `module` implements `c:lookup/2`.
  Routing holds tables as `{name, table}` pairs, so a failure can name
  the table.

  ## Telemetry

    * `[:sovite, :tables, :lookup_error]` - `%{}`, `%{table, reason}`:
      a table could not be read; the mail is deferred or answered with a
      temporary error.
  """

  @typedoc "A table: a module and its handle."
  @type table :: {module(), term()}

  @typedoc "Named tables, searched in order."
  @type tables :: [{String.t(), table()}]

  @typedoc """
  The result of a lookup: `{:ok, value}`, `:error` when the key is not in
  the table, or `{:error, reason}` when the table could not be read.
  """
  @type result :: {:ok, String.t()} | :error | {:error, term()}

  @doc "Looks up `key`."
  @callback lookup(handle :: term(), key :: String.t()) :: result()

  @doc """
  Tries each key in turn, in each table, and returns the first value
  found with the key that found it. A table that cannot be read stops the
  search and returns `{:error, name}`: a later table must not answer for
  a key the failing one might hold.
  """
  @spec lookup(tables(), [String.t()]) ::
          {:ok, String.t(), String.t()} | :error | {:error, String.t()}
  def lookup([], _keys), do: :error

  def lookup(tables, keys) do
    Enum.reduce_while(keys, :error, fn key, :error ->
      case lookup_key(tables, key) do
        {:ok, value} -> {:halt, {:ok, value, key}}
        :error -> {:cont, :error}
        {:error, _name} = error -> {:halt, error}
      end
    end)
  end

  defp lookup_key(tables, key) do
    Enum.reduce_while(tables, :error, fn {name, {module, handle}}, :error ->
      case module.lookup(handle, key) do
        {:ok, value} ->
          {:halt, {:ok, value}}

        :error ->
          {:cont, :error}

        {:error, reason} ->
          :telemetry.execute([:sovite, :tables, :lookup_error], %{}, %{
            table: name,
            reason: reason
          })

          {:halt, {:error, name}}
      end
    end)
  end
end
