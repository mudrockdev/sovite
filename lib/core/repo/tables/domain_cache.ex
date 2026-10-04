defmodule Sovite.Core.Repo.Tables.DomainCache do
  @moduledoc """
  Keeps the domains of `Sovite.Core.Repo.Tables.Domains` in `:persistent_term`, so
  every recipient check can read them without a database query.

  The list is read at start and every `:interval` (default 10 seconds).
  When the database cannot be read, the last list stays in use.

  ## Options

    * `:repo` - the `Sovite.Core.Repo` reference. Required.
    * `:id` - names the cache, for `classes/1`. Defaults to `id/1` of
      the repo.
    * `:interval` - milliseconds between refreshes.

  ## Telemetry

    * `[:sovite, :domains, :error]` - `%{}`, `%{reason}`
  """

  use GenServer

  alias Sovite.Core.Repo.Tables.Domains

  @doc false
  def child_spec(opts), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}

  @doc "The cache ID for Sovite's database `repo`."
  @spec id(Sovite.Core.Repo.t()) :: term()
  def id({_module, name}), do: name

  @doc "Starts the cache."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc "The cached domains of cache `id`: name to class. Empty before the first read."
  @spec classes(term()) :: %{String.t() => Sovite.Core.Repo.Schemas.Domain.kind()}
  def classes(id), do: :persistent_term.get({__MODULE__, id}, %{})

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)

    state = %{
      repo: Keyword.fetch!(opts, :repo),
      id: Keyword.get_lazy(opts, :id, fn -> id(Keyword.fetch!(opts, :repo)) end),
      interval: Keyword.get(opts, :interval, 10_000)
    }

    refresh(state)
    Process.send_after(self(), :refresh, state.interval)
    {:ok, state}
  end

  @impl true
  def handle_info(:refresh, state) do
    refresh(state)
    Process.send_after(self(), :refresh, state.interval)
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    :persistent_term.erase({__MODULE__, state.id})
    :ok
  end

  defp refresh(state) do
    classes = Domains.classes(state.repo)

    # Replacing a persistent term is costly; only do it on a change.
    if classes != classes(state.id), do: :persistent_term.put({__MODULE__, state.id}, classes)
  rescue
    error ->
      :telemetry.execute([:sovite, :domains, :error], %{}, %{reason: Exception.message(error)})
  catch
    :exit, reason ->
      :telemetry.execute([:sovite, :domains, :error], %{}, %{reason: inspect(reason)})
  end
end
