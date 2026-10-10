defmodule Sovite.Core.Greylist do
  @moduledoc """
  Built-in greylisting (`[greylist]`), with `Sovite.Abuse.Greylist`
  deciding and the `greylist_entries` table remembering.

  A triplet (client network, sender, recipient) seen for the first time
  is deferred. A retry after `greylist.delay`, and within
  `greylist.retry_window`, passes, and the triplet then passes at once
  until it has gone unused for `greylist.max_age`. Real mail servers
  retry; most spam bots do not.

  If the database fails, the recipient passes: greylisting must never
  lose mail.

  As a process, it deletes expired entries every hour.

  ## Telemetry

    * `[:sovite, :greylist, :deferred]` - `%{retry_after}` (seconds),
      `%{client_network, sender, recipient}`
  """

  use GenServer

  require Logger

  alias Sovite.Abuse.Greylist, as: Rules
  alias Sovite.Core.Repo.Tables.GreylistEntries

  @cleanup_interval 3_600_000

  @doc "Greylisting options from the config, or `nil` when it is off."
  @spec opts(Sovite.Core.Config.t(), Sovite.Core.Repo.t() | nil) :: map() | nil
  def opts(%{greylist: %{enabled: true} = greylist}, repo) when repo != nil,
    do: %{
      repo: repo,
      delay: greylist.delay,
      retry_window: greylist.retry_window,
      max_age: greylist.max_age
    }

  def opts(_config, _repo), do: nil

  @doc "Whether mail from `ip` and `sender` to `recipient` may pass now."
  @spec check(map() | nil, :inet.ip_address(), String.t(), String.t()) ::
          :pass | {:defer, pos_integer()}
  def check(nil, _ip, _sender, _recipient), do: :pass

  def check(opts, ip, sender, recipient) do
    triplet = Rules.triplet(ip, sender, recipient)

    case decide(opts, triplet) do
      # Another session stored the triplet first: decide again with it.
      :conflict -> with :conflict <- decide(opts, triplet), do: :pass
      verdict -> verdict
    end
  rescue
    error ->
      Logger.error("greylisting failed, letting mail through: #{Exception.message(error)}")
      :pass
  end

  defp decide(opts, {network, sender, recipient} = triplet) do
    key = Rules.key(triplet)
    stored = GreylistEntries.get(opts.repo, key)
    entry = stored && Map.take(stored, [:first_seen, :last_seen, :passed_at, :expires_at])
    check_opts = opts |> Map.take([:delay, :retry_window, :max_age]) |> Map.to_list()
    {verdict, entry} = Rules.check(entry, DateTime.utc_now(), check_opts)
    fields = %{triplet: key, client_network: network, sender: sender, recipient: recipient}

    case GreylistEntries.put(opts.repo, Map.merge(entry, fields)) do
      {:ok, _entry} ->
        deferred(verdict, fields)

      {:error, %{errors: [triplet: _]}} when stored == nil ->
        :conflict

      {:error, changeset} ->
        raise ArgumentError, "invalid greylist entry: #{inspect(changeset.errors)}"
    end
  end

  defp deferred({:defer, seconds} = verdict, fields) do
    :telemetry.execute(
      [:sovite, :greylist, :deferred],
      %{retry_after: seconds},
      Map.delete(fields, :triplet)
    )

    verdict
  end

  defp deferred(:pass, _fields), do: :pass

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @impl true
  def init(opts) do
    schedule(opts)
    {:ok, Map.new(opts)}
  end

  @impl true
  def handle_info(:cleanup, state) do
    GreylistEntries.delete_expired(state.repo, DateTime.utc_now())
    schedule(state)
    {:noreply, state}
  rescue
    error ->
      Logger.error("cannot delete expired greylist entries: #{Exception.message(error)}")
      schedule(state)
      {:noreply, state}
  end

  defp schedule(opts),
    do: Process.send_after(self(), :cleanup, opts[:interval] || @cleanup_interval)
end
