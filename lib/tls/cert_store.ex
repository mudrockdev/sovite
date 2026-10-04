defmodule Sovite.TLS.CertStore do
  @moduledoc """
  Holds server certificates, picks one per connection by SNI (RFC 6066),
  and reloads them when their files change.

      children = [
        {Sovite.TLS.CertStore,
         name: MyApp.Certs,
         certificates: [
           %{cert_file: "/etc/tls/mx.example.com.pem", key_file: "/etc/tls/mx.example.com.key"},
           %{cert_file: "/etc/tls/mail.example.org.pem", key_file: "/etc/tls/mail.example.org.key"}
         ]}
      ]

      ssl_opts = Sovite.TLS.CertStore.server_options(MyApp.Certs)

  A client asking for a name gets every certificate valid for it (for
  example both an RSA and an ECDSA one; `:ssl` picks what the client
  supports). Clients without SNI, or asking for an unknown name, get the
  default: the first certificate, with any others for exactly the same
  names.

  Files are checked every `:reload_interval` and reloaded when their
  size, modification time, or inode changes. A file that fails to load
  keeps its previous certificate, so a half-written renewal does not
  take TLS down. `reload/1` forces a check.

  ## Options

    * `:certificates` - a list of `%{cert_file, key_file}` maps, see
      `Sovite.TLS.Certificate.load/2`. Add `optional: true` to skip a pair
      whose files do not exist yet, such as one an ACME client will write.
      Required.
    * `:tls` - options for `Sovite.TLS.server_options/1`, such as
      `:min_version` and `:ciphers`.
    * `:reload_interval` - milliseconds, or `nil` to never check. Defaults
      to 60 seconds.
    * `:name` - registered name.

  Starting fails if a required certificate cannot be loaded.

  ## Telemetry

    * `[:sovite, :tls, :certificate, :loaded]` - `%{}`, `%{cert_file,
      names, not_after}`
    * `[:sovite, :tls, :certificate, :error]` - `%{}`, `%{cert_file,
      reason}` (a `Sovite.TLS.Certificate.error()`)
  """

  use GenServer

  alias Sovite.TLS
  alias Sovite.TLS.Certificate

  @doc false
  def child_spec(opts) do
    %{id: Keyword.get(opts, :name) || __MODULE__, start: {__MODULE__, :start_link, [opts]}}
  end

  @doc "Starts the store."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    opts = Keyword.validate!(opts, [:certificates, :name, tls: [], reload_interval: 60_000])
    name = opts[:name]
    GenServer.start_link(__MODULE__, opts, if(name, do: [name: name], else: []))
  end

  @doc """
  Returns `:ssl` server options for the current certificates, or `nil`
  when none is loaded. Call it per connection, so reloaded certificates
  apply to new connections.
  """
  @spec server_options(GenServer.server()) :: [:ssl.tls_server_option()] | nil
  def server_options(store), do: GenServer.call(store, :server_options)

  @doc "Returns the loaded certificates, default first."
  @spec certificates(GenServer.server()) :: [Certificate.t()]
  def certificates(store), do: GenServer.call(store, :certificates)

  @doc "Checks the files now and reloads what changed."
  @spec reload(GenServer.server()) :: :ok
  def reload(store), do: GenServer.call(store, :reload)

  ## Server

  @impl true
  def init(opts) do
    entries =
      for spec <- Keyword.fetch!(opts, :certificates) do
        %{
          cert_file: Map.fetch!(spec, :cert_file),
          key_file: Map.fetch!(spec, :key_file),
          optional: Map.get(spec, :optional, false),
          stamp: nil,
          certificate: nil
        }
      end

    state = %{entries: entries, tls: opts[:tls], interval: opts[:reload_interval], options: nil}

    case refresh(state) do
      {state, []} ->
        schedule(state)
        {:ok, state}

      {_state, [{entry, reason} | _]} ->
        {:stop, {:certificate, entry.cert_file, reason}}
    end
  end

  @impl true
  def handle_call(:server_options, _from, state), do: {:reply, state.options, state}

  def handle_call(:certificates, _from, state),
    do: {:reply, for(%{certificate: %Certificate{} = c} <- state.entries, do: c), state}

  def handle_call(:reload, _from, state) do
    {state, _failed} = refresh(state)
    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:reload, state) do
    {state, _failed} = refresh(state)
    schedule(state)
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp schedule(%{interval: nil}), do: :ok
  defp schedule(%{interval: interval}), do: Process.send_after(self(), :reload, interval)

  # Reloads changed entries. Returns the new state and the required
  # entries that have no certificate.
  defp refresh(state) do
    entries = Enum.map(state.entries, &refresh_entry/1)

    failed =
      for %{certificate: nil, optional: false} = entry <- entries,
          do: {entry, Map.get(entry, :error, :not_loaded)}

    entries = Enum.map(entries, &Map.delete(&1, :error))
    state = %{state | entries: entries}
    {%{state | options: build_options(state)}, failed}
  end

  defp refresh_entry(entry) do
    stamp = stamp(entry)

    cond do
      stamp == entry.stamp ->
        entry

      stamp == :missing and entry.optional and entry.certificate == nil ->
        %{entry | stamp: stamp}

      true ->
        load(entry, stamp)
    end
  end

  defp load(entry, stamp) do
    case Certificate.load(entry.cert_file, entry.key_file) do
      {:ok, certificate} ->
        :telemetry.execute([:sovite, :tls, :certificate, :loaded], %{}, %{
          cert_file: entry.cert_file,
          names: certificate.names,
          not_after: certificate.not_after
        })

        %{entry | stamp: stamp, certificate: certificate}

      {:error, reason} ->
        :telemetry.execute([:sovite, :tls, :certificate, :error], %{}, %{
          cert_file: entry.cert_file,
          reason: reason
        })

        # Keep the stamp, so a broken file is reported once, not on every check.
        Map.put(%{entry | stamp: stamp}, :error, reason)
    end
  end

  defp stamp(entry) do
    with {:ok, cert} <- File.stat(entry.cert_file),
         {:ok, key} <- File.stat(entry.key_file) do
      {cert.size, cert.mtime, cert.inode, key.size, key.mtime, key.inode}
    else
      _ -> :missing
    end
  end

  defp build_options(state) do
    case for(%{certificate: %Certificate{} = c} <- state.entries, do: c) do
      [] ->
        nil

      [default | _] = certificates ->
        defaults = for c <- certificates, c.names == default.names, do: Certificate.certs_keys(c)

        TLS.server_options(
          Keyword.merge(state.tls, certs_keys: defaults, sni_fun: sni_fun(certificates))
        )
    end
  end

  defp sni_fun(certificates), do: &select(certificates, to_string(&1))

  defp select(certificates, hostname) do
    case for(c <- certificates, Certificate.matches?(c, hostname), do: c) do
      [] -> :undefined
      matching -> [certs_keys: Enum.map(matching, &Certificate.certs_keys/1)]
    end
  end
end
