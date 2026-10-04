defmodule Sovite.Core.ACME do
  @moduledoc """
  Keeps an ACME certificate (`[tls.acme]`) issued and renewed.

  At startup, and twice a day, it checks the certificate in
  `tls.acme.storage`. If it is missing, does not cover `tls.acme.domains`,
  or expires within `tls.acme.renew_before`, a new one is ordered with
  `Sovite.TLS.ACME`:

    1. An HTTP listener for HTTP-01 challenges starts on
       `tls.acme.http_address:http_port` (port 80 for real CAs: they
       connect there). It runs only while an order is in progress.
    2. The new key and certificate are written next to each other,
       `key.pem` (mode `0600`) and `cert.pem`, then the certificate store
       reloads them.

  A failed attempt is retried after an hour; the current certificate
  stays in use meanwhile. The account key is kept in `account.key`.

  ## Telemetry

    * `[:sovite, :tls, :acme, :issued]` - `%{}`, `%{domains, not_after}`
    * `[:sovite, :tls, :acme, :failed]` - `%{}`, `%{domains, reason}`
  """

  use GenServer

  alias Sovite.TLS.{ACME, Certificate, CertStore}

  @check_interval 12 * 3_600_000
  @retry_interval 3_600_000

  @doc "The certificate and key files ACME maintains for `config`."
  @spec files(map()) :: %{cert_file: Path.t(), key_file: Path.t()}
  def files(config) do
    %{
      cert_file: Path.join(config.storage, "cert.pem"),
      key_file: Path.join(config.storage, "key.pem")
    }
  end

  @doc false
  def child_spec(opts), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}

  @doc """
  Starts the manager. Options: `:config` (the `[tls.acme]` section),
  `:cert_store`, `:name`, and `:acme` (extra `Sovite.TLS.ACME` options,
  for tests).
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name)
    GenServer.start_link(__MODULE__, opts, if(name, do: [name: name], else: []))
  end

  @doc "Checks the certificate now, and renews it if needed. Waits for the result."
  @spec check(GenServer.server(), timeout()) :: :ok | {:error, term()}
  def check(server, timeout \\ 300_000), do: GenServer.call(server, :check, timeout)

  @impl true
  def init(opts) do
    state = %{
      config: Keyword.fetch!(opts, :config),
      cert_store: Keyword.get(opts, :cert_store),
      acme_opts: Keyword.get(opts, :acme, []),
      timer: nil
    }

    {:ok, state, {:continue, :check}}
  end

  @impl true
  def handle_continue(:check, state) do
    {_result, state} = run(state)
    {:noreply, state}
  end

  @impl true
  def handle_call(:check, _from, state) do
    {result, state} = run(state)
    {:reply, result, state}
  end

  @impl true
  def handle_info(:check, state) do
    {_result, state} = run(state)
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp run(state) do
    if state.timer, do: Process.cancel_timer(state.timer)

    {result, delay} =
      if renewal_needed?(state.config) do
        case issue(state) do
          :ok -> {:ok, @check_interval}
          {:error, _} = error -> {error, @retry_interval}
        end
      else
        {:ok, @check_interval}
      end

    {result, %{state | timer: Process.send_after(self(), :check, delay)}}
  end

  defp renewal_needed?(config) do
    %{cert_file: cert_file, key_file: key_file} = files(config)

    case Certificate.load(cert_file, key_file) do
      {:ok, cert} ->
        renew_at = DateTime.add(cert.not_after, -config.renew_before, :millisecond)
        missing = Enum.reject(config.domains, &Certificate.matches?(cert, &1))
        missing != [] or DateTime.compare(DateTime.utc_now(), renew_at) != :lt

      {:error, _} ->
        true
    end
  end

  defp issue(state) do
    config = state.config
    table = :ets.new(__MODULE__, [:public, :set])

    result =
      with :ok <- File.mkdir_p(config.storage),
           :ok <- File.chmod(config.storage, 0o700),
           {:ok, account_key} <- account_key(config),
           {:ok, listener} <- start_listener(config, table) do
        try do
          order(state, account_key, table)
        after
          Supervisor.stop(listener)
        end
      end

    :ets.delete(table)

    case result do
      {:ok, cert} ->
        :telemetry.execute([:sovite, :tls, :acme, :issued], %{}, %{
          domains: config.domains,
          not_after: cert.not_after
        })

        if state.cert_store, do: CertStore.reload(state.cert_store)
        :ok

      {:error, reason} = error ->
        :telemetry.execute([:sovite, :tls, :acme, :failed], %{}, %{
          domains: config.domains,
          reason: reason
        })

        error
    end
  end

  defp order(state, account_key, table) do
    config = state.config
    key = :public_key.generate_key({:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}})

    publish = fn
      {:put, token, key_authorization} -> :ets.insert(table, {token, key_authorization})
      {:delete, token} -> :ets.delete(table, token)
    end

    with {:ok, acme} <- ACME.connect(config.directory_url, account_key, state.acme_opts),
         {:ok, acme} <- ACME.register(acme, config.email),
         {:ok, pem, _acme} <- ACME.obtain(acme, config.domains, key, publish),
         key_pem = pem_key(key),
         {:ok, cert} <- Certificate.decode(pem, key_pem),
         :ok <- write(files(config), pem, key_pem) do
      {:ok, cert}
    end
  end

  defp start_listener(config, table) do
    Sovite.Listener.start_link(
      ip: config.http_address,
      port: config.http_port,
      handler: Sovite.TLS.ACME.HTTPChallenge,
      handler_opts: [table: table],
      id: "acme-http",
      max_connections: 100
    )
  end

  defp account_key(config) do
    path = Path.join(config.storage, "account.key")

    case File.read(path) do
      {:ok, pem} ->
        case :public_key.pem_decode(pem) do
          [entry | _] -> {:ok, :public_key.pem_entry_decode(entry)}
          [] -> {:error, {:invalid_account_key, path}}
        end

      {:error, :enoent} ->
        key = :public_key.generate_key({:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}})

        with :ok <- write_file(path, pem_key(key), 0o600), do: {:ok, key}

      {:error, reason} ->
        {:error, {:account_key, reason}}
    end
  end

  # Key first, then certificate, each by rename, so readers never see a
  # half-written file.
  defp write(%{cert_file: cert_file, key_file: key_file}, pem, key_pem) do
    with :ok <- write_file(key_file, key_pem, 0o600), do: write_file(cert_file, pem, 0o644)
  end

  defp write_file(path, data, mode) do
    tmp = path <> ".tmp"

    with :ok <- File.write(tmp, data),
         :ok <- File.chmod(tmp, mode) do
      File.rename(tmp, path)
    end
  end

  defp pem_key(key) do
    :public_key.pem_encode([
      {:ECPrivateKey, :public_key.der_encode(:ECPrivateKey, key), :not_encrypted}
    ])
  end
end
