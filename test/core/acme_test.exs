defmodule Sovite.Core.ACMETest do
  use ExUnit.Case, async: true

  alias Sovite.Core.ACME
  alias Sovite.Test.{FakeACME, TelemetryForwarder}
  alias Sovite.TLS.CertStore

  @moduletag :tmp_dir

  defp free_port do
    {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    port
  end

  defp config(dir, ca, port, extra \\ %{}) do
    Map.merge(
      %{
        enabled: true,
        directory_url: FakeACME.directory_url(ca),
        email: "admin@example.com",
        domains: ["mx.example.com"],
        accept_terms: true,
        storage: Path.join(dir, "acme"),
        http_address: {127, 0, 0, 1},
        http_port: port,
        renew_before: 30 * 86_400_000
      },
      extra
    )
  end

  defp start(config) do
    store =
      start_supervised!(
        {CertStore,
         certificates: [Map.put(ACME.files(config), :optional, true)], reload_interval: nil},
        id: make_ref()
      )

    manager =
      start_supervised!({ACME, config: config, cert_store: store, acme: [poll_interval: 10]},
        id: config.storage
      )

    {store, manager}
  end

  test "issues a certificate at startup and keeps it while valid", %{tmp_dir: dir} do
    TelemetryForwarder.attach([[:sovite, :tls, :acme, :issued]])
    port = free_port()
    ca = FakeACME.start!(challenge_port: port)
    config = config(dir, ca, port)
    {store, manager} = start(config)

    assert ACME.check(manager) == :ok
    assert FakeACME.orders(ca) == 1
    assert_received {:telemetry, _, _, %{domains: ["mx.example.com"], not_after: %DateTime{}}}

    %{cert_file: cert_file, key_file: key_file} = ACME.files(config)
    assert File.stat!(key_file).mode |> Bitwise.band(0o777) == 0o600

    assert File.stat!(Path.join(config.storage, "account.key")).mode |> Bitwise.band(0o777) ==
             0o600

    assert File.exists?(cert_file)
    assert [%{names: ["mx.example.com"]}] = CertStore.certificates(store)
  end

  test "renews a certificate close to expiry, and when domains change", %{tmp_dir: dir} do
    port = free_port()
    ca = FakeACME.start!(challenge_port: port, valid_days: 10)
    config = config(dir, ca, port)
    {_store, manager} = start(config)
    # Wait for the order made at startup.
    :sys.get_state(manager)
    assert FakeACME.orders(ca) == 1

    # Ten days left, renew_before is 30: every check renews.
    assert ACME.check(manager) == :ok
    assert FakeACME.orders(ca) == 2
    stop_supervised!(config.storage)

    FakeACME.set(ca, :valid_days, 90)
    config = %{config | domains: ["mx.example.com", "mail.example.com"]}
    {store, manager} = start(config)
    :sys.get_state(manager)
    assert FakeACME.orders(ca) == 3
    assert [%{names: ["mx.example.com", "mail.example.com"]}] = CertStore.certificates(store)
  end

  test "reports failures and keeps no certificate", %{tmp_dir: dir} do
    TelemetryForwarder.attach([[:sovite, :tls, :acme, :failed]])
    # The CA checks a port where nothing answers.
    ca = FakeACME.start!(challenge_port: free_port())
    config = config(dir, ca, free_port())
    {store, manager} = start(config)

    assert {:error, {:challenge_failed, "mx.example.com", _}} = ACME.check(manager)
    assert_received {:telemetry, _, _, %{reason: {:challenge_failed, _, _}}}
    assert CertStore.server_options(store) == nil
  end
end
