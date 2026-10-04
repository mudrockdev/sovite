defmodule Sovite.TLS.CertStoreTest do
  use ExUnit.Case, async: true

  alias Sovite.Test.{Certs, TelemetryForwarder}
  alias Sovite.TLS.CertStore

  @moduletag :tmp_dir

  setup_all do
    %{ca: Certs.ca()}
  end

  defp entry(dir, name, cert, extra \\ %{}) do
    {cert_file, key_file} = Certs.write!(dir, name, cert)
    Map.merge(%{cert_file: cert_file, key_file: key_file}, extra)
  end

  defp start_store(certificates, opts \\ []) do
    opts = Keyword.merge([certificates: certificates, reload_interval: nil], opts)
    start_supervised!({CertStore, opts}, id: make_ref())
  end

  test "picks the certificate by SNI, with the first as default", %{ca: ca, tmp_dir: dir} do
    first = Certs.issue(ca, names: ["mx.example.com"])
    second = Certs.issue(ca, names: ["*.example.org"])
    store = start_store([entry(dir, "first", first), entry(dir, "second", second)])

    der_names = fn name ->
      {:ok, listen} =
        :ssl.listen(0, [ip: {127, 0, 0, 1}, reuseaddr: true] ++ CertStore.server_options(store))

      {:ok, {_, port}} = :ssl.sockname(listen)

      spawn_link(fn ->
        {:ok, socket} = :ssl.transport_accept(listen)
        _ = :ssl.handshake(socket, 5_000)
        Process.sleep(300)
      end)

      sni = if name, do: String.to_charlist(name), else: :disable

      {:ok, socket} =
        :ssl.connect(
          {127, 0, 0, 1},
          port,
          [verify: :verify_none, server_name_indication: sni],
          5_000
        )

      {:ok, der} = :ssl.peercert(socket)
      :ssl.close(socket)
      :ssl.close(listen)
      der
    end

    assert der_names.("mail.example.org") == second.cert
    assert der_names.("mx.example.com") == first.cert
    assert der_names.("unknown.test") == first.cert
    assert der_names.(nil) == first.cert

    assert [%{names: ["mx.example.com"]}, %{names: ["*.example.org"]}] =
             CertStore.certificates(store)
  end

  test "refuses to start without a required certificate", %{tmp_dir: dir} do
    missing = %{cert_file: Path.join(dir, "no.crt"), key_file: Path.join(dir, "no.key")}

    assert {:error, {{:certificate, _, {:cert_file, :enoent}}, _}} =
             start_supervised({CertStore, certificates: [missing]})
  end

  test "has no options until an optional certificate appears", %{ca: ca, tmp_dir: dir} do
    TelemetryForwarder.attach([[:sovite, :tls, :certificate, :loaded]])
    cert_file = Path.join(dir, "acme.crt")
    key_file = Path.join(dir, "acme.key")
    store = start_store([%{cert_file: cert_file, key_file: key_file, optional: true}])
    assert CertStore.server_options(store) == nil

    {^cert_file, ^key_file} = Certs.write!(dir, "acme", Certs.issue(ca, names: ["mx.test"]))
    :ok = CertStore.reload(store)
    assert [_ | _] = CertStore.server_options(store)
    assert_received {:telemetry, _, _, %{cert_file: ^cert_file, names: ["mx.test"]}}
  end

  test "reloads changed files and keeps the old certificate if the new one is broken", %{
    ca: ca,
    tmp_dir: dir
  } do
    TelemetryForwarder.attach([[:sovite, :tls, :certificate, :error]])
    entry = entry(dir, "mx", Certs.issue(ca, names: ["old.test"]))
    store = start_store([entry], reload_interval: 20)
    assert [%{names: ["old.test"]}] = CertStore.certificates(store)

    # A different size guarantees the change is seen within one mtime second.
    Certs.write!(dir, "mx", Certs.issue(ca, names: ["a-longer-new-name.test"]))
    Process.sleep(100)
    assert [%{names: ["a-longer-new-name.test"]}] = CertStore.certificates(store)

    File.write!(entry.key_file, "garbage")
    Process.sleep(100)
    assert [%{names: ["a-longer-new-name.test"]}] = CertStore.certificates(store)
    assert_received {:telemetry, _, _, %{cert_file: _, reason: :no_key}}
  end

  test "applies TLS settings", %{ca: ca, tmp_dir: dir} do
    store =
      start_store([entry(dir, "mx", Certs.issue(ca, names: ["mx.test"]))],
        tls: [min_version: :"tlsv1.3"]
      )

    assert CertStore.server_options(store)[:versions] == [:"tlsv1.3"]
  end
end
