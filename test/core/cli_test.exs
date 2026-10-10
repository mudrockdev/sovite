defmodule Sovite.Core.CLITest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias Sovite.Core.{CLI, Greylist}
  alias Sovite.DKIM.SigningKey
  alias Sovite.SASL.Password
  alias Sovite.Test.{Certs, Database, FakeNameserver}
  alias Sovite.TLS.MTASTS

  @moduletag :tmp_dir

  test "config check succeeds for a valid file", %{tmp_dir: dir} do
    path = Path.join(dir, "ok.toml")
    File.write!(path, ~s([server]\nhostname = "mx.example.org"\n))

    assert capture_io(fn -> assert CLI.run(["config", "check", path]) == 0 end) == "#{path}: OK\n"
  end

  test "config check prints each error and fails", %{tmp_dir: dir} do
    path = Path.join(dir, "bad.toml")
    File.write!(path, ~s([log]\nlevel = "loud"\nfoo = 1\n))

    stderr = capture_io(:stderr, fn -> assert CLI.run(["config", "check", path]) == 1 end)

    assert stderr =~ "#{path}: log.foo: unknown key"
    assert stderr =~ "#{path}: log.level: expected one of"
  end

  describe "DKIM keys and DNS records" do
    test "dkim generate writes a private key and prints its record", %{tmp_dir: dir} do
      file = Path.join(dir, "example.com.pem")

      output =
        capture_io(fn ->
          assert CLI.run(["dkim", "generate", "Example.com", "s2026", file, "rsa:1024"]) == 0
        end)

      assert output =~ ~s(s2026._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=)
      assert output =~ ~s(file = "#{file}")
      assert Bitwise.band(File.stat!(file).mode, 0o777) == 0o600
      assert {:ok, _key} = SigningKey.from_pem(File.read!(file), "example.com", "s")

      # An existing file is never overwritten.
      stderr =
        capture_io(:stderr, fn ->
          assert CLI.run(["dkim", "generate", "example.com", "s2026", file, "ed25519"]) == 1
        end)

      assert stderr =~ "cannot write #{file}: file already exists"

      for args <- [["rsa:512"], ["dsa"], ["rsa:x"]] do
        capture_io(:stderr, fn ->
          assert CLI.run(["dkim", "generate", "example.com", "s", file <> "2" | args]) == 64
        end)
      end

      assert capture_io(:stderr, fn ->
               assert CLI.run(["dkim", "generate", "bad_domain!", "s", file <> "3"]) == 1
             end) =~ "invalid domain"

      assert capture_io(:stderr, fn ->
               assert CLI.run(["dkim", "generate", "example.com", "-s", file <> "3"]) == 1
             end) =~ "invalid selector"
    end

    test "dns records prints what a domain needs", %{tmp_dir: dir} do
      cert = Certs.issue(Certs.ca(), names: ["mx.example.com"])
      {cert_file, key_file} = Certs.write!(dir, "mx", cert)
      key = Path.join(dir, "key.pem")
      File.write!(key, SigningKey.generate(:rsa, 2048))
      config = Path.join(dir, "sovite.toml")

      File.write!(config, """
      [server]
      hostname = "mx.example.com"
      [delivery]
      source_address = ["192.0.2.25", "2001:db8::25"]
      [[tls.certificate]]
      cert_file = "#{cert_file}"
      key_file = "#{key_file}"
      [mta_sts]
      mode = "enforce"
      [[dkim.key]]
      domain = "example.com"
      selector = "old"
      file = "#{key}"
      sign = false
      """)

      output =
        capture_io(fn ->
          assert CLI.run(["--config", config, "dns", "records", "example.com"]) == 0
        end)

      assert output =~ "example.com. IN MX 10 mx.example.com."

      assert output =~
               ~s(example.com. IN TXT "v=spf1 a:mx.example.com ip4:192.0.2.25 ip6:2001:db8::25 -all")

      # Long keys are split into strings of at most 255 bytes.
      assert [_, strings] = Regex.run(~r/old._domainkey.example.com. IN TXT (.*)\n/, output)
      assert length(String.split(strings, ~s(" "))) == 2
      assert output =~ "old does not sign"

      assert output =~
               ~s(_dmarc.example.com. IN TXT "v=DMARC1; p=none; rua=mailto:postmaster@example.com")

      policy = MTASTS.policy_text(:enforce, ["mx.example.com"], 604_800)
      id = MTASTS.policy_id(policy)
      assert output =~ ~s(_mta-sts.example.com. IN TXT "v=STSv1; id=#{id}")
      assert output =~ ";   mode: enforce\n;   mx: mx.example.com\n"

      {:Certificate, tbs, _, _} = :public_key.pkix_decode_cert(cert.cert, :plain)
      spki = :public_key.der_encode(:SubjectPublicKeyInfo, elem(tbs, 7))
      tlsa = :sha256 |> :crypto.hash(spki) |> Base.encode16(case: :lower)
      assert output =~ "_25._tcp.mx.example.com. IN TLSA 3 1 1 #{tlsa}\n"

      assert output =~
               ~s(_smtp._tls.example.com. IN TXT "v=TLSRPTv1; rua=mailto:postmaster@example.com")

      other = capture_io(fn -> CLI.run(["--config", config, "dns", "records", "example.org"]) end)
      assert other =~ "No [[dkim.key]] for example.org"

      stderr =
        capture_io(:stderr, fn ->
          assert CLI.run(["--config", key, "dns", "records", "x.example"]) == 1
        end)

      assert stderr =~ "invalid TOML"
      assert capture_io(:stderr, fn -> assert CLI.run(["dns", "frob"]) == 64 end) =~ "Usage"
    end

    test "dns check asks the configured resolver", %{tmp_dir: dir} do
      {:ok, ns} =
        FakeNameserver.start_link(%{
          {".", :ns} => {:secure, [~c"a.root-servers.net"]}
        })

      {{127, 0, 0, 1}, port} = FakeNameserver.address(ns)
      config = Path.join(dir, "sovite.toml")
      write = &File.write!(config, "[dns]\nnameservers = [\"127.0.0.1\"]\nport = #{port}\n" <> &1)

      write.("")

      assert capture_io(fn -> assert CLI.run(["--config", config, "dns", "check"]) == 0 end) =~
               "validates DNSSEC"

      write.(~s(dnssec = "off"\n))

      assert capture_io(fn -> assert CLI.run(["--config", config, "dns", "check"]) == 1 end) =~
               "DANE will not be used"

      {:ok, empty} = FakeNameserver.start_link(%{})
      {_, port} = FakeNameserver.address(empty)
      File.write!(config, "[dns]\nnameservers = [\"127.0.0.1\"]\nport = #{port}\n")

      assert capture_io(:stderr, fn ->
               assert CLI.run(["--config", config, "dns", "check"]) == 1
             end) =~ "cannot query the DNS resolver: nxdomain"
    end
  end

  test "unknown commands print usage and exit 64" do
    stderr = capture_io(:stderr, fn -> assert CLI.run(["frobnicate"]) == 64 end)
    assert stderr =~ "Usage: sovitectl"
  end

  test "version prints the version" do
    assert capture_io(fn -> assert CLI.run(["version"]) == 0 end) =~ ~r/^sovite \d+\.\d+\.\d+/
  end

  test "help prints usage" do
    assert capture_io(fn -> assert CLI.run(["help"]) == 0 end) =~ "config check [PATH]"
  end

  describe "users" do
    setup %{tmp_dir: dir} do
      path = Path.join(dir, "sovite.toml")
      File.write!(path, ~s([database]\npath = "#{Path.join(dir, "sovite.db")}"\n))
      %{config: path}
    end

    defp cli(config, args, input \\ "") do
      ref = make_ref()
      parent = self()

      stdout =
        capture_io(input, fn ->
          stderr =
            capture_io(:stderr, fn ->
              send(parent, {ref, CLI.run(["--config", config | args])})
            end)

          send(parent, {ref, :stderr, stderr})
        end)

      assert_received {^ref, status}
      assert_received {^ref, :stderr, stderr}
      {status, stdout, stderr}
    end

    test "lists and flushes greylisting triplets", %{config: config, tmp_dir: dir} do
      repo = Database.start!(dir)
      opts = %{repo: repo, delay: 60_000, retry_window: 86_400_000, max_age: 86_400_000}
      {:defer, _} = Greylist.check(opts, {192, 0, 2, 1}, "", "bob@example.com")

      assert {0, stdout, _} = cli(config, ["greylist", "list"])

      assert stdout =~
               ~r/\A192.0.2.0\/24  <>  bob@example.com  waiting  \S+\n1 triplets, 0 passed\n\z/

      assert {0, "deleted 1 greylisting triplets\n", _} = cli(config, ["greylist", "flush"])
      assert {0, "0 triplets, 0 passed\n", _} = cli(config, ["greylist", "list"])
    end

    test "manages users and sender addresses", %{config: config} do
      assert {0, "created alice@example.com\n", _} =
               cli(config, ["user", "add", "Alice@Example.com"], "secret\n")

      assert {1, "", stderr} = cli(config, ["user", "add", "alice@example.com"], "x\n")
      assert stderr =~ "error: username has already been taken"

      assert {0, _, _} =
               cli(config, ["user", "sender", "add", "alice@example.com", "@example.org"])

      assert {1, _, stderr} =
               cli(config, ["user", "sender", "add", "alice@example.com", "nonsense"])

      assert stderr =~ "address must be"

      assert {0, "alice@example.com  enabled  senders: @example.org\n", _} =
               cli(config, ["user", "list"])

      assert {0, _, _} = cli(config, ["user", "disable", "alice@example.com"])

      assert {0, "alice@example.com  disabled  senders: @example.org\n", _} =
               cli(config, ["user", "list"])

      assert {0, _, _} = cli(config, ["user", "enable", "alice@example.com"])
      assert {0, _, _} = cli(config, ["user", "passwd", "alice@example.com"], "new\n")

      assert {0, _, _} =
               cli(config, ["user", "sender", "remove", "alice@example.com", "@example.org"])

      assert {0, _, _} = cli(config, ["user", "delete", "alice@example.com"])

      assert {1, _, "error: no such user\n"} =
               cli(config, ["user", "delete", "alice@example.com"])

      assert {0, "", _} = cli(config, ["user", "list"])
    end

    test "refuses an empty password", %{config: config} do
      assert {1, _, stderr} = cli(config, ["user", "add", "bob@example.com"], "\n")
      assert stderr =~ "error: empty password"
      assert {1, _, _} = cli(config, ["user", "add", "bob@example.com"])
    end

    test "reports config errors", %{tmp_dir: dir} do
      bad = Path.join(dir, "bad.toml")
      File.write!(bad, "[database]\nadapter = \"oracle\"\n")
      assert {1, _, stderr} = cli(bad, ["user", "list"])
      assert stderr =~ "database.adapter"
    end
  end

  test "hash-password prints a hash usable in a users file" do
    output =
      capture_io("pw\n", fn ->
        capture_io(:stderr, fn -> assert CLI.run(["hash-password"]) == 0 end)
      end)

    assert "{SCRAM-SHA-256}" <> _ = hash = String.trim(output)
    assert Password.verify(hash, "pw") == :ok

    output =
      capture_io("pw\n", fn ->
        capture_io(:stderr, fn -> CLI.run(["hash-password", "sha512-crypt"]) end)
      end)

    assert "$6$" <> _ = String.trim(output)

    assert capture_io(:stderr, fn -> assert CLI.run(["hash-password", "md5"]) == 64 end) =~
             "Usage"
  end
end
