defmodule Sovite.SASL.PasswordTest do
  use ExUnit.Case, async: true

  alias Sovite.SASL.Password

  doctest Sovite.SASL

  test "checks SHA-crypt hashes (reference vectors)" do
    vectors = [
      {"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
       "Hello world!"},
      {"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5", "Hello world!"},
      {"$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
       "Hello world!"},
      {"$6$rounds=10$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.",
       "the minimum number is still observed"},
      {"{SHA512-CRYPT}$6$toolongsaltstri$/orYJZ8x16xCIzQPaoNYVTo9Ox0dlB1t00D4y5ARpn3RvE.mleHmiCuMNyUePsOijsR.xiJAydt8uVttFEppU.",
       "a much longer password here"}
    ]

    for {hash, password} <- vectors do
      assert Password.verify(hash, password) == :ok, hash
      assert Password.verify(hash, password <> "x") == {:error, :mismatch}
    end
  end

  test "hashes and verifies in every scheme" do
    for scheme <- [:scram_sha256, :sha512_crypt, :sha256_crypt] do
      hash = Password.hash("pässword", scheme)
      assert Password.supported?(hash)
      assert Password.verify(hash, "pässword") == :ok
      assert Password.verify(hash, "password") == {:error, :mismatch}
    end

    assert "$5$rounds=6000$" <> _ = Password.hash("x", :sha256_crypt, rounds: 6000)
    assert "{SCRAM-SHA-256}8192," <> _ = Password.hash("x", :scram_sha256, iterations: 8192)
  end

  test "SCRAM hashes match RFC 7677 key derivation" do
    salt = Base.decode64!("W22ZaJ0SNY7soEsUEjb6gQ==")
    keys = Password.scram("pencil", salt, 4096)

    hash =
      "{SCRAM-SHA-256}4096,W22ZaJ0SNY7soEsUEjb6gQ==,#{Base.encode64(keys.stored_key)},#{Base.encode64(keys.server_key)}"

    assert Password.verify(hash, "pencil") == :ok
    assert {:ok, ^keys} = Password.scram_credentials(hash)
  end

  test "plain passwords work but crypt hashes have no SCRAM values" do
    assert Password.verify("{PLAIN}secret", "secret") == :ok
    assert Password.verify("{PLAIN}secret", "Secret") == {:error, :mismatch}
    assert {:ok, %{iterations: 4096}} = Password.scram_credentials("{PLAIN}secret")
    assert Password.scram_credentials(Password.hash("x", :sha512_crypt)) == :error
  end

  test "refuses unknown and malformed hashes" do
    for hash <- [
          "$2y$10$abcdefghijklmnopqrstuuK1uY8H7bH2i9F1HcqYFZ6H7d7z5Gz7S",
          "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
          "{SCRAM-SHA-256}4096,salt,short,short",
          "{SCRAM-SHA-256}x,c2FsdA==",
          "$6$salt",
          "plaintext"
        ] do
      refute Password.supported?(hash), hash
      assert Password.verify(hash, "x") == {:error, :unsupported}
    end
  end

  test "dummy verification always fails" do
    assert Password.dummy_verify("anything") == {:error, :mismatch}
  end
end
