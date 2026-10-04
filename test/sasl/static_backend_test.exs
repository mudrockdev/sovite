defmodule Sovite.SASL.Backend.StaticTest do
  use ExUnit.Case, async: true

  alias Sovite.SASL.Backend.Static
  alias Sovite.SASL.Password

  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    users = Path.join(dir, "users")

    File.write!(users, """
    # comment
    Alice@Example.com:#{Password.hash("secret")}:1000:1000::/home/alice

    bob@example.com:#{Password.hash("hunter2", :sha512_crypt)}
    """)

    %{users: users, opts: [file: users]}
  end

  test "verifies passwords case-insensitively by user", %{opts: opts} do
    assert Static.verify_password("alice@example.com", "secret", opts) ==
             {:ok, "alice@example.com"}

    assert Static.verify_password("ALICE@example.com", "secret", opts) ==
             {:ok, "alice@example.com"}

    assert Static.verify_password("alice@example.com", "Secret", opts) == {:error, :invalid}
    assert Static.verify_password("carol@example.com", "x", opts) == {:error, :unknown_user}
    assert Static.verify_password("bob@example.com", "hunter2", opts) == {:ok, "bob@example.com"}
  end

  test "returns SCRAM values when the hash has them", %{opts: opts} do
    assert {:ok, %{iterations: 4096}, "alice@example.com"} =
             Static.scram_credentials("Alice@example.com", opts)

    assert Static.scram_credentials("bob@example.com", opts) == {:error, :unavailable}
    assert Static.scram_credentials("carol@example.com", opts) == {:error, :unknown_user}
  end

  test "rereads the file when it changes and keeps the old one if broken",
       %{users: users, opts: opts} do
    assert {:error, :unknown_user} = Static.verify_password("carol@example.com", "pw", opts)
    File.write!(users, "carol@example.com:{PLAIN}pw\n")
    assert {:ok, _} = Static.verify_password("carol@example.com", "pw", opts)

    File.write!(users, "carol@example.com\nbroken line\n")
    assert {:ok, _} = Static.verify_password("carol@example.com", "pw", opts)

    File.rm!(users)
    assert {:ok, _} = Static.verify_password("carol@example.com", "pw", opts)
  end

  test "a missing file is a temporary failure", %{tmp_dir: dir} do
    opts = [file: Path.join(dir, "missing")]
    assert Static.verify_password("a", "b", opts) == {:error, {:temporary, :enoent}}
  end

  test "parse reports the first bad line" do
    assert Static.parse("a:{PLAIN}x\nb\n") == {:error, {:line, 2, :syntax}}
    assert Static.parse("a:$2y$10$x\n") == {:error, {:line, 1, :unsupported_hash}}
    assert {:ok, %{"a" => "{PLAIN}x"}} = Static.parse("A:{PLAIN}x\r\n")
  end
end
