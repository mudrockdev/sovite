defmodule Sovite.Core.SenderCheckTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.SenderCheck

  test "a login without patterns may only send as itself" do
    assert SenderCheck.allowed?("alice@example.com", "Alice@Example.com", [])
    refute SenderCheck.allowed?("alice@example.com", "bob@example.com", [])
    refute SenderCheck.allowed?("alice", "alice@example.com", [])
  end

  test "patterns allow addresses, domains, or anything" do
    patterns = ["sales@example.com", "@example.org"]
    assert SenderCheck.allowed?("alice", "SALES@example.com", patterns)
    assert SenderCheck.allowed?("alice", "anyone@Example.org", patterns)
    refute SenderCheck.allowed?("alice", "anyone@sub.example.org", patterns)
    refute SenderCheck.allowed?("alice", "alice@example.com", patterns)
    assert SenderCheck.allowed?("alice@example.com", "alice@example.com", patterns)
    assert SenderCheck.allowed?("alice", "x@y.test", ["*"])
  end

  test "the null sender is always allowed" do
    assert SenderCheck.allowed?("alice", "", [])
  end

  test "validates patterns" do
    assert SenderCheck.valid_pattern?("*")
    assert SenderCheck.valid_pattern?("@example.com")
    assert SenderCheck.valid_pattern?("a@example.com")
    refute SenderCheck.valid_pattern?("@")
    refute SenderCheck.valid_pattern?("example.com")
    refute SenderCheck.valid_pattern?("a b@example.com")
  end
end
