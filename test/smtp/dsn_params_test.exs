defmodule Sovite.SMTP.DSNParamsTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.SMTP.DSNParams

  doctest DSNParams

  test "NOTIFY" do
    assert DSNParams.parse_notify("never") == {:ok, :never}
    assert DSNParams.parse_notify("DELAY,SUCCESS,FAILURE") == {:ok, [:delay, :success, :failure]}
    assert DSNParams.parse_notify("NEVER,FAILURE") == :error
    assert DSNParams.parse_notify("FAILURE,") == :error
    assert DSNParams.parse_notify("") == :error
    assert DSNParams.encode_notify(:never) == "NEVER"
    assert DSNParams.encode_notify([:failure, :delay]) == "FAILURE,DELAY"
  end

  test "RET and ENVID" do
    assert DSNParams.parse_ret("full") == {:ok, :full}
    assert DSNParams.parse_ret("HDRS") == {:ok, :hdrs}
    assert DSNParams.parse_ret("BODY") == :error
    assert DSNParams.encode_ret(:full) == "FULL"

    assert DSNParams.parse_envid("a+20b") == {:ok, "a b"}
    assert DSNParams.parse_envid(String.duplicate("x", 100)) == {:ok, String.duplicate("x", 100)}
    assert DSNParams.parse_envid(String.duplicate("x", 101)) == :error
    assert DSNParams.parse_envid("a+0Db") == :error
    assert DSNParams.parse_envid("a+C3+BC") == :error
    assert DSNParams.parse_envid("") == :error
    assert DSNParams.encode_envid("a b=c") == "a+20b+3Dc"
  end

  test "ORCPT" do
    assert DSNParams.parse_orcpt("RFC822;a@example.com") == {:ok, {"rfc822", "a@example.com"}}
    assert DSNParams.parse_orcpt("x-local;a+20b") == {:ok, {"x-local", "a b"}}
    assert DSNParams.parse_orcpt("rfc822;") == :error
    assert DSNParams.parse_orcpt("a@example.com") == :error
    assert DSNParams.parse_orcpt("rfc 822;a@example.com") == :error
    assert DSNParams.parse_orcpt("rfc822;a+00@example.com") == :error
    assert DSNParams.parse_orcpt("rfc822;" <> String.duplicate("a", 493)) != :error
    assert DSNParams.parse_orcpt("rfc822;" <> String.duplicate("a", 494)) == :error

    # RFC 6533 utf-8 addresses.
    assert DSNParams.parse_orcpt("utf-8;j\\x{FC}rgen@example.com") ==
             {:ok, {"utf-8", "jürgen@example.com"}}

    assert DSNParams.parse_orcpt("utf-8;jürgen@example.com") == :error

    assert DSNParams.parse_orcpt("utf-8;jürgen@example.com", utf8: true) ==
             {:ok, {"utf-8", "jürgen@example.com"}}

    assert DSNParams.parse_orcpt("utf-8;a+b@example.com") == :error
    assert DSNParams.parse_orcpt("utf-8;a\\x{0}@example.com") == :error
    assert DSNParams.parse_orcpt("utf-8;a\\x{0A}@example.com") == :error
    assert DSNParams.parse_orcpt("utf-8;a\\x{D800}@example.com") == :error
    assert DSNParams.parse_orcpt("utf-8;a\\x{110000}@example.com") == :error
    assert DSNParams.parse_orcpt("utf-8;a\\x{2B@example.com") == :error

    assert DSNParams.encode_orcpt({"utf-8", "jü+r@example.com"}) ==
             "utf-8;j\\x{FC}\\x{2B}r@example.com"

    assert DSNParams.encode_orcpt({"utf-8", "jü+r@example.com"}, smtputf8: true) ==
             "utf-8;jü\\x{2B}r@example.com"

    assert DSNParams.orcpt("a@example.com") == {"rfc822", "a@example.com"}
    assert DSNParams.orcpt("ü@example.com") == {"utf-8", "ü@example.com"}
  end

  property "ORCPT addresses survive encoding" do
    check all(
            local <- string([?a..?z, ?+, ?=, ?\\, ?ü, ?中, ?.], min_length: 1, max_length: 20),
            type <- member_of(["rfc822", "utf-8"]),
            smtputf8 <- boolean()
          ) do
      address = local <> "@example.com"

      if type == "rfc822" and not String.match?(address, ~r/\A[\x20-\x7e]+\z/) do
        :ok
      else
        encoded = DSNParams.encode_orcpt({type, address}, smtputf8: smtputf8)
        assert DSNParams.parse_orcpt(encoded, utf8: smtputf8) == {:ok, {type, address}}
      end
    end
  end
end
