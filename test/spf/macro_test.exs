defmodule Sovite.SPF.MacroTest do
  use ExUnit.Case, async: true

  alias Sovite.SPF.Macro

  doctest Macro

  # RFC 7208 §7.4.
  @context %{
    sender: "strong-bad@email.example.com",
    domain: "email.example.com",
    ip: {192, 0, 2, 3}
  }

  defp expand(string, context \\ @context, kind \\ :domain_spec) do
    {:ok, macro} = Macro.parse(string, kind)
    Macro.expand(macro, context)
  end

  describe "RFC 7208 §7.4 examples" do
    test "IPv4" do
      examples = [
        {"%{s}", "strong-bad@email.example.com"},
        {"%{o}", "email.example.com"},
        {"%{d}", "email.example.com"},
        {"%{d4}", "email.example.com"},
        {"%{d3}", "email.example.com"},
        {"%{d2}", "example.com"},
        {"%{d1}", "com"},
        {"%{dr}", "com.example.email"},
        {"%{d2r}", "example.email"},
        {"%{l}", "strong-bad"},
        {"%{l-}", "strong.bad"},
        {"%{lr}", "strong-bad"},
        {"%{lr-}", "bad.strong"},
        {"%{l1r-}", "strong"},
        {"%{ir}.%{v}._spf.%{d2}", "3.2.0.192.in-addr._spf.example.com"},
        {"%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"},
        {"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}", "bad.strong.lp.3.2.0.192.in-addr._spf.example.com"},
        {"%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", "3.2.0.192.in-addr.strong.lp._spf.example.com"},
        {"%{d2}.trusted-domains.example.net", "example.com.trusted-domains.example.net"}
      ]

      for {macro, expected} <- examples do
        assert {macro, expand(macro, @context, :macro_string)} == {macro, expected}
      end
    end

    test "IPv6" do
      context = %{@context | ip: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0xCB01}}

      assert expand("%{ir}.%{v}._spf.%{d2}", context) ==
               "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"

      assert expand("%{c}", context, :explanation) == "2001:db8::cb01"
    end
  end

  test "uppercase letters are URL-escaped" do
    assert expand("%{S}", @context, :macro_string) == "strong-bad%40email.example.com"

    assert expand("%{L}.%{d}", %{@context | sender: "a b/c@example.com"}) ==
             "a%20b%2Fc.email.example.com"

    assert expand("%{DR}", @context, :macro_string) == "com.example.email"
  end

  test "delimiters" do
    context = %{@context | sender: "a+b=c,d/e_f@example.com"}
    assert expand("%{l+=}", context, :macro_string) == "a.b.c,d/e_f"
    assert expand("%{l,/_}", context, :macro_string) == "a+b=c.d.e.f"
    assert expand("%{l2r+=,/_}", context, :macro_string) == "b.a"
  end

  test "escapes" do
    assert expand("%%%_%-", @context, :explanation) == "% %20"
    assert expand("a%%b.example.com") == "a%b.example.com"
  end

  test "letters that only explanations may use" do
    context = Map.merge(@context, %{receiver: "mx.example.org", now: 1_700_000_000})

    assert expand("%{c} %{r} %{t}", context, :explanation) ==
             "192.0.2.3 mx.example.org 1700000000"

    assert expand("%{r}", @context, :explanation) == "unknown"
    assert expand("%{t}", @context, :explanation) =~ ~r/\A[0-9]+\z/

    for letter <- ~w(c r t C) do
      assert Macro.parse("%{#{letter}}.example.com") == {:error, "macro letter not allowed here"}
    end
  end

  test "h, p, and v" do
    assert expand("%{h}", Map.put(@context, :helo, "mx.example.org"), :macro_string) ==
             "mx.example.org"

    assert expand("%{h}", @context, :macro_string) == "unknown"
    assert expand("%{p}", @context, :macro_string) == "unknown"

    assert expand("%{p}", Map.put(@context, :ptr, "mx.example.com"), :macro_string) ==
             "mx.example.com"

    assert expand("%{v}", @context, :macro_string) == "in-addr"
  end

  test "a sender without a local part is postmaster" do
    assert expand("%{l}@%{o}", %{@context | sender: "example.com"}, :macro_string) ==
             "postmaster@example.com"

    assert expand("%{l}", %{@context | sender: ~s("a@b"@example.com)}, :macro_string) ==
             ~s("a@b")
  end

  test "uses_ptr?/1" do
    {:ok, macro} = Macro.parse("%{p}.example.com")
    assert Macro.uses_ptr?(macro)
    {:ok, macro} = Macro.parse("%{d}.example.com")
    refute Macro.uses_ptr?(macro)
  end

  test "expand_domain/2 drops labels from the left past 253 characters" do
    sender = String.duplicate("abcdefghi.", 30) <> "x@example.com"
    {:ok, macro} = Macro.parse("%{l}.example.com")
    name = Macro.expand_domain(macro, %{@context | sender: sender})

    assert byte_size(name) <= 253
    assert byte_size(name) > 243
    assert String.ends_with?(name, ".x.example.com")
    assert String.starts_with?(name, "abcdefghi.")

    {:ok, macro} = Macro.parse("%{d}")

    assert Macro.expand_domain(macro, %{domain: String.duplicate("a", 300)}) ==
             String.duplicate("a", 300)
  end

  test "rejects invalid macro strings" do
    for bad <- [
          "%{d0}.example.com",
          "%{x}.example.com",
          "%{d",
          "%{}.example.com",
          "%d.example.com",
          "%",
          "100%.example.com",
          "%{d2r!}.example.com"
        ] do
      assert {bad, Macro.parse(bad)} == {bad, {:error, "invalid macro"}}
    end

    assert Macro.parse("a b.example.com") == {:error, "invalid character"}
    assert Macro.parse("café.example.com") == {:error, "invalid character"}
    assert {:ok, _} = Macro.parse("a b", :explanation)
  end

  test "a domain-spec must end like a domain" do
    for good <- ["example.com", "example.com.", "%{d}", "x.%{d}", "foo.com%%", "a.b-c", "a.1b"] do
      assert match?({:ok, _}, Macro.parse(good)), good
    end

    for bad <- [
          "",
          "com",
          "example.com..",
          "example.123",
          "%{d}.",
          "example.-com",
          "example.com-"
        ] do
      assert {bad, Macro.parse(bad)} == {bad, {:error, "invalid domain"}}
    end

    assert {:ok, []} = Macro.parse("", :macro_string)
  end
end
