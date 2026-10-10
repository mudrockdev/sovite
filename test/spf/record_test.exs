defmodule Sovite.SPF.RecordTest do
  use ExUnit.Case, async: true

  alias Sovite.SPF.Record

  doctest Record

  @d [{:macro, :d, nil, false, [], false}]

  defp parse!(record) do
    {:ok, terms} = Record.parse(record)
    terms
  end

  test "spf?/1 needs v=spf1 followed by a space or nothing" do
    assert Record.spf?("v=spf1")
    assert Record.spf?("V=SPF1 -all")
    refute Record.spf?("v=spf1\t-all")
    refute Record.spf?("v=spf2.0/pra -all")
    refute Record.spf?(" v=spf1 -all")
    refute Record.spf?("spf1")
  end

  test "qualifiers" do
    assert parse!("v=spf1 all +all -all ~all ?all") == [
             {:pass, :all, "all"},
             {:pass, :all, "+all"},
             {:fail, :all, "-all"},
             {:softfail, :all, "~all"},
             {:neutral, :all, "?all"}
           ]
  end

  test "mechanisms" do
    assert parse!("v=spf1 include:_spf.example.net exists:%{d} ptr ptr:example.com") == [
             {:pass, {:include, ["_spf.example.net"]}, "include:_spf.example.net"},
             {:pass, {:exists, @d}, "exists:%{d}"},
             {:pass, {:ptr, nil}, "ptr"},
             {:pass, {:ptr, ["example.com"]}, "ptr:example.com"}
           ]

    assert parse!("v=spf1 ip4:192.0.2.1 ip4:192.0.2.0/24 ip6:2001:db8::/32 ip6:::1") == [
             {:pass, {:ip4, {192, 0, 2, 1}, 32}, "ip4:192.0.2.1"},
             {:pass, {:ip4, {192, 0, 2, 0}, 24}, "ip4:192.0.2.0/24"},
             {:pass, {:ip6, {0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32}, "ip6:2001:db8::/32"},
             {:pass, {:ip6, {0, 0, 0, 0, 0, 0, 0, 1}, 128}, "ip6:::1"}
           ]
  end

  test "dual CIDR lengths for a and mx" do
    assert parse!("v=spf1 a mx a/24 mx//64 a:foo.example.com/24//64 mx:%{d}/0//0") == [
             {:pass, {:a, nil, {32, 128}}, "a"},
             {:pass, {:mx, nil, {32, 128}}, "mx"},
             {:pass, {:a, nil, {24, 128}}, "a/24"},
             {:pass, {:mx, nil, {32, 64}}, "mx//64"},
             {:pass, {:a, ["foo.example.com"], {24, 64}}, "a:foo.example.com/24//64"},
             {:pass, {:mx, @d, {0, 0}}, "mx:%{d}/0//0"}
           ]
  end

  test "names are case-insensitive" do
    assert parse!("v=spf1 IP4:192.0.2.1 A:Example.COM Include:x.example -ALL Redirect=x.example") ==
             [
               {:pass, {:ip4, {192, 0, 2, 1}, 32}, "IP4:192.0.2.1"},
               {:pass, {:a, ["Example.COM"], {32, 128}}, "A:Example.COM"},
               {:pass, {:include, ["x.example"]}, "Include:x.example"},
               {:fail, :all, "-ALL"},
               {:redirect, ["x.example"]}
             ]
  end

  test "modifiers" do
    assert parse!("v=spf1 exp=explain.%{d} -all redirect=_spf.example.com") == [
             {:exp, ["explain." | @d]},
             {:fail, :all, "-all"},
             {:redirect, ["_spf.example.com"]}
           ]
  end

  test "unknown modifiers are checked and ignored" do
    assert parse!("v=spf1 foo=bar x-y_z.1=%{c}%{d} empty= -all") == [{:fail, :all, "-all"}]
    assert Record.parse("v=spf1 foo=%{x} -all") == {:error, ~s(invalid term "foo=%{x}")}
  end

  test "extra spaces between terms" do
    assert parse!("v=spf1   a    -all  ") == [
             {:pass, {:a, nil, {32, 128}}, "a"},
             {:fail, :all, "-all"}
           ]

    assert parse!("v=spf1") == []
  end

  test "duplicate redirect or exp" do
    assert Record.parse("v=spf1 redirect=a.example redirect=b.example") ==
             {:error, "duplicate redirect modifier"}

    assert Record.parse("v=spf1 exp=a.example exp=b.example -all") ==
             {:error, "duplicate exp modifier"}
  end

  test "syntax errors" do
    assert Record.parse("v=spf1 foo -all") == {:error, ~s(unknown mechanism "foo")}
    assert Record.parse("v=spf1 -all foo:bar") == {:error, ~s(unknown mechanism "foo:bar")}
    assert Record.parse("spf1 -all") == {:error, "not an SPF record"}

    for term <- [
          "all:foo",
          "all/24",
          "include",
          "include:",
          "include:com",
          "exists",
          "a:",
          "a/",
          "a/33",
          "a//129",
          "a/024",
          "a/24/64",
          "a:example.com/",
          "a:1.2.3.4",
          "mx:example",
          "ptr:",
          "ip4",
          "ip4:",
          "ip4:192.0.2",
          "ip4:192.0.2.1/",
          "ip4:192.0.2.1/33",
          "ip4:192.0.2.1/08",
          "ip4:192.0.2.1/24/24",
          "ip4:2001:db8::1",
          "ip6:192.0.2.1",
          "ip6:2001:db8::/129",
          "a:%{c}.example.com",
          "exists:%{d0}.example.com",
          "exists:100%.example.com",
          "redirect=",
          "redirect=%{t}",
          "exp=foo",
          "-",
          "+",
          "=foo",
          "a:fooé.example.com"
        ] do
      assert {term, Record.parse("v=spf1 " <> term)} ==
               {term, {:error, "invalid term #{inspect(term)}"}}
    end
  end
end
