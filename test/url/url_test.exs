defmodule Sovite.URLTest do
  use ExUnit.Case, async: true

  alias Sovite.URL

  doctest URL

  test "finds URLs in text, without the punctuation after them" do
    text = """
    See https://example.com/a?b=1#top, or (www.example.org/path). Also
    ftp://files.example.net/x.zip! and https://example.com/a?b=1#top again.
    Not mailto:someone@example.com or javascript:alert(1).
    """

    assert Enum.map(URL.extract(text), & &1.url) == [
             "https://example.com/a?b=1",
             "http://www.example.org/path",
             "ftp://files.example.net/x.zip"
           ]

    assert [%{flags: [:no_scheme]}] = URL.extract("go to www.example.com")
  end

  test "normalizes hosts, and notes the tricks" do
    assert {:ok, %{host: "example.com", port: 8080, path: "/x", flags: []}} =
             URL.parse("HTTP://EXAMPLE.COM.:8080/x")

    assert {:ok, %{host: "xn--bcher-kva.example", flags: [:idn]}} =
             URL.parse("http://bücher.example/")

    assert {:ok, %{host: "example.com", flags: [:encoded_host]}} =
             URL.parse("http://ex%61mple.com/")

    for numeric <- ["0xC0.0xA8.1.1", "0300.0250.1.1", "3232235777", "192.168.257"] do
      assert {:ok, %{host: host, flags: [:numeric_host]}} = URL.parse("http://#{numeric}/")
      assert host in ["192.168.1.1", "192.168.1.1"]
    end

    assert {:ok, %{host: "192.0.2.1", flags: [:ip]}} = URL.parse("http://192.0.2.1/")
    assert {:ok, %{host: "[2001:db8::1]", flags: [:ip]}} = URL.parse("http://[2001:DB8::1]/")

    assert {:ok, %{user: "paypal.com", host: "evil.example"}} =
             URL.parse("https://paypal.com@evil.example/")

    for bad <- ["mailto:a@b", "http:///path", "http://[::1/", "http://a:99999/", "notaurl"] do
      assert URL.parse(bad) == :error, bad
    end
  end

  test "finds mail addresses" do
    assert URL.addresses("Write to Alice@Example.COM or bob.smith+x@sub.example.org. Not a@b.") ==
             ["Alice@example.com", "bob.smith+x@sub.example.org"]
  end
end
