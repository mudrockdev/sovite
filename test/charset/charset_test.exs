defmodule Sovite.CharsetTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.Charset

  doctest Charset

  # Text encoded with Python's codecs (see the test), so the decoder is
  # checked against another implementation.
  @vectors "test/fixtures/charset/vectors.json" |> File.read!() |> JSON.decode!()

  test "decodes what Python's codecs encoded" do
    for %{"label" => label, "bytes" => hex, "text" => text} <- @vectors do
      assert Charset.to_utf8(Base.decode16!(hex, case: :lower), label) == {:ok, text}, label
    end
  end

  test "labels are those of the Encoding Standard" do
    assert Charset.canonical("ISO_8859-1:1987") == "windows-1252"
    assert Charset.canonical("US-ASCII") == "windows-1252"
    assert Charset.canonical("gb_2312-80") == "gbk"
    assert Charset.canonical("Windows-31J") == "shift_jis"
    assert Charset.canonical("ks_c_5601-1987") == "euc-kr"
    assert Charset.canonical("latin5") == "windows-1254"
    assert Charset.canonical("x-unknown") == nil
    assert Charset.to_utf8("x", "ebcdic") == {:error, :unknown_charset}
  end

  test "bytes that are not valid become U+FFFD" do
    assert Charset.to_utf8(<<"a", 0xFF, "b">>, "utf-8") == {:ok, "a�b"}
    # 0x81 has no character in windows-1252.
    assert Charset.to_utf8(<<0x81>>, "windows-1252") == {:ok, "�"}
    # A lead byte without its trail byte, and an ASCII trail byte kept.
    assert Charset.to_utf8(<<0x82>>, "shift_jis") == {:ok, "�"}
    assert Charset.to_utf8(<<0x82, "A">>, "shift_jis") == {:ok, "�A"}
    # A lone surrogate, an odd byte, and a code point past Unicode.
    assert Charset.to_utf8(<<0xD8, 0x00, 0x00, 0x41>>, "utf-16be") == {:ok, "�A"}
    assert Charset.to_utf8(<<0, 0x41, 0x42>>, "utf-16be") == {:ok, "A�"}
    assert Charset.to_utf8(<<0x00, 0x11, 0x00, 0x00>>, "utf-32be") == {:ok, "�"}
    # A byte order mark is not part of the text.
    assert Charset.to_utf8(<<0xEF, 0xBB, 0xBF, "x">>, "utf-8") == {:ok, "x"}
  end

  test "UTF-7 hides words in base64" do
    assert Charset.to_utf8("+AHYAaQBhAGcAcgBh-", "utf-7") == {:ok, "viagra"}
    assert Charset.to_utf8("1 +- 1", "utf-7") == {:ok, "1 + 1"}
  end

  property "any bytes in any charset decode to valid UTF-8" do
    labels = ~w(utf-8 windows-1252 iso-8859-5 koi8-r gbk gb18030 big5 shift_jis euc-jp
                iso-2022-jp euc-kr utf-16 utf-16le utf-32 utf-7)

    check all(label <- member_of(labels), data <- binary(max_length: 64)) do
      assert {:ok, text} = Charset.to_utf8(data, label)
      assert String.valid?(text)
    end
  end
end
