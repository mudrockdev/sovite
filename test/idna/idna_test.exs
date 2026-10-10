defmodule Sovite.IDNATest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.IDNA
  alias Sovite.IDNA.{CodePoints, Punycode}

  doctest IDNA
  doctest Punycode
  doctest CodePoints

  describe "Punycode" do
    # RFC 3492 §7.1, and some of our own.
    @samples [
      {"ليهمابتكلموشعربي؟", "egbpdaj6bu4bxfgehfvwxn"},
      {"他们为什么不说中文", "ihqwcrb4cv8a8dqg056pqjye"},
      {"他們爲什麽不說中文", "ihqwctvzc91f659drss3x8bo0yb"},
      {"Pročprostěnemluvíčesky", "Proprostnemluvesky-uyb24dma41a"},
      {"למההםפשוטלאמדבריםעברית", "4dbcagdahymbxekheh6e0a7fei0b"},
      {"почемужеонинеговорятпорусски", "b1abfaaepdrnnbgefbadotcwatmq2g4l"},
      {"PorquénopuedensimplementehablarenEspañol",
       "PorqunopuedensimplementehablarenEspaol-fmd56a"},
      {"TạisaohọkhôngthểchỉnóitiếngViệt", "TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g"},
      {"3年B組金八先生", "3B-ww4c5e180e575a65lsy2b"},
      {"安室奈美恵-with-SUPER-MONKEYS", "-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n"},
      {"Hello-Another-Way-それぞれの場所", "Hello-Another-Way--fc4qua05auwb3674vfr0b"},
      {"ひとつ屋根の下2", "2-u9tlzr9756bt3uc0v"},
      {"MajiでKoiする5秒前", "MajiKoi5-783gue6qz075azm5e"},
      {"パフィーdeルンバ", "de-jg4avhby1noc0d"},
      {"そのスピードで", "d9juau41awczczp"},
      {"-> $1.00 <-", "-> $1.00 <--"},
      {"bücher", "bcher-kva"},
      {"", ""}
    ]

    test "encodes and decodes the RFC 3492 samples" do
      for {unicode, encoded} <- @samples do
        assert Punycode.encode(unicode) == {:ok, encoded}, unicode
        assert Punycode.decode(encoded) == {:ok, unicode}, encoded
      end
    end

    test "invalid input" do
      assert Punycode.encode(<<0xFF>>) == :error
      assert Punycode.encode(String.duplicate("ü", 300)) == :error
      assert Punycode.encode(:atom) == :error
      assert Punycode.decode("ü") == :error
      assert Punycode.decode("a-?") == :error
      assert Punycode.decode("99999999999") == :error
      assert Punycode.decode(String.duplicate("a", 300)) == :error
      assert Punycode.decode(:atom) == :error
    end

    property "decoding reverses encoding" do
      check all(string <- string(:printable, max_length: 40)) do
        {:ok, encoded} = Punycode.encode(string)
        assert Punycode.decode(encoded) == {:ok, string}
      end
    end

    property "decoding never raises" do
      check all(input <- binary(max_length: 80)) do
        assert match?({:ok, _}, Punycode.decode(input)) or Punycode.decode(input) == :error
      end
    end
  end

  describe "to_ascii and to_unicode" do
    test "convert between U-labels and A-labels" do
      for {unicode, ascii} <- [
            {"münchen.example", "xn--mnchen-3ya.example"},
            {"пример.рф", "xn--e1afmkfd.xn--p1ai"},
            {"例え.テスト", "xn--r8jz45g.xn--zckzah"},
            {"مثال.إختبار", "xn--mgbh0fb.xn--kgbechtv"},
            {"faß.de", "xn--fa-hia.de"},
            {"l·l.cat", "xn--ll-0ea.cat"},
            {"x.אב", "x.xn--4dbc"},
            {"क्‍ष.in", "xn--11b2ezcw70k.in"},
            {"example.com", "example.com"}
          ] do
        assert IDNA.to_ascii(unicode) == {:ok, ascii}, unicode
        assert IDNA.to_unicode(ascii) == {:ok, unicode}, ascii
      end
    end

    test "map what people type" do
      assert IDNA.to_ascii("MÜNCHEN.Example") == {:ok, "xn--mnchen-3ya.example"}
      assert IDNA.to_ascii("ẞ.de") == {:ok, "xn--zca.de"}
      assert IDNA.to_ascii("日本。jp") == {:ok, "xn--wgv71a.jp"}
      assert IDNA.to_ascii("ü.de") == {:ok, "xn--tda.de"}
      assert IDNA.to_ascii("XN--BCHER-KVA.example") == {:ok, "xn--bcher-kva.example"}
    end

    test "refuse invalid names" do
      for {name, error} <- [
            {"", :empty_label},
            {"a..b", :empty_label},
            {"a.", :empty_label},
            {"-ab.example", :invalid_ldh},
            {"ab_c.example", :invalid_ldh},
            {String.duplicate("a", 64) <> ".example", :too_long},
            {String.duplicate("ü", 60) <> ".example", :too_long},
            {Enum.map_join(1..60, ".", fn _ -> "abcd" end), :too_long},
            {"xn--zz.example", :invalid_a_label},
            {"xn--abc.example", :invalid_a_label},
            {"xn--bcher-kva-.example", :invalid_a_label},
            {"☃.net", :disallowed},
            {"a b.example", :disallowed},
            {"a​b.example", :disallowed},
            {"\u1100.kr", :disallowed},
            {"ü-.example", :hyphen},
            {"-ü.example", :hyphen},
            {"üb--x.example", :hyphen},
            {"́a.example", :leading_combining_mark},
            {"a·b.cat", :context},
            {"a‍b.example", :context},
            {"͵b.gr", :context},
            {"a׳.il", :context},
            {"a・b.jp", :context},
            {"٠۰.example", :context},
            {"1א.example", :bidi},
            {"אa.example", :bidi},
            {"a.1א", :bidi},
            {"a٠.example", :bidi}
          ] do
        assert IDNA.to_ascii(name) == {:error, error}, inspect(name)
        assert IDNA.to_unicode(name) == {:error, error}
        refute IDNA.valid?(name)
      end

      assert IDNA.to_ascii(<<0xFF>>) == {:error, :disallowed}
      assert IDNA.to_ascii(:atom) == {:error, :invalid_ldh}
      assert IDNA.to_unicode(:atom) == {:error, :invalid_ldh}
    end

    test "contextual rules that pass" do
      assert {:ok, _} = IDNA.to_ascii("͵α.gr")
      assert {:ok, _} = IDNA.to_ascii("א׳.il")
      assert {:ok, _} = IDNA.to_ascii("カ・ナ.jp")
      assert {:ok, _} = IDNA.to_ascii("\u0628\u0661\u0662.example")
      assert {:ok, _} = IDNA.to_ascii("۱۲.example")
    end

    test "which names are internationalized" do
      assert IDNA.international?("bücher.example")
      assert IDNA.international?("XN--bcher-kva.example")
      refute IDNA.international?("example.com")
    end

    property "never raises, and A-labels convert back" do
      check all(name <- string(:printable, max_length: 30)) do
        case IDNA.to_ascii(name) do
          {:ok, ascii} ->
            {:ok, unicode} = IDNA.to_unicode(ascii)
            assert IDNA.to_ascii(unicode) == {:ok, ascii}

          {:error, _} ->
            :ok
        end
      end
    end
  end

  describe "code points" do
    test "derived properties" do
      assert CodePoints.property(?a) == :pvalid
      assert CodePoints.property(?-) == :pvalid
      assert CodePoints.property(?.) == :disallowed
      assert CodePoints.property(0x00E9) == :pvalid
      assert CodePoints.property(0x00C9) == :disallowed
      assert CodePoints.property(0x00DF) == :pvalid
      assert CodePoints.property(0x00B7) == :contexto
      assert CodePoints.property(0x0640) == :disallowed
      assert CodePoints.property(0x0378) == :unassigned
      assert CodePoints.property(0xFDD0) == :disallowed
      assert CodePoints.property(0xFE0F) == :disallowed
      assert CodePoints.property(0x20D0) == :disallowed
      assert CodePoints.property(0x2163) == :disallowed
    end
  end
end
