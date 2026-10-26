defmodule Sovite.RulesTest do
  use ExUnit.Case, async: true

  alias Sovite.{Analyzer, Rules}
  alias Sovite.Rules.{Expression, Maps, Pattern}

  doctest Expression
  doctest Maps
  doctest Pattern

  @message """
           From: Shop <shop@spam.example>
           To: you@example.com
           Subject: =?utf-8?Q?CHEAP_PILLS_TODAY_ONLY?=
           Content-Type: multipart/mixed; boundary=b

           --b
           Content-Type: text/html

           <p>Buy at <a href="http://www.spam.example/buy">our shop</a></p>
           <div style="display:none">lorem ipsum</div>
           --b
           Content-Type: application/octet-stream; name=invoice.pdf

           MZ
           --b--
           """
           |> String.replace("\n", "\r\n")

  defp rules!(toml, opts \\ []) do
    {:ok, rules} = Rules.compile([{"test.toml", Toml.decode!(toml)}], opts)
    rules
  end

  defp scan(rules, opts \\ []) do
    Rules.scan(rules, Analyzer.analyze(@message), Keyword.put_new(opts, :raw, @message))
  end

  defp names(result), do: Enum.map(result.symbols, & &1.name)

  test "regular expressions on headers, text, URLs, attachments, and the envelope" do
    rules =
      rules!("""
      [[symbol]]
      name = "SUBJECT_CAPS"
      score = 2.0
      match = "subject"
      regex = '\\A[^a-z]{12,}\\z'

      [[symbol]]
      name = "FROM_SHOP"
      score = 0.5
      match = "header:from"
      regex = "shop@"
      flags = "i"

      [[symbol]]
      name = "HIDDEN"
      score = 1.0
      match = "hidden_text"
      regex = "lorem"

      [[symbol]]
      name = "BUY"
      score = 1.0
      match = "text"
      regex = "buy"
      flags = "i"

      [[symbol]]
      name = "EXE"
      score = 3.0
      match = "attachment_type"
      regex = "msdownload|dosexec"

      [[symbol]]
      name = "HELO_IP"
      score = 1.0
      match = "helo"
      regex = '\\A\\['

      [[symbol]]
      name = "NOPE"
      score = 9.0
      match = "body"
      regex = "nothing like this"
      """)

    result = scan(rules, envelope: %{helo: "[192.0.2.1]"})
    assert names(result) == ~w(SUBJECT_CAPS FROM_SHOP HIDDEN BUY EXE HELO_IP)
    assert result.score == 8.5
    assert %{options: ["CHEAP PILLS TODAY ONLY"]} = hd(result.symbols)
  end

  test "every target has the values it names" do
    targets =
      ~w(header:to raw_header:subject mime_header:content-type headers subject text hidden_text
         html body url url_host address attachment_name attachment_type attachment_hash ip
         hostname helo from from_domain rcpt rcpt_domain user)

    toml =
      targets
      |> Enum.with_index()
      |> Enum.map_join("\n", fn {target, index} ->
        ~s([[symbol]]\nname = "T#{index}"\nmatch = "#{target}"\nregex = '\\A[\\s\\S]{0,40}'\n)
      end)

    envelope = %{
      ip: "192.0.2.1",
      hostname: "client.example",
      helo: "client",
      from: "shop@Spam.Example",
      rcpts: ["you@example.com", "me@Example.com"],
      user: "shop"
    }

    found =
      Map.new(scan(rules!(toml), envelope: envelope).symbols, fn symbol ->
        {Enum.at(targets, String.to_integer(String.trim_leading(symbol.name, "T"))),
         symbol.options}
      end)

    assert found["header:to"] == ["you@example.com"]
    assert found["raw_header:subject"] == ["=?utf-8?Q?CHEAP_PILLS_TODAY_ONLY?="]
    assert found["mime_header:content-type"] |> length() == 3
    assert [<<"From: Shop", _::binary>>] = found["headers"]
    assert found["subject"] == ["CHEAP PILLS TODAY ONLY"]
    assert [<<"Buy at our shop", _::binary>>] = found["text"]
    assert found["hidden_text"] == ["lorem ipsum"]
    assert [<<"<p>Buy at", _::binary>>] = found["html"]
    assert [<<"--b", _::binary>>] = found["body"]
    assert found["url"] == ["http://www.spam.example/buy"]
    assert found["url_host"] == ["www.spam.example"]
    assert found["attachment_name"] == ["invoice.pdf"]
    assert found["attachment_type"] == ["application/x-dosexec"]
    assert [<<_::binary-40>>] = found["attachment_hash"]
    assert found["ip"] == ["192.0.2.1"]
    assert found["hostname"] == ["client.example"]
    assert found["helo"] == ["client"]
    assert found["from"] == ["shop@Spam.Example"]
    assert found["from_domain"] == ["spam.example"]
    assert found["rcpt"] == ["you@example.com", "me@Example.com"]
    assert found["rcpt_domain"] == ["example.com"]
    assert found["user"] == ["shop"]
    refute Map.has_key?(found, "address")

    # Without the raw message, no body; without an envelope, none of it.
    result = Rules.scan(rules!(toml), Analyzer.analyze(@message))

    names =
      Enum.map(
        result.symbols,
        &Enum.at(targets, String.to_integer(String.trim_leading(&1.name, "T")))
      )

    refute "body" in names
    refute "ip" in names
    refute "from_domain" in names
  end

  test "maps, inline and loaded from files" do
    rules =
      rules!("""
      [[map]]
      name = "bad_domains"
      type = "domain"
      entries = ["spam.example"]

      [[map]]
      name = "networks"
      type = "ip"
      file = "/etc/sovite/maps/networks.txt"

      [[symbol]]
      name = "URL_BAD"
      score = 5.0
      match = "url_host"
      map = "bad_domains"

      [[symbol]]
      name = "IP_LISTED"
      score = 2.0
      match = "ip"
      map = "networks"
      """)

    assert Rules.file_maps(rules) == %{"networks" => {:ip, "/etc/sovite/maps/networks.txt"}}
    assert names(scan(rules, envelope: %{ip: "192.0.2.7"})) == ["URL_BAD"]

    {networks, []} = Maps.parse(:ip, "192.0.2.0/24\n# comment\n2001:db8::/32 listed\n")

    result = scan(rules, envelope: %{ip: "192.0.2.7"}, maps: %{"networks" => networks})
    assert names(result) == ["URL_BAD", "IP_LISTED"]
    assert List.last(result.symbols).options == ["192.0.2.7"]
  end

  test "symbols found by code get the scores of the rule files" do
    rules =
      rules!("""
      [[symbol]]
      name = "R_SPF_FAIL"
      score = 3.0
      group = "spf"

      [[symbol]]
      name = "R_SPF_PASS"
      score = -1.0
      enabled = false
      """)

    result = scan(rules, symbols: [{"R_SPF_FAIL", ["-all"]}, "R_SPF_PASS", "OTHER"])

    assert [%{name: "R_SPF_FAIL", score: 3.0, group: "spf", options: ["-all"]}, other] =
             result.symbols

    assert %{name: "OTHER", score: +0.0} = other
    assert result.score == 3.0
  end

  test "composites, and the scores they take out" do
    base = """
    [[symbol]]
    name = "A"
    score = 1.0

    [[symbol]]
    name = "B"
    score = 2.0
    group = "g"

    [[symbol]]
    name = "C"
    score = 4.0
    """

    composite = fn policy ->
      rules!(
        base <>
          """
          [[composite]]
          name = "A_AND_B"
          expression = "A & g:g & !C"
          score = 10.0
          #{policy}

          [[composite]]
          name = "OUTER"
          expression = "A_AND_B | C"
          score = 0.5
          policy = "leave"
          """
      )
    end

    result = scan(composite.(""), symbols: ["A", "B"])
    assert names(result) == ["B", "A_AND_B", "OUTER"]
    assert result.score == 12.5

    result = scan(composite.(~s(policy = "remove_weight")), symbols: ["A", "B"])
    assert names(result) == ["A", "B", "A_AND_B", "OUTER"]
    assert result.score == 12.5

    result = scan(composite.(~s(policy = "leave")), symbols: ["A", "B", "C"])
    assert names(result) == ["A", "B", "C", "OUTER"]
  end

  test "groups limit what they add and take away" do
    rules =
      rules!("""
      [[group]]
      name = "g"
      max_score = 3.0
      min_score = -1.0

      [[symbol]]
      name = "A"
      score = 2.0
      group = "g"

      [[symbol]]
      name = "B"
      score = 2.0
      group = "g"

      [[symbol]]
      name = "C"
      score = -5.0
      group = "g"

      [[symbol]]
      name = "D"
      score = 1.0
      """)

    assert scan(rules, symbols: ~w(A B D)).score == 4.0
    assert scan(rules, symbols: ~w(A B C D)).score == 3.0
  end

  test "conditions, over flags and symbols found before" do
    rules =
      rules!(
        """
        [[symbol]]
        name = "AUTH"
        score = -1.0

        [[symbol]]
        name = "CAPS"
        score = 2.0
        match = "subject"
        regex = "CHEAP"
        condition = "!is:authenticated & !AUTH"
        """,
        flags: ["authenticated"]
      )

    assert names(scan(rules)) == ["CAPS"]
    assert names(scan(rules, flags: ["authenticated"])) == []
    assert names(scan(rules, symbols: ["AUTH"])) == ["AUTH"]
  end

  test "later files change and disable the rules of earlier ones" do
    defaults =
      Toml.decode!("""
      [[symbol]]
      name = "CAPS"
      score = 2.0
      match = "subject"
      regex = "CHEAP"
      description = "Capitals"

      [[symbol]]
      name = "OFF"
      score = 1.0
      match = "subject"
      regex = "PILLS"
      """)

    local =
      Toml.decode!("""
      [[symbol]]
      name = "CAPS"
      score = 7.0

      [[symbol]]
      name = "OFF"
      enabled = false
      """)

    {:ok, rules} = Rules.compile([{"defaults.toml", defaults}, {"local.toml", local}])

    assert [%{name: "CAPS", score: 7.0, description: "Capitals"}] = scan(rules).symbols

    assert [%{name: "CAPS", score: 7.0}, %{name: "OFF", score: 1.0}] = Rules.symbols(rules)
  end

  test "errors say where they are" do
    toml = """
    unknown = 1

    [[symbol]]
    name = "A"
    match = "subjekt"
    regex = "x"

    [[symbol]]
    name = "B"
    match = "text"
    regex = "("
    extra = true

    [[symbol]]
    name = "B"

    [[symbol]]
    name = "C"
    match = "url_host"
    map = "missing"

    [[map]]
    name = "m"
    type = "ip"
    entries = ["192.0.2.1", "300.1.1.1"]

    [[composite]]
    name = "X"
    expression = "Y & !NOBODY & g:none & is:weird"

    [[composite]]
    name = "Y"
    expression = "X |"

    [[symbol]]
    name = "D"
    score = "high"
    """

    {:error, errors} = Rules.compile([{"t.toml", Toml.decode!(toml)}], flags: ["authenticated"])
    paths = Map.new(errors, fn {path, reason} -> {Enum.join(path, "."), reason} end)

    assert paths["t.toml.unknown"] =~ "unknown key"
    assert paths["t.toml.symbol.[0].match"] =~ "must be one of"
    assert paths["t.toml.symbol.[1].regex"] =~ "missing closing parenthesis"
    assert paths["t.toml.symbol.[1].extra"] == "unknown key"
    assert paths["t.toml.symbol.[2].name"] == "B is already defined"
    assert paths["t.toml.map.[0].entries.[1]"] =~ "not an IP address"
    assert paths["t.toml.composite.[1].expression"] =~ "unexpected end"
    assert paths["t.toml.symbol.[4].score"] == "must be a number"

    # References are checked once every entry is valid.
    {:error, errors} =
      Rules.compile(
        [
          {"t.toml",
           Toml.decode!("""
           [[symbol]]
           name = "C"
           match = "url_host"
           map = "missing"

           [[composite]]
           name = "X"
           expression = "Y & !NOBODY & g:none & is:weird"

           [[composite]]
           name = "Y"
           expression = "X"
           """)}
        ],
        flags: ["authenticated"]
      )

    reasons = Enum.map(errors, &elem(&1, 1))
    assert "no map is named missing" in reasons
    assert "no symbol is named NOBODY" in reasons
    assert "no group is named none" in reasons
    assert "unknown flag weird (authenticated)" in reasons
    assert Enum.any?(reasons, &(&1 =~ "depends on itself"))
  end

  test "a pattern that backtracks without bound gives up" do
    rules =
      rules!("""
      [[symbol]]
      name = "EVIL"
      score = 1.0
      match = "helo"
      regex = '\\A(a+)+\\z'
      """)

    helo = String.duplicate("a", 40) <> "!"
    result = scan(rules, envelope: %{helo: helo})
    assert result.symbols == []
    assert result.anomalies == [{:match_limit, "EVIL"}]
  end

  test "rules stop at the time limit" do
    rules =
      rules!("""
      [[symbol]]
      name = "A"
      score = 1.0
      match = "text"
      regex = "buy"
      """)

    assert %{symbols: [], anomalies: [:time_limit]} = scan(rules, timeout: -1)
  end

  test "maps of every type" do
    {map, [{2, reason}]} =
      Maps.parse(:address, "Shop@Spam.Example\nnot an address\n@evil.example")

    assert reason =~ "not a mail address"
    assert Maps.member?(map, "shop@spam.example")
    assert Maps.member?(map, "anyone@EVIL.example")
    refute Maps.member?(map, "other@spam.example")
    assert Maps.size(map) == 2

    {map, [{1, _}, {2, _}]} =
      Maps.new(:ip, ["192.0.2.1/24", "2001:db8::/129", "10.0.0.0/8", "::1"])

    assert Maps.member?(map, "10.1.2.3")
    assert Maps.member?(map, "::ffff:10.1.2.3")
    assert Maps.member?(map, "::1")
    refute Maps.member?(map, "11.0.0.1")
    refute Maps.member?(map, "not an ip")

    {map, []} = Maps.new(:domain, ["*.bücher.example", "Example.ORG."])
    assert Maps.member?(map, "shop.xn--bcher-kva.example")
    assert Maps.member?(map, "user@sub.example.org")
    refute Maps.member?(map, "example.com")

    {map, []} = Maps.new(:string, ["E3B0C442"])
    assert Maps.member?(map, "e3b0c442")
  end

  test "expressions" do
    assert {:ok, {:or, [{:and, [{:symbol, "A"}, {:not, {:group, "g"}}]}, {:flag, "x"}]}} =
             Expression.parse("A & !g:g | is:x")

    assert {:ok, {:group_positive, "g"}} = Expression.parse("(g+:g)")
    assert {:error, "missing )"} = Expression.parse("(A")
    assert {:error, "unexpected \"&\""} = Expression.parse("A & & B")
    assert {:error, "unexpected B"} = Expression.parse("A B")
    assert {:error, "unexpected \"@\""} = Expression.parse("A@")
    assert {:error, _} = Expression.parse(String.duplicate("(", 100) <> "A")
    assert Expression.positive_symbols(elem(Expression.parse("A & !B & (C | g:x)"), 1)) == ~w(A C)
  end

  test "patterns" do
    assert {:error, "unknown flag \"q\""} = Pattern.compile("a", "q")
    assert {:ok, pattern} = Pattern.compile("^b.c$", "ms")
    assert {:match, "b\nc"} = Pattern.run(pattern, "a\nb\nc")
    assert Pattern.source(pattern) == "^b.c$"
  end
end
