defmodule Sovite.HTMLTest do
  use ExUnit.Case, async: true

  alias Sovite.HTML
  alias Sovite.HTML.Entities

  doctest Entities

  test "visible text, with lines for blocks and one space for runs of white space" do
    html = """
    <!DOCTYPE html><html><head><title> Your   order </title>
    <style>p { color: red }</style><script>alert("x")</script></head>
    <body><h1>Hello</h1><p>Your   <b>order</b>
    has shipped.<br>Thanks</p><!-- a comment -->
    <table><tr><td>a</td><td>b</td></tr></table></body></html>
    """

    parsed = HTML.parse(html)
    assert parsed.title == "Your order"
    assert parsed.text == "Hello\nYour order has shipped.\nThanks\na b"
    assert parsed.hidden_text == ""
    assert parsed.anomalies == []
  end

  test "links and images, with the link's text" do
    parsed =
      HTML.parse(~s(<a href="https://bank.example/login?a=1&amp;b=2">Your <i>bank</i></a>
      <a href='http://other.example'>open <a href=next>nested</a>
      <img src="cid:logo" alt="Logo"><a name="anchor">no href</a>))

    assert parsed.links == [
             %{href: "https://bank.example/login?a=1&b=2", text: "Your bank"},
             %{href: "http://other.example", text: "open"},
             %{href: "next", text: "nested"}
           ]

    assert parsed.images == [%{src: "cid:logo", alt: "Logo"}]
  end

  test "text that styles hide goes apart" do
    parsed =
      HTML.parse(~s(<p>Buy now</p><div style="display:none">cheap viagra <b>pills</b></div>
      <span style="font-size: 0px">hidden</span><span style="font-size:0.9em">small</span>
      <p hidden>attribute</p><p style="color:red; OPACITY: 0">faded</p>))

    assert parsed.text == "Buy now\nsmall"
    assert parsed.hidden_text =~ "cheap viagra pills"
    assert parsed.hidden_text =~ "hidden"
    assert parsed.hidden_text =~ "attribute"
    assert parsed.hidden_text =~ "faded"
  end

  test "character references, as the HTML Standard decodes them" do
    assert Entities.decode("&lt;&gt;&quot;&apos; &nbsp;&copy &notit; &#0; &#x110000; &bogus;") ==
             "<>\"'  © ¬it; � � &bogus;"
  end

  test "broken markup is read anyway" do
    assert HTML.parse("a < b and <3 <").text == "a < b and <3 <"
    assert HTML.parse("<p class='x unterminated>text").text == ""
    assert HTML.parse("<div><p>open").text == "open"
    assert HTML.parse("</nothing>text").text == "text"
    assert HTML.parse("<!-- open comment").text == ""
    assert HTML.parse(<<"caf", 0xE9, "<br>x">>).text == "caf�\nx"
  end

  test "keeps to its limits" do
    assert %{anomalies: [:size_limit], text: "abc"} = HTML.parse("abcdef", max_input: 3)

    many = String.duplicate("<b>x</b>", 100)
    assert %{anomalies: [:tag_limit], tags: 11} = HTML.parse(many, max_tags: 10)

    deep = String.duplicate("<div style='display:none'>", 300) <> "deep"
    assert %{anomalies: [:depth_limit], hidden_text: "deep"} = HTML.parse(deep, max_depth: 256)

    links = String.duplicate("<a href=x>y</a>", 5)
    assert %{anomalies: [:link_limit], links: [_, _]} = HTML.parse(links, max_links: 2)
  end
end
