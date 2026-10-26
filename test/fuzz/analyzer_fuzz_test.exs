defmodule Sovite.AnalyzerFuzzTest do
  # Fuzzing of the filter's message analyzer: MIME structure, transfer
  # encodings, encoded words, parameters, charsets, HTML, URLs, and file
  # types. Messages are what spammers write: any of it must be read
  # without crashing, within the limits, into valid UTF-8.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.{Analyzer, Charset, HTML, Magic, MIME, URL}
  alias Sovite.MIME.{EncodedWord, Params, Transfer}
  alias Sovite.Test.Fuzz

  @moduletag :fuzz
  # `mix fuzz` runs each property many times.
  @moduletag timeout: :infinity

  @message """
           From: =?utf-8?B?UGF5UGFs?= <a@example.com>
           Subject: =?iso-8859-1?Q?caf=E9?= =?utf-8?b?w6k=?=
           Content-Type: multipart/mixed; boundary="outer"

           --outer
           Content-Type: multipart/alternative; boundary=inner

           --inner
           Content-Type: text/plain; charset=shift_jis
           Content-Transfer-Encoding: base64

           k/qWe4zq
           --inner
           Content-Type: text/html; charset="utf-8"
           Content-Transfer-Encoding: quoted-printable

           <p style=3D"display:none">x</p><a href=3D"hxxp://a[.]example/=
           x">www.b.example</a>&amp;&#x41;
           --inner--
           --outer
           Content-Type: message/rfc822

           Subject: inner
           Content-Type: application/octet-stream; name*0*=utf-8''%C3%A9; name*1=.exe
           Content-Transfer-Encoding: base64

           TVqQAAMAAAAEAAAA
           --outer--
           """
           |> String.replace("\n", "\r\n")

  @tokens ["\r\n", "--outer", "--inner", "--", "=?", "?=", "=", ";", "\"", "<", ">", "&#"]

  @limits [max_depth: 5, max_parts: 20, max_size: 4096, max_header: 1024, html: [max_tags: 100]]

  property "any message is analyzed, within the limits, into valid UTF-8" do
    check all(message <- Fuzz.input([@message], @tokens), max_runs: Fuzz.runs()) do
      analysis = Fuzz.quick(fn -> Analyzer.analyze(message, @limits) end)

      parts = MIME.flatten(analysis.mime)
      assert length(parts) <= 20 + 1
      assert parts |> Enum.map(&byte_size(&1.body || "")) |> Enum.sum() <= 4096

      for text <- analysis.texts,
          value <- [text.text, text.hidden_text, text.title || ""],
          do: assert(String.valid?(value))

      assert analysis.subject == nil or String.valid?(analysis.subject)
      assert Enum.all?(analysis.urls, &String.valid?(&1.url.host))
      assert Enum.all?(analysis.attachments, &(&1.filename == nil or String.valid?(&1.filename)))
    end
  end

  property "header values, parameters, and transfer encodings decode" do
    seeds = [
      "=?utf-8?B?w6k=?= =?gbk?Q?=D6=D0?=",
      ~s(text/plain; a*0*=utf-8''%E2; a*1*=%82%AC),
      "aGk=\r\n",
      "=E9=\r\n"
    ]

    check all(
            value <- Fuzz.input(seeds, ["=?", "?=", "%", "*", "'", ";", "="]),
            max_runs: Fuzz.runs()
          ) do
      assert String.valid?(Fuzz.quick(fn -> EncodedWord.decode(value) end))
      {type, params} = Fuzz.quick(fn -> Params.parse(value) end)
      assert type == nil or String.valid?(type)
      assert Enum.all?(params, fn {name, v} -> String.valid?(name) and String.valid?(v) end)
      assert {_, _} = Transfer.decode(value, "base64")
      assert {_, _} = Transfer.decode(value, "quoted-printable")
    end
  end

  property "any bytes decode in any charset" do
    labels =
      ~w(utf-8 windows-1252 koi8-r gbk gb18030 big5 shift_jis euc-jp iso-2022-jp euc-kr utf-16 utf-32 utf-7)

    check all(
            label <- member_of(labels),
            data <- Fuzz.bytes(max_length: 300),
            max_runs: Fuzz.runs()
          ) do
      assert {:ok, text} = Fuzz.quick(fn -> Charset.to_utf8(data, label) end)
      assert String.valid?(text)
    end
  end

  property "any HTML, URL, and file is read" do
    seeds = [
      ~s(<a href="http://x.example/?a=1&amp;b">y</a><img src=z alt=w><div style="font-size:0">h</div>),
      "<!-- <script>x</script> --><title>t</title><table><tr><td>a",
      "http://user@0x7f.1/ https://[::1]:80/ www.a[.]b/c?d#e",
      <<"MZ", 0::size(464), 64::32-little, "PE", 0, 0>>
    ]

    check all(
            input <- Fuzz.input(seeds, ["<", ">", "\"", "&", "=", "/", ".", "[", "%"]),
            max_runs: Fuzz.runs()
          ) do
      html = Fuzz.quick(fn -> HTML.parse(input, max_tags: 200) end)
      assert String.valid?(html.text) and String.valid?(html.hidden_text)

      for url <- Fuzz.quick(fn -> URL.extract(input) end), do: assert(String.valid?(url.url))
      assert match?({:ok, _}, URL.parse(input)) or URL.parse(input) == :error
      assert Magic.detect(input) == nil or is_map(Magic.detect(input))
    end
  end
end
