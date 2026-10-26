defmodule Sovite.MIMETest do
  use ExUnit.Case, async: true

  alias Sovite.MIME
  alias Sovite.MIME.{EncodedWord, Params, Transfer}

  doctest Transfer
  doctest EncodedWord
  doctest Params

  defp crlf(text), do: String.replace(text, "\n", "\r\n")

  @mixed String.replace(
           """
           From: a@example.com
           Subject: =?utf-8?B?SGVsbG8=?=
           MIME-Version: 1.0
           Content-Type: multipart/mixed; boundary="outer"

           This is the preamble.
           --outer
           Content-Type: multipart/alternative; boundary=inner

           --inner
           Content-Type: text/plain; charset=iso-8859-1
           Content-Transfer-Encoding: quoted-printable

           Caf=E9 au lait
           --inner
           Content-Type: text/html; charset=utf-8

           <p>Café</p>
           --inner--
           --outer
           Content-Type: application/pdf
           Content-Disposition: attachment; filename*=utf-8''r%C3%A9sum%C3%A9.pdf
           Content-Transfer-Encoding: base64

           JVBERi0x
           LjQK
           --outer
           Content-Type: message/rfc822

           Subject: inner
           Content-Type: text/plain; charset="windows-1251"

           \xCF\xF0\xE8\xE2\xE5\xF2
           --outer--
           Epilogue.
           """,
           "\n",
           "\r\n"
         )

  test "parses nested multiparts, attachments, and messages" do
    root = MIME.parse(@mixed)
    assert root.type == "multipart/mixed"
    assert MIME.header(root, "subject") == "Hello"
    assert MIME.anomalies(root) == []

    [alternative, pdf, message] = root.parts
    assert alternative.type == "multipart/alternative"
    assert [plain, html] = alternative.parts
    assert plain.text == "Café au lait"
    assert html.text == "<p>Café</p>"
    refute MIME.attachment?(plain)

    assert pdf.type == "application/pdf"
    assert pdf.filename == "résumé.pdf"
    assert pdf.body == "%PDF-1.4\n"
    assert MIME.attachment?(pdf)

    assert message.type == "message/rfc822"
    assert [inner] = message.parts
    assert MIME.header(inner, "subject") == "inner"
    assert inner.text == "Привет"

    assert Enum.map(MIME.leaves(root), & &1.type) ==
             ["text/plain", "text/html", "application/pdf", "text/plain"]
  end

  test "takes LF line endings and transport padding" do
    message =
      "Content-Type: multipart/mixed; boundary=b\n\n--b \t\nContent-Type: text/plain\n\nhi\n--b--  \n"

    assert %{parts: [%{text: "hi"}], anomalies: []} = MIME.parse(message)
  end

  test "notes what is wrong, and goes on" do
    assert %{type: "text/plain", text: "x", anomalies: [:no_boundary]} =
             MIME.parse(crlf("Content-Type: multipart/mixed\n\nx"))

    assert %{anomalies: [:no_parts]} =
             MIME.parse(crlf("Content-Type: multipart/mixed; boundary=b\n\nno delimiters"))

    assert %{parts: [%{text: "open"}], anomalies: [:unclosed]} =
             MIME.parse(crlf("Content-Type: multipart/mixed; boundary=b\n\n--b\n\nopen"))

    assert %{body: "hi", anomalies: [:damaged_encoding]} =
             MIME.parse(crlf("Content-Transfer-Encoding: base64\n\naGk*"))

    assert %{text: "x", anomalies: [:unknown_charset]} =
             MIME.parse(crlf("Content-Type: text/plain; charset=x-klingon\n\nx"))

    assert %{body: "x", anomalies: [:unknown_encoding]} =
             MIME.parse(crlf("Content-Transfer-Encoding: x-uuencode\n\nx"))

    # A base64 message: forbidden, but decoded.
    inner = Base.encode64("Subject: hidden\r\n\r\nbody")

    assert %{parts: [inner], anomalies: [:encoded_composite]} =
             MIME.parse(
               crlf("Content-Type: message/rfc822\nContent-Transfer-Encoding: base64\n\n#{inner}")
             )

    assert MIME.header(inner, "subject") == "hidden"

    # A delimiter one byte into the body is not at a line start.
    assert %{anomalies: [:no_parts]} =
             MIME.parse(crlf("Content-Type: multipart/mixed; boundary=b\n\n=--b\nx"))

    # Raw 8-bit bytes in a parameter: windows-1252.
    assert {"attachment", %{"filename" => "café.txt"}} =
             Params.parse(<<"attachment; filename=caf", 0xE9, ".txt">>)

    # A type that is not one: the default.
    assert %{type: "text/plain"} = MIME.parse(crlf("Content-Type: nonsense\n\nx"))
  end

  test "keeps to its limits" do
    nested =
      Enum.reduce(1..30, "Content-Type: text/plain\r\n\r\ndeep", fn _, inner ->
        "Content-Type: message/rfc822\r\n\r\n" <> inner
      end)

    assert :depth_limit in MIME.anomalies(MIME.parse(nested))

    many =
      "Content-Type: multipart/mixed; boundary=b\r\n\r\n" <>
        String.duplicate("--b\r\n\r\nx\r\n", 20) <> "--b--\r\n"

    assert MIME.parse(many, max_parts: 5) |> MIME.anomalies() |> Enum.count(&(&1 == :part_limit)) ==
             16

    big = "Content-Transfer-Encoding: base64\r\n\r\n" <> Base.encode64(:binary.copy("a", 1000))
    assert %{body: body, anomalies: [:size_limit]} = MIME.parse(big, max_size: 100)
    assert byte_size(body) == 100

    long = String.duplicate("X-Long: #{String.duplicate("y", 50)}\r\n", 10) <> "\r\nbody"
    assert %{headers: headers, anomalies: [:header_limit]} = MIME.parse(long, max_header: 200)
    assert length(headers) == 3
  end

  test "quoted-printable drops trailing white space and keeps broken escapes" do
    assert Transfer.decode("a  \r\nb\t\r\n", "quoted-printable") == {:ok, "a\r\nb\r\n"}
    assert Transfer.decode("a =\r\nb", "quoted-printable") == {:ok, "a b"}
    assert Transfer.decode("=e9", "quoted-printable") == {:ok, <<0xE9>>}
    assert Transfer.decode("=-1", "quoted-printable") == {:damaged, "=-1"}
    # A soft line break at the very end.
    assert Transfer.decode("a=", "quoted-printable") == {:ok, "a"}
  end

  test "encoded words are decoded inside quotes and words, as mail readers do" do
    assert EncodedWord.decode(~s("=?utf-8?Q?J=C3=B6rg?=" <j@example.com>)) ==
             ~s("Jörg" <j@example.com>)

    assert EncodedWord.decode("V=?utf-8?Q?i?=agra") == "Viagra"
    assert EncodedWord.decode(<<"caf", 0xE9>>) == "café"
    assert EncodedWord.decode("=?utf-8*en?Q?a_b?=") == "a b"
  end
end
