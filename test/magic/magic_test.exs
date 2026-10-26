defmodule Sovite.MagicTest do
  use ExUnit.Case, async: true

  alias Sovite.Magic

  doctest Magic

  defp kind(data), do: (Magic.detect(data) || %{})[:extension]

  test "knows programs, whatever they are called" do
    assert kind(<<"MZ", 0::size(464), 64::32-little, "PE", 0, 0, "rest">>) == "exe"
    assert kind(<<"MZ", 0::size(464), 4096::32-little>>) == "exe"
    assert kind(<<0x7F, "ELF", 2, 1>>) == "elf"
    assert kind(<<0xCF, 0xFA, 0xED, 0xFE>>) == "macho"
    assert kind(<<0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52>>) == "class"
    assert kind(<<0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2>>) == "macho"
    assert kind(<<0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0>>) == "lnk"
    assert kind("#!/bin/sh\nrm -rf /") == "sh"
    assert kind("<HTA:APPLICATION ID=x>") == "hta"
  end

  test "tells ZIP-based formats apart by the names inside" do
    zip = fn name -> <<"PK", 3, 4, 0::size(208), name::binary, "...">> end
    assert kind(zip.("word/document.xml")) == "docx"
    assert kind(zip.("xl/workbook.xml")) == "xlsx"
    assert kind(zip.("ppt/slides/slide1.xml")) == "pptx"
    assert kind(zip.("mimetypeapplication/vnd.oasis.opendocument.text")) == "odt"
    assert kind(zip.("META-INF/MANIFEST.MF")) == "jar"
    assert kind(zip.("classes.dex")) == "apk"
    assert kind(zip.("readme.txt")) == "zip"
  end

  test "knows archives, documents, images, and markup" do
    assert kind(<<"Rar!", 0x1A, 0x07, 1, 0>>) == "rar"
    assert kind(<<"7z", 0xBC, 0xAF, 0x27, 0x1C>>) == "7z"
    assert kind(<<0x1F, 0x8B, 8>>) == "gz"
    assert kind(<<0::size(2056), "ustar", 0>>) == "tar"
    assert kind("%PDF-1.4") == "pdf"
    assert kind("{\\rtf1\\ansi") == "rtf"

    ole = <<0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0::size(4096)>>
    utf16 = fn name -> for <<c <- name>>, into: "", do: <<c, 0>> end
    assert kind(ole <> utf16.("WordDocument")) == "doc"
    assert kind(ole <> utf16.("Workbook")) == "xls"
    assert kind(ole) == "msi"

    assert kind(<<0x89, "PNG\r\n", 0x1A, "\n">>) == "png"
    assert kind(<<0xFF, 0xD8, 0xFF, 0xE0>>) == "jpg"
    assert kind("GIF89a") == "gif"
    assert kind(<<0xEF, 0xBB, 0xBF, "  <!DOCTYPE html><html>">>) == "html"
    assert kind(~s(<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg">)) == "svg"
    assert kind("plain text") == nil
    assert kind("") == nil
  end
end
