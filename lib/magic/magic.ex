defmodule Sovite.Magic do
  @moduledoc """
  File types by content (magic numbers), not by name: a filter must know
  that `invoice.pdf` is a Windows program.

      iex> Sovite.Magic.detect("%PDF-1.7\\n...")
      %{type: "application/pdf", extension: "pdf", kind: :document}
      iex> Sovite.Magic.detect(<<"MZ", 0::size(464), 64::32-little, "PE", 0, 0>>)
      %{type: "application/x-msdownload", extension: "exe", kind: :executable}
      iex> Sovite.Magic.detect("just text")
      nil

  `kind` groups types for policies: `:executable` (programs, libraries,
  shortcuts, installers), `:script` (files a system runs as code),
  `:archive`, `:document`, `:image`, `:media`, and `:markup` (HTML, SVG,
  XML, which can carry scripts). ZIP-based formats (Office documents,
  OpenDocument, Java archives, Android packages) are told apart by the
  names inside them. Only the start of the data is read: pass the first
  few kilobytes.
  """

  @type kind :: :executable | :script | :archive | :document | :image | :media | :markup
  @type result :: %{type: String.t(), extension: String.t(), kind: kind()}

  @doc "The type of `data`, or `nil` when it is not one this module knows."
  @spec detect(binary()) :: result() | nil
  def detect(data) when is_binary(data), do: signature(data) || text(data)

  defp t(type, extension, kind), do: %{type: type, extension: extension, kind: kind}

  # Executables.
  defp signature(<<"MZ", _::binary>> = data), do: pe(data)

  defp signature(<<0x7F, "ELF", _::binary>>),
    do: t("application/x-executable", "elf", :executable)

  defp signature(<<0xFE, 0xED, 0xFA, b, _::binary>>) when b in [0xCE, 0xCF], do: macho()
  defp signature(<<b, 0xFA, 0xED, 0xFE, _::binary>>) when b in [0xCE, 0xCF], do: macho()

  # 0xCAFEBABE is a Mach-O universal binary or a Java class: classes have
  # a major version of 45 or more, universal binaries a small arch count.
  defp signature(<<0xCA, 0xFE, 0xBA, 0xBE, _minor::16, major::16, _::binary>>) when major >= 45,
    do: t("application/java-vm", "class", :executable)

  defp signature(<<0xCA, 0xFE, 0xBA, 0xBE, _::binary>>), do: macho()

  defp signature(<<0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, _::binary>>),
    do: t("application/x-ms-shortcut", "lnk", :executable)

  defp signature(<<"ITSF", _::binary>>), do: t("application/vnd.ms-htmlhelp", "chm", :executable)

  defp signature(<<0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, _::binary>>),
    do: t("application/onenote", "one", :document)

  # Archives.
  defp signature(<<"PK", a, b, _::binary>> = data) when {a, b} in [{3, 4}, {5, 6}, {7, 8}],
    do: zip(data)

  defp signature(<<"Rar!", 0x1A, 0x07, _::binary>>), do: t("application/vnd.rar", "rar", :archive)

  defp signature(<<"7z", 0xBC, 0xAF, 0x27, 0x1C, _::binary>>),
    do: t("application/x-7z-compressed", "7z", :archive)

  defp signature(<<0x1F, 0x8B, _::binary>>), do: t("application/gzip", "gz", :archive)
  defp signature(<<"BZh", _::binary>>), do: t("application/x-bzip2", "bz2", :archive)
  defp signature(<<0xFD, "7zXZ", 0, _::binary>>), do: t("application/x-xz", "xz", :archive)

  defp signature(<<0x28, 0xB5, 0x2F, 0xFD, _::binary>>),
    do: t("application/zstd", "zst", :archive)

  defp signature(<<"MSCF", 0, 0, 0, 0, _::binary>>),
    do: t("application/vnd.ms-cab-compressed", "cab", :archive)

  defp signature(<<_::binary-7, "**ACE**", _::binary>>),
    do: t("application/x-ace-compressed", "ace", :archive)

  defp signature(<<0x60, 0xEA, _::binary>>), do: t("application/x-arj", "arj", :archive)

  defp signature(<<_::binary-2, "-lh", _, "-", _::binary>>),
    do: t("application/x-lzh-compressed", "lzh", :archive)

  defp signature(<<_::binary-257, "ustar", _::binary>>),
    do: t("application/x-tar", "tar", :archive)

  defp signature(<<_::binary-0x8001, "CD001", _::binary>>),
    do: t("application/x-iso9660-image", "iso", :archive)

  # Documents.
  defp signature(<<"%PDF-", _::binary>>), do: t("application/pdf", "pdf", :document)

  defp signature(<<0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, _::binary>> = data),
    do: ole(data)

  defp signature(<<"{\\rtf", _::binary>>), do: t("application/rtf", "rtf", :document)

  # Images and media.
  defp signature(<<0x89, "PNG\r\n", 0x1A, "\n", _::binary>>), do: t("image/png", "png", :image)
  defp signature(<<0xFF, 0xD8, 0xFF, _::binary>>), do: t("image/jpeg", "jpg", :image)

  defp signature(<<"GIF8", v, "a", _::binary>>) when v in [?7, ?9],
    do: t("image/gif", "gif", :image)

  defp signature(<<"BM", _::binary-12, size::32-little, _::binary>>)
       when size in [12, 40, 52, 56, 108, 124], do: t("image/bmp", "bmp", :image)

  defp signature(<<"II*", 0, _::binary>>), do: t("image/tiff", "tif", :image)
  defp signature(<<"MM", 0, "*", _::binary>>), do: t("image/tiff", "tif", :image)
  defp signature(<<"RIFF", _::binary-4, "WEBP", _::binary>>), do: t("image/webp", "webp", :image)
  defp signature(<<"RIFF", _::binary-4, "WAVE", _::binary>>), do: t("audio/wav", "wav", :media)

  defp signature(<<"RIFF", _::binary-4, "AVI ", _::binary>>),
    do: t("video/x-msvideo", "avi", :media)

  defp signature(<<0, 0, 1, 0, count::16-little, _::binary>>) when count in 1..64,
    do: t("image/x-icon", "ico", :image)

  defp signature(<<"ID3", _::binary>>), do: t("audio/mpeg", "mp3", :media)
  defp signature(<<_::binary-4, "ftyp", _::binary>>), do: t("video/mp4", "mp4", :media)
  defp signature(<<"OggS", _::binary>>), do: t("audio/ogg", "ogg", :media)

  defp signature(_data), do: nil

  defp macho, do: t("application/x-mach-binary", "macho", :executable)

  # A PE file has "PE\0\0" where the DOS header's e_lfanew points; a DOS
  # program does not.
  defp pe(<<_::binary-0x3C, offset::32-little, _::binary>> = data)
       when offset <= byte_size(data) - 4 do
    case data do
      <<_::binary-size(^offset), "PE", 0, 0, _::binary>> ->
        t("application/x-msdownload", "exe", :executable)

      _ ->
        t("application/x-dosexec", "com", :executable)
    end
  end

  defp pe(_data), do: t("application/x-dosexec", "exe", :executable)

  # ZIP-based formats: the names of the first entries tell, in this order.
  @zip [
    {"mimetypeapplication/vnd.oasis.opendocument.text", "application/vnd.oasis.opendocument.text",
     "odt", :document},
    {"mimetypeapplication/vnd.oasis.opendocument.spreadsheet",
     "application/vnd.oasis.opendocument.spreadsheet", "ods", :document},
    {"mimetypeapplication/vnd.oasis.opendocument.presentation",
     "application/vnd.oasis.opendocument.presentation", "odp", :document},
    {"word/", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx",
     :document},
    {"xl/", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx",
     :document},
    {"ppt/", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx",
     :document},
    {"AndroidManifest.xml", "application/vnd.android.package-archive", "apk", :executable},
    {"classes.dex", "application/vnd.android.package-archive", "apk", :executable},
    {"META-INF/MANIFEST.MF", "application/java-archive", "jar", :executable}
  ]

  defp zip(data) do
    Enum.find_value(@zip, t("application/zip", "zip", :archive), fn {marker, type, extension,
                                                                     kind} ->
      if String.contains?(data, marker), do: t(type, extension, kind)
    end)
  end

  # OLE compound files: Word, Excel, PowerPoint, Outlook, installers. The
  # stream names (UTF-16) in the first sectors tell.
  defp ole(data) do
    cond do
      String.contains?(data, utf16("WordDocument")) ->
        t("application/msword", "doc", :document)

      String.contains?(data, utf16("Workbook")) or String.contains?(data, utf16("Book")) ->
        t("application/vnd.ms-excel", "xls", :document)

      String.contains?(data, utf16("PowerPoint Document")) ->
        t("application/vnd.ms-powerpoint", "ppt", :document)

      String.contains?(data, utf16("__substg1.0_")) ->
        t("application/vnd.ms-outlook", "msg", :document)

      true ->
        t("application/x-ole-storage", "msi", :executable)
    end
  end

  defp utf16(name), do: for(<<c <- name>>, into: "", do: <<c, 0>>)

  # Text formats: markup and scripts, by how they start (lower-cased,
  # after a byte order mark and white space), in this order.
  @text [
    {"#!", "text/x-shellscript", "sh", :script},
    {"<!doctype html", "text/html", "html", :markup},
    {"<html", "text/html", "html", :markup},
    {"<svg", "image/svg+xml", "svg", :markup},
    {"<hta:application", "application/hta", "hta", :script}
  ]

  defp text(data) do
    head =
      data
      |> binary_part(0, min(byte_size(data), 1024))
      |> String.replace_prefix(<<0xEF, 0xBB, 0xBF>>, "")
      |> String.trim_leading()
      |> String.downcase(:ascii)

    Enum.find_value(@text, fn {start, type, extension, kind} ->
      if String.starts_with?(head, start), do: t(type, extension, kind)
    end) || xml(head)
  end

  defp xml("<?xml" <> _ = head) do
    if String.contains?(head, "<svg"),
      do: t("image/svg+xml", "svg", :markup),
      else: t("application/xml", "xml", :markup)
  end

  defp xml(head) do
    if String.contains?(head, "<hta:application"), do: t("application/hta", "hta", :script)
  end
end
