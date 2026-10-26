defmodule Sovite.Analyzer do
  @moduledoc """
  Takes a message apart for a filter, within hard limits: its MIME
  structure (`Sovite.MIME`), the text of its text parts (HTML made text
  with `Sovite.HTML`), the URLs and mail addresses in them
  (`Sovite.URL`), and its attachments with their types by content
  (`Sovite.Magic`).

      analysis = Sovite.Analyzer.analyze(message)
      analysis.subject
      for url <- analysis.urls, do: url.host
      for %{disguised: true} = attachment <- analysis.attachments, do: attachment.filename

  Nothing fails: what is broken or over a limit is listed in
  `anomalies`, as MIME anomalies (`:unclosed`, ...) and HTML ones as
  `{:html, anomaly}`.

  ## Options

  Those of `Sovite.MIME.parse/2`, `:html` with those of
  `Sovite.HTML.parse/2`, and `:max_urls` and `:max_addresses` (1,000
  each).
  """

  alias Sovite.{HTML, Magic, MIME, URL}

  defstruct [:mime, :subject, texts: [], urls: [], addresses: [], attachments: [], anomalies: []]

  @typedoc """
  A text part: its text, where it came from (`:plain` or `:html`), and
  for HTML the text it hides, its title, and its images.
  """
  @type text :: %{
          source: :plain | :html,
          text: String.t(),
          hidden_text: String.t(),
          title: String.t() | nil,
          images: [HTML.image()]
        }

  @typedoc """
  A URL, where it was found, and for a link the text the reader sees
  (which a phishing link makes look like another URL).
  """
  @type url :: %{url: URL.t(), source: :text | :html, link_text: String.t() | nil}

  @typedoc """
  An attachment: its file name, declared type, size, the type its content
  has (`Sovite.Magic`), and whether those disagree in a way that hides
  something: a program or script with a name or type that says
  otherwise.
  """
  @type attachment :: %{
          filename: String.t() | nil,
          declared: String.t(),
          size: non_neg_integer(),
          detected: Magic.result() | nil,
          disguised: boolean()
        }

  @type t :: %__MODULE__{
          mime: MIME.t(),
          subject: String.t() | nil,
          texts: [text()],
          urls: [url()],
          addresses: [String.t()],
          attachments: [attachment()],
          anomalies: [MIME.anomaly() | {:html, atom()}]
        }

  # Extensions of files a system runs: a name that says otherwise hides them.
  @runnable ~w(exe com scr pif bat cmd msi msp lnk hta js jse vbs vbe wsf wsh ps1 psm1 jar
               apk app dmg elf sh macho class chm one cpl dll sys reg)

  @doc "Analyzes a message. See the module docs."
  @spec analyze(binary(), keyword()) :: t()
  def analyze(message, opts \\ []) when is_binary(message) do
    mime =
      MIME.parse(message, Keyword.take(opts, [:max_depth, :max_parts, :max_size, :max_header]))

    leaves = MIME.leaves(mime)

    {texts, html_anomalies, links} =
      leaves
      |> Enum.reject(&MIME.attachment?/1)
      |> Enum.filter(&(&1.text != nil))
      |> Enum.map(&text(&1, opts))
      |> unzip3()

    urls = urls(texts, List.flatten(links), opts)

    %__MODULE__{
      mime: mime,
      subject: MIME.header(mime, "subject"),
      texts: texts,
      urls: urls,
      addresses:
        URL.addresses(Enum.map_join(texts, "\n", & &1.text),
          max_addresses: Keyword.get(opts, :max_addresses, 1000)
        ),
      attachments: for(part <- leaves, MIME.attachment?(part), do: attachment(part)),
      anomalies: MIME.anomalies(mime) ++ Enum.map(List.flatten(html_anomalies), &{:html, &1})
    }
  end

  defp unzip3(triples) do
    {Enum.map(triples, &elem(&1, 0)), Enum.map(triples, &elem(&1, 1)),
     Enum.map(triples, &elem(&1, 2))}
  end

  defp text(%{type: "text/html", text: source}, opts) do
    html = HTML.parse(source, Keyword.get(opts, :html, []))

    text = %{
      source: :html,
      text: html.text,
      hidden_text: html.hidden_text,
      title: html.title,
      images: html.images
    }

    {text, html.anomalies, html.links}
  end

  defp text(%{text: text}, _opts),
    do: {%{source: :plain, text: text, hidden_text: "", title: nil, images: []}, [], []}

  # URLs in links first (with what the reader sees), then those in text.
  defp urls(texts, links, opts) do
    max = Keyword.get(opts, :max_urls, 1000)

    linked =
      for %{href: href, text: link_text} <- links, {:ok, url} <- [URL.parse(href)] do
        %{url: url, source: :html, link_text: link_text}
      end

    written =
      for %{text: text} <- texts, url <- URL.extract(text, max_urls: max) do
        %{url: url, source: :text, link_text: nil}
      end

    # And where redirectors send the reader.
    targets =
      for %{url: url} = found <- linked ++ written,
          target <- URL.redirect_targets(url),
          do: %{found | url: target, link_text: nil}

    # Once per source: a URL in a link and in text are two findings.
    (linked ++ written ++ targets) |> Enum.uniq_by(&{&1.source, &1.url.url}) |> Enum.take(max)
  end

  defp attachment(part) do
    body = part.body || ""
    detected = Magic.detect(binary_part(body, 0, min(byte_size(body), 65_536)))

    %{
      filename: part.filename,
      declared: part.type,
      size: byte_size(body),
      detected: detected,
      disguised: disguised?(part.filename, detected)
    }
  end

  # A program or script whose name does not say so.
  defp disguised?(_filename, nil), do: false

  defp disguised?(filename, %{kind: kind}) when kind in [:executable, :script] do
    extension =
      filename && filename |> Path.extname() |> String.trim_leading(".") |> String.downcase()

    extension not in @runnable
  end

  defp disguised?(_filename, _detected), do: false
end
