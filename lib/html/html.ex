defmodule Sovite.HTML do
  @moduledoc """
  What a filter needs from the HTML of a message: its visible text, the
  text it hides, its links and images, and its title. A tokenizer, not a
  browser: it never builds a document tree, runs nothing, fetches
  nothing, and works in bounded time and memory on any input.

      html = Sovite.HTML.parse(~s(<p>Hello <a href="https://example.com/">there</a></p>))
      html.text   #=> "Hello there"
      html.links  #=> [%{href: "https://example.com/", text: "there"}]

  Block elements (`p`, `div`, `br`, `li`, `tr`, headings, ...) end lines;
  runs of white space become one space. `script`, `style`, and comments
  are left out. Text in elements an inline `style` hides (`display:
  none`, `visibility: hidden`, `font-size: 0`, `opacity: 0`) or with the
  `hidden` attribute goes to `hidden_text` instead: spam hides words for
  filters there. Character references are decoded
  (`Sovite.HTML.Entities`).

  ## Limits

    * `:max_input` - bytes of HTML read. Defaults to 2 MiB.
    * `:max_tags` - tags read. Defaults to 20,000.
    * `:max_depth` - open elements tracked for hiding. Defaults to 256.
    * `:max_links` - links and images kept, each. Defaults to 1,000.

  Going over a limit is noted in `anomalies` (`:size_limit`,
  `:tag_limit`, `:depth_limit`, `:link_limit`).
  """

  alias Sovite.HTML.Entities

  defstruct text: "", hidden_text: "", title: nil, links: [], images: [], tags: 0, anomalies: []

  @type link :: %{href: String.t(), text: String.t()}
  @type image :: %{src: String.t(), alt: String.t() | nil}

  @type t :: %__MODULE__{
          text: String.t(),
          hidden_text: String.t(),
          title: String.t() | nil,
          links: [link()],
          images: [image()],
          tags: non_neg_integer(),
          anomalies: [atom()]
        }

  @defaults [max_input: 2 * 1024 * 1024, max_tags: 20_000, max_depth: 256, max_links: 1000]

  @blocks ~w(address article aside blockquote br center dd details dialog div dl dt fieldset
             figcaption figure footer form h1 h2 h3 h4 h5 h6 header hr li main nav ol p pre
             section summary table tbody thead tfoot tr ul)
  @cells ~w(td th)
  @void ~w(area base br col embed hr img input link meta param source track wbr)
  @skipped ~w(script style template)

  @doc "Reads `html` (UTF-8). See the module docs."
  @spec parse(String.t(), keyword()) :: t()
  def parse(html, opts \\ []) when is_binary(html) do
    limits = Map.new(Keyword.merge(@defaults, opts))
    html = String.replace_invalid(html)

    {html, anomalies} =
      if byte_size(html) > limits.max_input,
        do: {binary_part(html, 0, limits.max_input), [:size_limit]},
        else: {html, []}

    state = %{
      limits: limits,
      visible: [],
      hidden: [],
      stack: [],
      links: [],
      images: [],
      kept: %{links: 0, images: 0},
      depth: 0,
      link: nil,
      title: nil,
      tags: 0,
      anomalies: anomalies
    }

    state = scan(html, state)

    %__MODULE__{
      text: finish(state.visible),
      hidden_text: finish(state.hidden),
      title: state.title,
      links: Enum.reverse(state.links),
      images: Enum.reverse(state.images),
      tags: state.tags,
      anomalies: Enum.reverse(state.anomalies)
    }
  end

  ## Scanning

  defp scan(<<>>, state), do: close_link(state)

  defp scan(html, state) do
    case :binary.match(html, "<") do
      :nomatch ->
        state |> text(html) |> close_link()

      {at, 1} ->
        <<before::binary-size(^at), _lt, rest::binary>> = html
        markup(rest, text(state, before))
    end
  end

  defp markup(<<"!--", rest::binary>>, state), do: scan(after_text(rest, "-->"), state)
  defp markup(<<"!", rest::binary>>, state), do: scan(after_text(rest, ">"), state)
  defp markup(<<"?", rest::binary>>, state), do: scan(after_text(rest, ">"), state)

  defp markup(<<"/", c, _::binary>> = rest, state) when c in ?a..?z or c in ?A..?Z do
    <<"/", rest::binary>> = rest
    {name, rest} = name(rest)
    tag(state, after_text(rest, ">"), fn state -> end_tag(state, name) end)
  end

  defp markup(<<c, _::binary>> = rest, state) when c in ?a..?z or c in ?A..?Z do
    {name, rest} = name(rest)
    {attributes, rest} = attributes(rest, [])
    tag(state, rest, fn state -> start_tag(state, name, attributes) end, name)
  end

  # Not a tag: a "<" in the text.
  defp markup(rest, state), do: scan(rest, text(state, "<"))

  defp tag(state, rest, handle, name \\ nil) do
    state = %{state | tags: state.tags + 1}

    cond do
      state.tags > state.limits.max_tags ->
        close_link(%{state | anomalies: [:tag_limit | state.anomalies]})

      name in @skipped ->
        scan(after_end_tag(rest, name), state)

      name == "title" ->
        {title, rest} = raw_text(rest, "title")
        scan(rest, %{state | title: state.title || clean(title)})

      true ->
        scan(rest, handle.(state))
    end
  end

  defp after_text(html, marker) do
    case :binary.match(html, marker) do
      {at, length} -> binary_part(html, at + length, byte_size(html) - at - length)
      :nomatch -> ""
    end
  end

  @end_tags Map.new(~w(script style template title), &{&1, Regex.compile!("</#{&1}\\s*>", "i")})

  # The content of a raw text element up to its end tag, and what follows.
  defp raw_text(html, name) do
    case Regex.run(Map.fetch!(@end_tags, name), html, return: :index) do
      [{at, length}] ->
        {binary_part(html, 0, at), binary_part(html, at + length, byte_size(html) - at - length)}

      nil ->
        {html, ""}
    end
  end

  defp after_end_tag(html, name), do: html |> raw_text(name) |> elem(1)

  defp name(html) do
    [name] = Regex.run(~r/\A[A-Za-z][A-Za-z0-9:_-]*/, html)
    {String.downcase(name), binary_part(html, byte_size(name), byte_size(html) - byte_size(name))}
  end

  # Attributes up to ">", lower-cased names, decoded values; the rest of
  # the HTML after the tag.
  defp attributes(html, acc) do
    case Regex.run(
           ~r/\A[\s\/]*([^\s\/>=][^\s\/>=]*)(?:\s*=\s*(?:"([^"]*)"?|'([^']*)'?|([^\s>]*)))?/s,
           html
         ) do
      [all | captures] when all != "" ->
        rest = binary_part(html, byte_size(all), byte_size(html) - byte_size(all))
        [name | values] = captures ++ List.duplicate("", 4 - length(captures))
        value = Enum.find(values, "", &(&1 != ""))
        attributes(rest, [{String.downcase(name), Entities.decode(value)} | acc])

      _ ->
        {Enum.reverse(acc), after_text(html, ">")}
    end
  end

  ## Elements

  defp start_tag(state, name, attributes) do
    state = if name in @blocks, do: newline(state), else: state
    state = if name in @cells, do: text(state, " "), else: state
    state = element(state, name, Map.new(attributes))

    if name in @void, do: state, else: push(state, name, hides?(attributes))
  end

  defp element(state, "a", %{"href" => href}) do
    state = close_link(state)
    %{state | link: %{href: String.trim(href), text: []}}
  end

  defp element(state, "img", %{"src" => src} = attributes) do
    image = %{src: String.trim(src), alt: attributes["alt"]}
    keep(state, :images, image)
  end

  defp element(state, _name, _attributes), do: state

  defp end_tag(state, name) do
    state = if name in @blocks, do: newline(state), else: state
    state = if name == "a", do: close_link(state), else: state
    pop(state, name)
  end

  defp close_link(%{link: nil} = state), do: state

  defp close_link(%{link: link} = state) do
    text = link.text |> Enum.reverse() |> IO.iodata_to_binary() |> clean()
    keep(%{state | link: nil}, :links, %{href: link.href, text: text})
  end

  defp keep(state, key, item) do
    cond do
      state.kept[key] < state.limits.max_links ->
        state
        |> Map.put(key, [item | Map.fetch!(state, key)])
        |> Map.put(:kept, Map.update!(state.kept, key, &(&1 + 1)))

      :link_limit in state.anomalies ->
        state

      true ->
        %{state | anomalies: [:link_limit | state.anomalies]}
    end
  end

  # Open elements, and whether each hides its content.
  defp push(state, name, hides) do
    hidden = hides or hidden?(state)

    if state.depth < state.limits.max_depth do
      %{state | stack: [{name, hidden} | state.stack], depth: state.depth + 1}
    else
      if :depth_limit in state.anomalies,
        do: state,
        else: %{state | anomalies: [:depth_limit | state.anomalies]}
    end
  end

  # Closes the innermost open element of that name, and those in it.
  defp pop(state, name) do
    case Enum.split_while(state.stack, fn {open, _hidden} -> open != name end) do
      {inner, [_element | outer]} ->
        %{state | stack: outer, depth: state.depth - length(inner) - 1}

      {_all, []} ->
        state
    end
  end

  defp hidden?(%{stack: [{_name, hidden} | _]}), do: hidden
  defp hidden?(_state), do: false

  @hiding ~r/(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d]*[1-9])[a-z%]*\s*(?:;|$)|opacity\s*:\s*0(?:\.0*)?\s*(?:;|$))/i

  defp hides?(attributes) do
    Enum.any?(attributes, fn
      {"hidden", _} -> true
      {"style", style} -> Regex.match?(@hiding, style)
      _ -> false
    end)
  end

  ## Text

  defp text(state, ""), do: state

  defp text(state, raw) do
    # Line breaks in the source are white space; blocks end lines.
    decoded = raw |> Entities.decode() |> String.replace(["\r", "\n"], " ")
    state = if state.link, do: put_in(state.link.text, [decoded | state.link.text]), else: state

    if hidden?(state),
      do: %{state | hidden: [decoded | state.hidden]},
      else: %{state | visible: [decoded | state.visible]}
  end

  defp newline(state),
    do: %{state | visible: ["\n" | state.visible], hidden: ["\n" | state.hidden]}

  defp finish(pieces) do
    pieces
    |> Enum.reverse()
    |> IO.iodata_to_binary()
    |> String.replace(~r/[^\S\n]+/u, " ")
    |> String.replace(~r/ *\n[ \n]*/, "\n")
    |> String.trim()
  end

  defp clean(text),
    do: text |> Entities.decode() |> String.replace(~r/\s+/u, " ") |> String.trim()
end
