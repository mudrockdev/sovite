defmodule Sovite.DKIM.Body do
  @moduledoc """
  Body hashes (RFC 6376 §3.4.3, §3.4.4, §3.7), computed while the body
  streams by, for any number of signatures at once.

      body = Sovite.DKIM.Body.new([{:relaxed, :sha256, nil}, {:simple, :sha256, 100}])
      body = Sovite.DKIM.Body.update(body, chunk)
      %{{:relaxed, :sha256, nil} => {hash, length}} = Sovite.DKIM.Body.finish(body)

  A spec is the body canonicalization, the hash, and the `l=` length
  limit (`nil` for the whole body). Each canonicalization is done once,
  however many specs use it. `finish/1` returns each hash with the
  length of the whole canonicalized body, so a verifier can tell an
  `l=` larger than the body.

  The body is the data after the empty line that ends the header
  section, with CRLF line endings.
  """

  @type spec :: {Sovite.DKIM.Canon.algorithm(), :sha256, non_neg_integer() | nil}

  @opaque t :: %{optional(Sovite.DKIM.Canon.algorithm()) => map()}

  # A line longer than this is canonicalized in pieces, so a body without
  # line breaks does not pile up in memory.
  @max_pending 65_536

  @doc "Starts hashing for `specs`."
  @spec new([spec()]) :: t()
  def new(specs) do
    specs
    |> Enum.uniq()
    |> Enum.group_by(&elem(&1, 0))
    |> Map.new(fn {canon, specs} ->
      hashes =
        Map.new(specs, fn {_, hash, limit} = spec -> {spec, {:crypto.hash_init(hash), limit}} end)

      {canon, %{line: "", open: false, blank: 0, length: 0, hashes: hashes}}
    end)
  end

  @doc "Feeds body data."
  @spec update(t(), iodata()) :: t()
  def update(body, _data) when map_size(body) == 0, do: body

  def update(body, data) do
    data = IO.iodata_to_binary(data)
    Map.new(body, fn {canon, state} -> {canon, feed(canon, state, data)} end)
  end

  @doc "Ends the body. Returns each spec's hash and the canonicalized body length."
  @spec finish(t()) :: %{spec() => {binary(), non_neg_integer()}}
  def finish(body) do
    Enum.reduce(body, %{}, fn {canon, state}, acc ->
      state = finish_canon(canon, state)

      Enum.reduce(state.hashes, acc, fn {spec, {hash, _left}}, acc ->
        Map.put(acc, spec, {:crypto.hash_final(hash), state.length})
      end)
    end)
  end

  defp feed(canon, state, data) do
    lines = :binary.split(state.line <> data, "\r\n", [:global])
    {complete, [rest]} = Enum.split(lines, -1)
    state = Enum.reduce(complete, %{state | line: ""}, &line(canon, &2, &1))

    if byte_size(rest) > @max_pending,
      do: partial(canon, state, rest),
      else: %{state | line: rest}
  end

  # Empty lines are held back: at the end of the body they are dropped.
  # The end of a line that was started by `partial/3` is never empty.
  defp line(canon, state, text) do
    case canonical_line(canon, text) do
      "" when not state.open -> %{state | blank: state.blank + 1}
      text -> %{emit(flush_blank(state), [text, "\r\n"]) | open: false}
    end
  end

  defp canonical_line(:simple, text), do: text

  defp canonical_line(:relaxed, text),
    do: text |> String.replace(~r/[ \t]+/, " ") |> String.trim_trailing(" ")

  # Emits the start of a long line. What is kept back could still turn
  # out to be trailing whitespace (relaxed) or the end of the body.
  defp partial(:simple, state, text) do
    size = byte_size(text) - 1
    head = binary_part(text, 0, size)
    %{emit(flush_blank(state), head) | line: binary_part(text, size, 1), open: true}
  end

  defp partial(:relaxed, state, text) do
    case Regex.run(~r/\A(.*[^ \t])([ \t]*)\z/s, text) do
      [_, head, tail] ->
        head = String.replace(head, ~r/[ \t]+/, " ")
        %{emit(flush_blank(state), head) | line: tail, open: true}

      nil ->
        %{state | line: " "}
    end
  end

  defp flush_blank(%{blank: 0} = state), do: state

  defp flush_blank(state),
    do: emit(%{state | blank: 0}, :binary.copy("\r\n", state.blank))

  # A body that does not end in CRLF gets one (§3.4.3, §3.4.4). An empty
  # body is CRLF for simple and nothing for relaxed.
  defp finish_canon(canon, state) do
    case canonical_line(canon, state.line) do
      "" when state.open -> emit(state, "\r\n")
      "" when canon == :simple and state.length == 0 -> emit(state, "\r\n")
      "" -> state
      text -> emit(flush_blank(state), [text, "\r\n"])
    end
  end

  defp emit(state, data) do
    size = IO.iodata_length(data)

    hashes =
      Map.new(state.hashes, fn
        {spec, {hash, nil}} ->
          {spec, {:crypto.hash_update(hash, data), nil}}

        {spec, {hash, left}} ->
          take = min(left, size)
          part = binary_part(IO.iodata_to_binary(data), 0, take)
          {spec, {:crypto.hash_update(hash, part), left - take}}
      end)

    %{state | hashes: hashes, length: state.length + size}
  end
end
