defmodule Sovite.DKIM do
  @moduledoc """
  DKIM signing and verification (RFC 6376), with RSA-SHA256 and
  Ed25519-SHA256 (RFC 8463). RSA-SHA1 signatures and RSA keys shorter
  than 1024 bits are never accepted (RFC 8301).

  For a whole message in memory:

      results = Sovite.DKIM.verify(message, resolver)
      [field] = Sovite.DKIM.sign(message, [key])
      signed = field <> message

  An MTA hashes the body while it streams by instead: see
  `Sovite.DKIM.Verifier` and `sign_fields/4`, with `Sovite.DKIM.Body`.

  Header fields are as returned by `Sovite.Message.Headers.parse/1`.
  Signing always uses `relaxed/relaxed` canonicalization.

  ## Telemetry

    * `[:sovite, :dkim, :verify]` - `%{count: signatures}`, `%{results:
      [result]}`, once per message verified.
  """

  alias Sovite.DKIM.{Body, Canon, Result, SigningKey, Verifier}
  alias Sovite.Message.Headers

  @default_headers ~w(from reply-to subject date message-id to cc in-reply-to references
                      mime-version content-type content-transfer-encoding content-disposition
                      content-id content-description content-language resent-date resent-from
                      resent-to resent-cc resent-message-id sender list-id list-help
                      list-unsubscribe list-unsubscribe-post list-subscribe list-post
                      list-owner list-archive autocrypt)

  @doc "The header fields signed by default, when present."
  @spec default_headers() :: [String.t()]
  def default_headers, do: @default_headers

  @doc """
  Verifies every `DKIM-Signature:` of `message` (header and body, CRLF
  line endings). Options are those of `Sovite.DKIM.Verifier.new/2`.
  """
  @spec verify(binary(), Sovite.DNS.resolver(), keyword()) :: [Result.t()]
  def verify(message, resolver, opts \\ []) do
    {fields, body} = split(message)
    verifier = Verifier.new(fields, opts)
    hashes = verifier |> Verifier.body_specs() |> Body.new() |> Body.update(body) |> Body.finish()
    Verifier.finish(verifier, hashes, resolver)
  end

  @doc """
  Signs `message` with each key, for dual signing (RSA and Ed25519).
  Returns the `DKIM-Signature:` fields to put at the top of the message,
  in the order of `keys`. Options are those of `sign_fields/4`.
  """
  @spec sign(binary(), [SigningKey.t()], keyword()) :: [String.t()]
  def sign(message, keys, opts \\ []) do
    {fields, body} = split(message)
    hashes = [body_spec()] |> Body.new() |> Body.update(body) |> Body.finish()
    {body_hash, _length} = hashes[body_spec()]
    Enum.map(keys, &sign_fields(fields, body_hash, &1, opts))
  end

  defp split(message) do
    case Headers.split(message) do
      {:ok, header, body} -> {Headers.parse(header), body}
      :more -> {Headers.parse(message), ""}
    end
  end

  @doc "The body hash `sign_fields/4` needs: relaxed, SHA-256, whole body."
  @spec body_spec() :: Body.spec()
  def body_spec, do: {:relaxed, :sha256, nil}

  @doc """
  Builds a signed `DKIM-Signature:` field (with CRLF) for header `fields`
  and the body hash for `body_spec/0`.

  ## Options

    * `:headers` - names of the fields to sign when present. Defaults to
      `default_headers/0`.
    * `:oversign` - names signed once more than they occur, so no
      instance can be added later. Defaults to `["from"]`.
    * `:timestamp` - Unix seconds for `t=`. Defaults to now.
    * `:expiration` - seconds after `t=` for `x=`. None by default.
    * `:identity` - the `i=` value. None by default.
  """
  @spec sign_fields([Headers.field()], binary(), SigningKey.t(), keyword()) :: String.t()
  def sign_fields(fields, body_hash, %SigningKey{} = key, opts \\ []) do
    names = signed_names(fields, opts)
    timestamp = Keyword.get_lazy(opts, :timestamp, fn -> System.os_time(:second) end)

    tags =
      [
        "v=1",
        "a=" <> SigningKey.algorithm_name(key),
        "c=relaxed/relaxed",
        "d=" <> key.domain,
        "s=" <> key.selector
      ] ++
        optional_tag("i", opts[:identity]) ++
        ["t=#{timestamp}"] ++
        optional_tag("x", opts[:expiration] && timestamp + opts[:expiration]) ++
        ["h=" <> Enum.join(names, ":"), "bh=" <> Base.encode64(body_hash)]

    signed_field("DKIM-Signature", tags, Canon.select(fields, names), key)
  end

  defp optional_tag(_name, nil), do: []
  defp optional_tag(name, value), do: ["#{name}=#{value}"]

  defp signed_names(fields, opts) do
    wanted = MapSet.new(Keyword.get(opts, :headers, @default_headers), &String.downcase/1)
    oversign = Enum.map(Keyword.get(opts, :oversign, ["from"]), &String.downcase/1)

    present = for {name, _raw} <- fields, name != nil, MapSet.member?(wanted, name), do: name
    present ++ Enum.filter(oversign, &MapSet.member?(wanted, &1))
  end

  @doc false
  # Builds a field from `tags` and signs it, with relaxed header
  # canonicalization, over the canonicalized `selected` fields and the
  # field itself. Also used for the ARC fields.
  @spec signed_field(String.t(), [String.t()], [String.t()], SigningKey.t()) :: String.t()
  def signed_field(name, tags, selected, key) do
    unsigned = name <> ": " <> fold(tags ++ ["b="])
    signature = SigningKey.sign(key, Canon.signed_data(selected, unsigned, :relaxed))
    unsigned <> fold_base64(Base.encode64(signature)) <> "\r\n"
  end

  # Tags are filled into lines; bh= and b= start lines of their own,
  # long h= lists are folded at colons.
  defp fold(tags) do
    [first | rest] =
      Enum.map(tags, fn
        "h=" <> names -> "h=" <> fold_names(names)
        tag -> tag
      end)

    Enum.reduce(rest, first, fn tag, acc ->
      line = acc |> String.split("\r\n") |> List.last()
      [tag_line | _] = String.split(tag, "\r\n")

      if String.starts_with?(tag, "b") or byte_size(line) + byte_size(tag_line) > 72,
        do: acc <> ";\r\n\t" <> tag,
        else: acc <> "; " <> tag
    end)
  end

  defp fold_names(names) do
    names
    |> String.split(":")
    |> Enum.chunk_every(8)
    |> Enum.map_join(":\r\n\t  ", &Enum.join(&1, ":"))
  end

  defp fold_base64(data) when byte_size(data) > 72,
    do:
      binary_part(data, 0, 72) <>
        "\r\n\t " <> fold_base64(binary_part(data, 72, byte_size(data) - 72))

  defp fold_base64(data), do: data
end
