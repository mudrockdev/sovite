defmodule Sovite.SMTP.DSNParams do
  @moduledoc """
  The parameters of the SMTP `DSN` extension (RFC 3461 §4): `NOTIFY` and
  `ORCPT` on `RCPT`, `RET` and `ENVID` on `MAIL`.

      iex> Sovite.SMTP.DSNParams.parse_notify("SUCCESS,FAILURE")
      {:ok, [:success, :failure]}
      iex> Sovite.SMTP.DSNParams.parse_orcpt("rfc822;bob+2Bwork@example.com")
      {:ok, {"rfc822", "bob+work@example.com"}}
      iex> Sovite.SMTP.DSNParams.encode_orcpt({"rfc822", "bob+work@example.com"})
      "rfc822;bob+2Bwork@example.com"

  `ENVID` and the address in `ORCPT` are xtext (`Sovite.SMTP.XText`).
  For internationalized addresses `ORCPT` has the `utf-8` address type
  (RFC 6533 §3), where characters are escaped as `\\x{HEX}` instead:
  `utf-8;j\\x{FC}rgen@example.com`. With `SMTPUTF8` the non-ASCII
  characters may also be sent as they are.

  Decoded values never contain control characters.
  """

  alias Sovite.SMTP.XText

  @typedoc """
  `NOTIFY`: `:never`, or when to send a notification. Without `NOTIFY`, a
  server sends failure and (at its choice) delay notifications.
  """
  @type notify :: :never | [:success | :failure | :delay, ...]

  @typedoc "`RET`: return the whole message in a failure notification, or only its headers."
  @type ret :: :full | :hdrs

  @typedoc """
  `ORCPT`: the address type, lower-cased (`"rfc822"`, `"utf-8"`, ...), and
  the decoded address, as the first client gave it.
  """
  @type orcpt :: {type :: String.t(), address :: String.t()}

  @notify %{"SUCCESS" => :success, "FAILURE" => :failure, "DELAY" => :delay}

  @max_envid 100
  @max_orcpt 500

  @doc "Parses a `NOTIFY` value: `NEVER`, or a comma-separated list."
  @spec parse_notify(String.t()) :: {:ok, notify()} | :error
  def parse_notify(value) when is_binary(value) do
    case value |> String.upcase(:ascii) |> String.split(",") do
      ["NEVER"] ->
        {:ok, :never}

      keywords ->
        if Enum.all?(keywords, &Map.has_key?(@notify, &1)) and
             length(Enum.uniq(keywords)) == length(keywords),
           do: {:ok, Enum.map(keywords, &Map.fetch!(@notify, &1))},
           else: :error
    end
  end

  @doc "Encodes a `NOTIFY` value."
  @spec encode_notify(notify()) :: String.t()
  def encode_notify(:never), do: "NEVER"

  def encode_notify([_ | _] = keywords),
    do: Enum.map_join(keywords, ",", &(&1 |> Atom.to_string() |> String.upcase()))

  @doc "Parses a `RET` value."
  @spec parse_ret(String.t()) :: {:ok, ret()} | :error
  def parse_ret(value) when is_binary(value) do
    case String.upcase(value, :ascii) do
      "FULL" -> {:ok, :full}
      "HDRS" -> {:ok, :hdrs}
      _ -> :error
    end
  end

  @doc "Encodes a `RET` value."
  @spec encode_ret(ret()) :: String.t()
  def encode_ret(:full), do: "FULL"
  def encode_ret(:hdrs), do: "HDRS"

  @doc "Parses an `ENVID` value, at most 100 characters of xtext."
  @spec parse_envid(String.t()) :: {:ok, String.t()} | :error
  def parse_envid(value) when is_binary(value) and byte_size(value) in 1..@max_envid do
    case XText.decode(value) do
      {:ok, envid} -> if ascii?(envid) and printable?(envid), do: {:ok, envid}, else: :error
      :error -> :error
    end
  end

  def parse_envid(_value), do: :error

  @doc "Encodes an `ENVID` value."
  @spec encode_envid(String.t()) :: String.t()
  def encode_envid(envid), do: XText.encode(envid)

  @doc """
  Parses an `ORCPT` value. Non-ASCII characters in a `utf-8` address are
  accepted only with `utf8: true`, in a transaction with `SMTPUTF8`.
  """
  @spec parse_orcpt(String.t(), keyword()) :: {:ok, orcpt()} | :error
  def parse_orcpt(value, opts \\ [])

  def parse_orcpt(value, opts) when is_binary(value) and byte_size(value) <= @max_orcpt do
    with [type, address] when address != "" <- :binary.split(value, ";"),
         true <- String.match?(type, ~r/\A[A-Za-z0-9!#$%&'*+\/?^_`{|}~-]+\z/),
         type = String.downcase(type, :ascii),
         {:ok, address} <- decode_address(type, address, Keyword.get(opts, :utf8, false)) do
      {:ok, {type, address}}
    else
      _ -> :error
    end
  end

  def parse_orcpt(_value, _opts), do: :error

  @doc """
  Encodes an `ORCPT` value. A `utf-8` address keeps its non-ASCII
  characters with `smtputf8: true`, and is escaped otherwise.
  """
  @spec encode_orcpt(orcpt(), keyword()) :: String.t()
  def encode_orcpt({type, address}, opts \\ []) do
    encoded =
      if type == "utf-8",
        do: encode_utf8(address, Keyword.get(opts, :smtputf8, false)),
        else: XText.encode(address)

    type <> ";" <> encoded
  end

  @doc """
  The `ORCPT` for an address: `rfc822` for an ASCII one, `utf-8` for an
  internationalized one.
  """
  @spec orcpt(String.t()) :: orcpt()
  def orcpt(address) do
    if ascii?(address), do: {"rfc822", address}, else: {"utf-8", address}
  end

  ## Address encodings

  defp decode_address("utf-8", address, utf8) do
    with true <- String.valid?(address),
         true <- utf8 or ascii?(address),
         {:ok, decoded} <- decode_utf8(address, []),
         true <- printable?(decoded) do
      {:ok, decoded}
    else
      _ -> :error
    end
  end

  defp decode_address(_type, address, _utf8) do
    case XText.decode(address) do
      {:ok, decoded} ->
        if ascii?(decoded) and printable?(decoded), do: {:ok, decoded}, else: :error

      :error ->
        :error
    end
  end

  # utf-8-addr-xtext and utf-8-addr-unitext (RFC 6533 §3): "\x{HEX}"
  # escapes; "+", "=", and "\" only escaped.
  defp decode_utf8(<<>>, acc), do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}

  defp decode_utf8(<<"\\x{", rest::binary>>, acc) do
    with [hex, rest] <- :binary.split(rest, "}"),
         true <- byte_size(hex) in 2..6 and String.match?(hex, ~r/\A[0-9A-Fa-f]+\z/),
         code = String.to_integer(hex, 16),
         true <- code <= 0x10FFFF and code not in 0xD800..0xDFFF do
      decode_utf8(rest, [<<code::utf8>> | acc])
    else
      _ -> :error
    end
  end

  defp decode_utf8(<<c::utf8, rest::binary>>, acc)
       when (c in 0x21..0x7E and c not in [?+, ?=, ?\\]) or c > 0x7F,
       do: decode_utf8(rest, [<<c::utf8>> | acc])

  defp decode_utf8(_value, _acc), do: :error

  defp encode_utf8(address, smtputf8) do
    for <<c::utf8 <- address>>, into: "" do
      cond do
        c in 0x21..0x7E and c not in [?+, ?=, ?\\] -> <<c>>
        c > 0x9F and smtputf8 -> <<c::utf8>>
        true -> "\\x{" <> hex(c) <> "}"
      end
    end
  end

  defp hex(code) do
    hex = Integer.to_string(code, 16)
    if byte_size(hex) < 2, do: "0" <> hex, else: hex
  end

  defp ascii?(value), do: for(<<c <- value>>, reduce: true, do: (acc -> acc and c < 128))

  defp printable?(value),
    do: for(<<c::utf8 <- value>>, reduce: true, do: (acc -> acc and (c in 32..126 or c > 0x9F)))
end
