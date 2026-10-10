defmodule Sovite.DMARC.Record do
  @moduledoc """
  A DMARC policy record (RFC 7489 §6.3), as published in TXT at
  `_dmarc.<domain>`.

      {:ok, record} = Sovite.DMARC.Record.parse("v=DMARC1; p=reject; rua=mailto:d@example.com")
      record.p   #=> :reject
      record.sp  #=> :reject

  Parsing is lenient, as RFC 7489 §6.3 asks: unknown tags are ignored,
  and a known tag with an invalid value gets its default. After a
  successful parse no field is `nil` except `psd`:

    * `sp` defaults to `p`, and `np` (DMARCbis) to `sp`.
    * `rua` and `ruf` keep only `mailto:` URIs, each with the size limit
      from a `!size` suffix (RFC 7489 §6.4), or `nil`.
    * `testing` is the DMARCbis `t=y` flag, and `psd` the DMARCbis
      `psd=` tag: `:yes`, `:no`, or `nil` for `u` or absent.
  """

  defstruct [
    :p,
    :sp,
    :np,
    adkim: :relaxed,
    aspf: :relaxed,
    pct: 100,
    rua: [],
    ruf: [],
    fo: "0",
    ri: 86_400,
    testing: false,
    psd: nil
  ]

  @typedoc "A requested policy for failing mail."
  @type policy :: :none | :quarantine | :reject

  @typedoc "An identifier alignment mode."
  @type mode :: :relaxed | :strict

  @typedoc "A report destination and the largest report it accepts, in bytes."
  @type uri :: %{uri: String.t(), max_size: non_neg_integer() | nil}

  @type t :: %__MODULE__{
          p: policy(),
          sp: policy(),
          np: policy(),
          adkim: mode(),
          aspf: mode(),
          pct: 0..100,
          rua: [uri()],
          ruf: [uri()],
          fo: String.t(),
          ri: non_neg_integer(),
          testing: boolean(),
          psd: :yes | :no | nil
        }

  @policies %{"none" => :none, "quarantine" => :quarantine, "reject" => :reject}
  @modes %{"r" => :relaxed, "s" => :strict}
  @psd %{"y" => :yes, "n" => :no, "u" => nil}
  @testing %{"y" => true, "n" => false}
  @units %{"" => 1, "k" => 1024, "m" => 1024 ** 2, "g" => 1024 ** 3, "t" => 1024 ** 4}

  @doc """
  Returns whether a TXT record claims to be a DMARC record: its first
  tag is `v=DMARC1`. Records that do not are discarded during policy
  discovery.
  """
  @spec dmarc?(String.t()) :: boolean()
  def dmarc?(text), do: String.match?(text, ~r/\A[ \t]*v[ \t]*=[ \t]*DMARC1[ \t]*(;|\z)/)

  @doc """
  Parses a DMARC record.

  Fails if `v=DMARC1` is not the first tag, or if `p` is missing or
  invalid and there is no valid `rua` (RFC 7489 §6.6.3; with a valid
  `rua`, `p` is taken as `none`).
  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, String.t()}
  def parse(text) do
    if dmarc?(text) do
      text |> tags() |> build()
    else
      {:error, "not a DMARC record (v=DMARC1 must come first)"}
    end
  end

  # Tag names are matched case-insensitively. The first of a repeated
  # tag wins.
  defp tags(text) do
    text
    |> String.split(";")
    |> Enum.drop(1)
    |> Enum.flat_map(fn tag ->
      case :binary.split(tag, "=") do
        [name, value] -> [{name |> String.trim() |> String.downcase(:ascii), String.trim(value)}]
        [_] -> []
      end
    end)
    |> Enum.reverse()
    |> Map.new()
  end

  defp build(tags) do
    rua = uris(tags["rua"])

    case {lookup(@policies, tags["p"]), rua} do
      {:error, []} ->
        {:error, "missing or invalid p= tag"}

      {p, _} ->
        p = if p == :error, do: :none, else: p
        sp = default(lookup(@policies, tags["sp"]), p)

        {:ok,
         %__MODULE__{
           p: p,
           sp: sp,
           np: default(lookup(@policies, tags["np"]), sp),
           adkim: default(lookup(@modes, tags["adkim"]), :relaxed),
           aspf: default(lookup(@modes, tags["aspf"]), :relaxed),
           pct: pct(tags["pct"]),
           rua: rua,
           ruf: uris(tags["ruf"]),
           fo: fo(tags["fo"]),
           ri: default(integer(tags["ri"]), 86_400),
           testing: default(lookup(@testing, tags["t"]), false),
           psd: default(lookup(@psd, tags["psd"]), nil)
         }}
    end
  end

  defp lookup(_table, nil), do: :error
  defp lookup(table, value), do: Map.get(table, String.downcase(value, :ascii), :error)

  defp default(:error, default), do: default
  defp default(value, _default), do: value

  defp integer(nil), do: :error

  defp integer(value) do
    case Integer.parse(value) do
      {n, ""} when n >= 0 -> n
      _ -> :error
    end
  end

  defp pct(value) do
    case value && Integer.parse(value) do
      {n, ""} -> n |> max(0) |> min(100)
      _ -> 100
    end
  end

  # fo = 0 / 1 / d / s, joined with ":".
  defp fo(nil), do: "0"

  defp fo(value) do
    options = value |> String.split(":") |> Enum.map(&String.trim/1)
    if Enum.all?(options, &(&1 in ["0", "1", "d", "s"])), do: Enum.join(options, ":"), else: "0"
  end

  defp uris(nil), do: []

  defp uris(value) do
    value
    |> String.split(",")
    |> Enum.flat_map(fn uri ->
      case uri(String.trim(uri)) do
        {:ok, uri} -> [uri]
        :error -> []
      end
    end)
  end

  # A "!" cannot appear unencoded in a URI, so the last one starts the
  # size limit.
  defp uri(text) do
    {uri, size} =
      case String.split(text, "!") do
        [uri] -> {uri, nil}
        parts -> {parts |> Enum.drop(-1) |> Enum.join("!"), List.last(parts)}
      end

    with true <- mailto?(uri),
         {:ok, max_size} <- max_size(size) do
      {:ok, %{uri: uri, max_size: max_size}}
    else
      _ -> :error
    end
  end

  defp mailto?(uri) do
    case uri do
      <<scheme::binary-size(7), address::binary>> when address != "" ->
        String.downcase(scheme, :ascii) == "mailto:"

      _ ->
        false
    end
  end

  defp max_size(nil), do: {:ok, nil}

  defp max_size(size) do
    case Regex.run(~r/\A([0-9]+)([kmgtKMGT]?)\z/, size) do
      [_, digits, unit] -> {:ok, String.to_integer(digits) * @units[String.downcase(unit)]}
      nil -> :error
    end
  end
end
