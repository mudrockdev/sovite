defmodule Sovite.IDNA do
  @moduledoc """
  Internationalized domain names (IDNA2008, RFC 5890–5893): conversion
  between U-labels (`bücher.example`) and A-labels
  (`xn--bcher-kva.example`), and their validation.

      iex> Sovite.IDNA.to_ascii("Bücher.example")
      {:ok, "xn--bcher-kva.example"}
      iex> Sovite.IDNA.to_unicode("xn--bcher-kva.example")
      {:ok, "bücher.example"}
      iex> Sovite.IDNA.to_ascii("xn--bcher-kva.example")
      {:ok, "xn--bcher-kva.example"}

  `to_ascii/1` maps its input first, as RFC 5895 suggests for names
  people type: it is lower-cased, normalized to NFC, and the ideographic
  full stops (`。`, `．`, `｡`) separate labels like `.`. Every label must
  then be an LDH label (letters, digits, and hyphens), an A-label whose
  decoding is a valid U-label, or a valid U-label: only code points
  IDNA2008 allows (see `Sovite.IDNA.CodePoints`), in NFC, not starting
  with a combining mark, without `--` in the third and fourth positions,
  and following the contextual rules and, in domains with right-to-left
  labels, the Bidi rule. Results are lower-case.

  A-labels are at most 63 octets, and the whole name in A-labels at most
  253 octets. A trailing dot (the DNS root) is not accepted.
  """

  alias Sovite.IDNA.{CodePoints, Punycode}

  @typedoc "Why a name is not a valid IDNA2008 domain name."
  @type error ::
          :empty_label
          | :too_long
          | :invalid_ldh
          | :invalid_a_label
          | :hyphen
          | :leading_combining_mark
          | :disallowed
          | :context
          | :bidi
          | :not_nfc

  @max_label 63
  @max_name 253
  @dots ["。", "．", "｡"]

  @doc "Converts a domain name to A-labels."
  @spec to_ascii(String.t()) :: {:ok, String.t()} | {:error, error()}
  def to_ascii(name) when is_binary(name) do
    with {:ok, labels} <- labels(name),
         {:ok, a_labels} <- map_while(labels, &label_to_ascii/1),
         :ok <- check_bidi(labels) do
      ascii = Enum.join(a_labels, ".")
      if byte_size(ascii) <= @max_name, do: {:ok, ascii}, else: {:error, :too_long}
    end
  end

  def to_ascii(_name), do: {:error, :invalid_ldh}

  @doc "Converts a domain name to U-labels, checking it as `to_ascii/1` does."
  @spec to_unicode(String.t()) :: {:ok, String.t()} | {:error, error()}
  def to_unicode(name) when is_binary(name) do
    with {:ok, ascii} <- to_ascii(name) do
      ascii
      |> String.split(".")
      |> Enum.map_join(".", fn
        "xn--" <> encoded ->
          {:ok, label} = Punycode.decode(encoded)
          label

        label ->
          label
      end)
      |> then(&{:ok, &1})
    end
  end

  def to_unicode(_name), do: {:error, :invalid_ldh}

  @doc """
  Whether `name` is a valid domain name in either form.

      iex> Sovite.IDNA.valid?("münchen.example")
      true
      iex> Sovite.IDNA.valid?("a b.example")
      false
  """
  @spec valid?(term()) :: boolean()
  def valid?(name), do: match?({:ok, _}, to_ascii(name))

  @doc """
  Whether `name` has A-labels or non-ASCII characters, so it is
  internationalized.
  """
  @spec international?(String.t()) :: boolean()
  def international?(name) when is_binary(name) do
    not ascii?(name) or
      name
      |> String.downcase(:ascii)
      |> String.split(".")
      |> Enum.any?(&String.starts_with?(&1, "xn--"))
  end

  ## Labels

  # RFC 5895 mapping: lower case, NFC, and other full stops.
  defp labels(name) do
    mapped = name |> String.replace(@dots, ".") |> String.downcase() |> String.normalize(:nfc)

    cond do
      not String.valid?(name) -> {:error, :disallowed}
      mapped == "" -> {:error, :empty_label}
      true -> {:ok, String.split(mapped, ".")}
    end
  end

  defp label_to_ascii(""), do: {:error, :empty_label}

  defp label_to_ascii(label) do
    cond do
      not ascii?(label) -> u_label_to_ascii(label)
      String.starts_with?(label, "xn--") -> a_label(label)
      true -> ldh_label(label)
    end
  end

  defp ldh_label(label) do
    cond do
      byte_size(label) > @max_label -> {:error, :too_long}
      not String.match?(label, ~r/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/) -> {:error, :invalid_ldh}
      true -> {:ok, label}
    end
  end

  # An A-label must decode to a valid U-label that encodes back to it.
  defp a_label("xn--" <> encoded = label) do
    with true <- byte_size(label) <= @max_label,
         {:ok, unicode} <- Punycode.decode(encoded),
         false <- ascii?(unicode),
         {:ok, ^label} <- u_label_to_ascii(unicode) do
      {:ok, label}
    else
      _ -> {:error, :invalid_a_label}
    end
  end

  defp u_label_to_ascii(label) do
    code_points = String.to_charlist(label)

    with :ok <- check_nfc(label),
         :ok <- check_hyphens(label),
         :ok <- check_first(code_points),
         :ok <- check_code_points(code_points),
         {:ok, encoded} <- Punycode.encode(label),
         a_label = "xn--" <> encoded,
         true <- byte_size(a_label) <= @max_label do
      {:ok, a_label}
    else
      false -> {:error, :too_long}
      :error -> {:error, :disallowed}
      {:error, _} = error -> error
    end
  end

  defp check_nfc(label),
    do: if(String.normalize(label, :nfc) == label, do: :ok, else: {:error, :not_nfc})

  # RFC 5891 §4.2.3.1.
  defp check_hyphens(label) do
    cond do
      String.starts_with?(label, "-") or String.ends_with?(label, "-") -> {:error, :hyphen}
      String.slice(label, 2, 2) == "--" -> {:error, :hyphen}
      true -> :ok
    end
  end

  # RFC 5891 §4.2.3.2.
  defp check_first([first | _]) do
    if CodePoints.combining_mark?(first), do: {:error, :leading_combining_mark}, else: :ok
  end

  defp check_code_points(code_points) do
    code_points
    |> Enum.with_index()
    |> Enum.reduce_while(:ok, fn {cp, index}, :ok ->
      case CodePoints.property(cp) do
        :pvalid -> {:cont, :ok}
        context when context in [:contextj, :contexto] -> context(code_points, index)
        _ -> {:halt, {:error, :disallowed}}
      end
    end)
  end

  defp context(code_points, index) do
    if CodePoints.context?(code_points, index),
      do: {:cont, :ok},
      else: {:halt, {:error, :context}}
  end

  # RFC 5893 §1.4: in a domain with a right-to-left label, every label
  # must satisfy the Bidi rule.
  defp check_bidi(labels) do
    code_points =
      for label <- labels do
        case label do
          "xn--" <> encoded ->
            {:ok, unicode} = Punycode.decode(encoded)
            String.to_charlist(unicode)

          label ->
            String.to_charlist(label)
        end
      end

    cond do
      not Enum.any?(code_points, &CodePoints.rtl?/1) -> :ok
      Enum.all?(code_points, &CodePoints.bidi?/1) -> :ok
      true -> {:error, :bidi}
    end
  end

  defp map_while(list, fun) do
    list
    |> Enum.reduce_while({:ok, []}, fn item, {:ok, acc} ->
      case fun.(item) do
        {:ok, value} -> {:cont, {:ok, [value | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      error -> error
    end
  end

  defp ascii?(binary), do: for(<<c <- binary>>, reduce: true, do: (acc -> acc and c < 0x80))
end
