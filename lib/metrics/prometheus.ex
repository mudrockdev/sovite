defmodule Sovite.Metrics.Prometheus do
  @moduledoc """
  Encodes metric families, as `Sovite.Metrics.collect/1` returns them, in
  the Prometheus text exposition format, version 0.0.4.

  Serve the result with `content_type/0` as the `Content-Type`.
  """

  alias Sovite.Metrics.Label

  @doc """
  Encodes `families` as iodata.

  Each family gets a `# HELP` line, unless it has no help text, and a
  `# TYPE` line, then its samples. Histograms get a `_bucket` sample for
  each bound, plus `le="+Inf"` with the count, and `_sum` and `_count`
  samples. Labels are written sorted by name. When families share a name,
  only the first is written.

      iex> Sovite.Metrics.Prometheus.format([
      ...>   %{name: "mails_total", type: :counter, help: "Mails received.",
      ...>     samples: [{%{"queue" => "incoming"}, 3}]}
      ...> ]) |> IO.iodata_to_binary()
      ~S'''
      # HELP mails_total Mails received.
      # TYPE mails_total counter
      mails_total{queue="incoming"} 3
      '''
  """
  @spec format([Sovite.Metrics.family()]) :: iodata()
  def format(families),
    do: families |> Enum.uniq_by(& &1.name) |> Enum.map(&family/1)

  @doc "Returns the `Content-Type` of the format."
  @spec content_type() :: String.t()
  def content_type, do: "text/plain; version=0.0.4; charset=utf-8"

  defp family(%{name: name, type: type, samples: samples} = family)
       when type in [:counter, :gauge, :histogram] do
    [
      help(name, Map.get(family, :help)),
      ["# TYPE ", name, " ", Atom.to_string(type), "\n"]
      | Enum.map(samples, &sample(name, type, &1))
    ]
  end

  defp help(_name, nil), do: []
  defp help(name, text), do: ["# HELP ", name, " ", escape_help(text), "\n"]

  defp sample(name, :histogram, {labels, %{buckets: buckets, sum: sum, count: count}}) do
    labels = sorted(labels)

    [
      for {bound, n} <- buckets, bound != :infinity do
        line([name, "_bucket"], labels ++ [{"le", number(bound)}], n)
      end,
      line([name, "_bucket"], labels ++ [{"le", "+Inf"}], count),
      line([name, "_sum"], labels, sum),
      line([name, "_count"], labels, count)
    ]
  end

  defp sample(name, _type, {labels, value}), do: line(name, sorted(labels), value)

  defp sorted(labels) do
    labels
    |> Enum.map(fn {key, value} -> {Label.value(key), Label.value(value)} end)
    |> Enum.sort()
  end

  defp line(name, labels, value), do: [name, labels(labels), " ", number(value), "\n"]

  defp labels([]), do: []

  defp labels(labels) do
    pairs = Enum.map(labels, fn {key, value} -> [key, "=\"", escape_label(value), "\""] end)
    ["{", Enum.intersperse(pairs, ","), "}"]
  end

  defp number(n) when is_integer(n), do: Integer.to_string(n)
  defp number(n) when is_float(n), do: :erlang.float_to_binary(n, [:short])
  defp number(:infinity), do: "+Inf"
  defp number(:neg_infinity), do: "-Inf"
  defp number(:nan), do: "NaN"

  defp escape_help(text), do: String.replace(text, ["\\", "\n"], &escape/1)
  defp escape_label(text), do: String.replace(text, ["\\", "\n", "\""], &escape/1)

  defp escape("\\"), do: "\\\\"
  defp escape("\n"), do: "\\n"
  defp escape("\""), do: "\\\""
end
