defmodule Sovite.Core.Logging.JSONFormatter do
  @moduledoc """
  `:logger` formatter that writes one JSON object per line.

      {"time":"2026-10-04T12:00:00.000000Z","level":"info","msg":"...","queue_id":"..."}

  ## Config

    * `:metadata` - metadata keys to include, or `:all`. Defaults to `[]`.
  """

  # Internal logger metadata that adds noise to `metadata: :all` output.
  @internal_keys [:time, :gl, :report_cb, :domain, :error_logger, :logger_formatter]

  @doc false
  def check_config(config) when is_map(config), do: :ok
  def check_config(config), do: {:error, {:invalid_formatter_config, config}}

  @doc false
  def format(%{level: level, msg: msg, meta: meta}, config) do
    fields =
      meta
      |> select_metadata(Map.get(config, :metadata, []))
      |> Map.new(fn {key, value} -> {Atom.to_string(key), json_value(value)} end)
      |> Map.merge(%{
        "time" => format_time(meta),
        "level" => Atom.to_string(level),
        "msg" => render_message(msg, meta)
      })

    [JSON.encode!(fields), ?\n]
  rescue
    # A formatter crash would remove the handler, so fall back to a plain line.
    error -> ["log formatting failed: ", Exception.message(error), ?\n]
  end

  defp select_metadata(meta, :all), do: Map.drop(meta, @internal_keys)
  defp select_metadata(meta, keys), do: Map.take(meta, keys)

  defp format_time(%{time: time}),
    do:
      time
      |> :calendar.system_time_to_rfc3339(unit: :microsecond, offset: ~c"Z")
      |> List.to_string()

  defp format_time(_meta), do: nil

  defp render_message({:string, chardata}, _meta), do: to_utf8(chardata)

  defp render_message({:report, report}, %{report_cb: callback}) when is_function(callback, 1) do
    {format, args} = callback.(report)
    format |> :io_lib.format(args) |> to_utf8()
  end

  defp render_message({:report, report}, %{report_cb: callback}) when is_function(callback, 2) do
    report
    |> callback.(%{depth: :unlimited, chars_limit: :unlimited, single_line: true})
    |> to_utf8()
  end

  defp render_message({:report, report}, _meta), do: inspect(report)
  defp render_message({format, args}, _meta), do: format |> :io_lib.format(args) |> to_utf8()

  defp to_utf8(chardata) do
    case :unicode.characters_to_binary(chardata) do
      binary when is_binary(binary) -> binary
      _ -> inspect(chardata)
    end
  end

  defp json_value(value) when is_binary(value) do
    if String.valid?(value), do: value, else: inspect(value)
  end

  defp json_value(value) when is_number(value) or is_boolean(value) or is_nil(value), do: value
  defp json_value(value) when is_atom(value), do: Atom.to_string(value)

  defp json_value(value) when is_tuple(value) and tuple_size(value) in [4, 8] do
    case :inet.ntoa(value) do
      {:error, _} -> inspect(value)
      address -> List.to_string(address)
    end
  end

  defp json_value(value), do: inspect(value)
end
