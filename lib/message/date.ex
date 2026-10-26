defmodule Sovite.Message.Date do
  @moduledoc """
  RFC 5322 §3.3 date-times, as in `Date:` and `Received:`: formatting,
  and parsing, with the obsolete forms of §4.3.
  """

  @days ~w(Mon Tue Wed Thu Fri Sat Sun)
  @months ~w(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)

  @doc """
  Formats `datetime` with its UTC offset.

      iex> Sovite.Message.Date.format(~U[2026-10-04 12:00:00Z])
      "Sun, 4 Oct 2026 12:00:00 +0000"
  """
  @spec format(DateTime.t()) :: String.t()
  def format(%DateTime{} = datetime) do
    day = Enum.at(@days, Date.day_of_week(datetime) - 1)
    month = Enum.at(@months, datetime.month - 1)
    time = datetime |> DateTime.to_time() |> Time.truncate(:second) |> Time.to_string()

    "#{day}, #{datetime.day} #{month} #{datetime.year} #{time} #{offset(datetime)}"
  end

  defp offset(%DateTime{utc_offset: utc, std_offset: std}) do
    total = div(utc + std, 60)
    sign = if total < 0, do: "-", else: "+"
    hours = total |> abs() |> div(60) |> Integer.to_string() |> String.pad_leading(2, "0")
    minutes = total |> abs() |> rem(60) |> Integer.to_string() |> String.pad_leading(2, "0")
    sign <> hours <> minutes
  end

  # Obsolete zones (RFC 5322 §4.3): military letters and others are
  # taken as -0000, an unknown offset.
  @zones %{
    "UT" => 0,
    "GMT" => 0,
    "UTC" => 0,
    "Z" => 0,
    "EST" => -300,
    "EDT" => -240,
    "CST" => -360,
    "CDT" => -300,
    "MST" => -420,
    "MDT" => -360,
    "PST" => -480,
    "PDT" => -420
  }

  @date ~r/\A(?:[A-Za-z]{3}\s*,\s*)?(\d{1,2})\s+([A-Za-z]{3})\s+(\d{2,4})\s+(\d{1,2})\s*:\s*(\d{2})(?:\s*:\s*(\d{2}))?\s*([+-]\d{4}|[A-Za-z]{1,5})?\s*\z/

  @doc """
  Parses a date-time, as in a `Date:` field. Comments, two- and
  three-digit years, and obsolete zone names are read as RFC 5322 §4.3
  says; the day of the week, when given, is not checked.

      iex> Sovite.Message.Date.parse("Sun, 4 Oct 2026 15:00:00 +0300 (EEST)")
      {:ok, ~U[2026-10-04 12:00:00Z]}
      iex> Sovite.Message.Date.parse("4 Oct 26 12:00 PDT")
      {:ok, ~U[2026-10-04 19:00:00Z]}
      iex> Sovite.Message.Date.parse("yesterday")
      :error
  """
  @spec parse(String.t()) :: {:ok, DateTime.t()} | :error
  def parse(value) when is_binary(value) do
    text = value |> uncomment() |> String.trim()

    with [_, day, month, year, hour, minute | rest] <- Regex.run(@date, text),
         month when month != nil <- Enum.find_index(@months, &(&1 == String.capitalize(month))),
         {:ok, date} <- Date.new(year(year), month + 1, String.to_integer(day)),
         {:ok, time} <- Time.new(String.to_integer(hour), String.to_integer(minute), second(rest)),
         {:ok, offset} <- zone(Enum.at(rest, 1, "")) do
      {:ok, datetime} = DateTime.new(date, time, "Etc/UTC")
      {:ok, DateTime.add(datetime, -offset, :minute)}
    else
      _ -> :error
    end
  end

  defp year(text) do
    year = String.to_integer(text)

    cond do
      byte_size(text) == 4 -> year
      byte_size(text) == 3 -> year + 1900
      year < 50 -> year + 2000
      true -> year + 1900
    end
  end

  # 60 is a leap second: taken as 59.
  defp second([]), do: 0
  defp second(["" | _]), do: 0
  defp second([second | _]), do: min(String.to_integer(second), 59)

  defp zone(""), do: {:ok, 0}

  defp zone(<<sign, hours::binary-2, minutes::binary-2>>) when sign in [?+, ?-] do
    with {h, ""} <- Integer.parse(hours),
         {m, ""} <- Integer.parse(minutes),
         true <- m < 60 do
      offset = h * 60 + m
      {:ok, if(sign == ?-, do: -offset, else: offset)}
    else
      _ -> :error
    end
  end

  defp zone(name), do: {:ok, Map.get(@zones, String.upcase(name), 0)}

  # Comments nest: the innermost go first.
  defp uncomment(text) do
    case Regex.replace(~r/\([^()]*\)/, text, " ") do
      ^text -> text
      shorter -> uncomment(shorter)
    end
  end
end
