defmodule Sovite.Message.Date do
  @moduledoc """
  RFC 5322 §3.3 date-time formatting, as used in `Date:` and `Received:`.
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
end
