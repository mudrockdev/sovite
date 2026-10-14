defmodule Sovite.SMTP.Params do
  @moduledoc """
  Values of the `MAIL` and `RCPT` parameters of these SMTP extensions:

    * `MT-PRIORITY=` (RFC 6710): a priority from -9 to 9.
    * `HOLDFOR=` and `HOLDUNTIL=` (`FUTURERELEASE`, RFC 4865): hold the
      message for some seconds, or until a time.
    * `BY=` (`DELIVERBY`, RFC 2852): deliver within some seconds, or
      return the message (`R`) or notify the sender (`N`).
    * `RRVS=` (RFC 7293): the recipient's mailbox must have had the
      same owner since a time; if the next hop cannot check that, return
      the message (`R`, the default) or continue (`C`).

  Times are RFC 3339 date-times (`2026-10-14T12:00:00Z`).

      iex> Sovite.SMTP.Params.parse_priority("-3")
      {:ok, -3}
      iex> Sovite.SMTP.Params.parse_by("120;RT")
      {:ok, %{time: 120, mode: :return, trace: true}}
      iex> Sovite.SMTP.Params.encode_by(%{time: 98, mode: :return, trace: false})
      "98;R"
  """

  @typedoc "`BY`: seconds left, and what to do when they run out."
  @type by :: %{time: integer(), mode: :return | :notify, trace: boolean()}

  @typedoc "`HOLDFOR` or `HOLDUNTIL`."
  @type hold :: {:for, pos_integer()} | {:until, DateTime.t()}

  @typedoc "`RRVS`: the time, and what to do at a next hop without `RRVS`."
  @type rrvs :: {DateTime.t(), :reject | :continue}

  @doc ~S'Parses an `MT-PRIORITY` value: `(["-"] NZDIGIT) / "0"`.'
  @spec parse_priority(String.t()) :: {:ok, -9..9} | :error
  def parse_priority("0"), do: {:ok, 0}
  def parse_priority(<<"-", d>>) when d in ?1..?9, do: {:ok, -(d - ?0)}
  def parse_priority(<<d>>) when d in ?1..?9, do: {:ok, d - ?0}
  def parse_priority(_value), do: :error

  @doc "Parses a `HOLDFOR` value: seconds, 1 to 999999999."
  @spec parse_holdfor(String.t()) :: {:ok, pos_integer()} | :error
  def parse_holdfor(value) do
    case seconds(value) do
      {:ok, seconds} when seconds > 0 -> {:ok, seconds}
      _ -> :error
    end
  end

  @doc "Parses a `HOLDUNTIL` value, an RFC 3339 date-time."
  @spec parse_holduntil(String.t()) :: {:ok, DateTime.t()} | :error
  def parse_holduntil(value), do: date_time(value)

  @doc "Formats a time for `HOLDUNTIL`, `RRVS`, and the `FUTURERELEASE` keyword, in UTC."
  @spec format_time(DateTime.t()) :: String.t()
  def format_time(time) do
    time |> DateTime.shift_zone!("Etc/UTC") |> DateTime.truncate(:second) |> DateTime.to_iso8601()
  end

  @doc "The release time of a `hold`, for a message received at `received_at`."
  @spec release_time(hold(), DateTime.t()) :: DateTime.t()
  def release_time({:for, seconds}, received_at), do: DateTime.add(received_at, seconds)
  def release_time({:until, time}, _received_at), do: time

  @doc "Formats a `hold` as in a DSN's `Future-Release-Request:` field (RFC 4865 §5)."
  @spec format_hold(hold()) :: String.t()
  def format_hold({:for, seconds}), do: "for;" <> Integer.to_string(seconds)
  def format_hold({:until, time}), do: "until;" <> format_time(time)

  @doc """
  Parses a `BY` value: `by-time;by-mode[T]`. With `R`, the time must be
  positive.
  """
  @spec parse_by(String.t()) :: {:ok, by()} | :error
  def parse_by(value) do
    with [time, mode] <- :binary.split(value, ";"),
         {:ok, time} <- signed_seconds(time),
         {:ok, mode, trace} <- by_mode(String.upcase(mode, :ascii)),
         true <- mode == :notify or time > 0 do
      {:ok, %{time: time, mode: mode, trace: trace}}
    else
      _ -> :error
    end
  end

  @doc "Encodes a `BY` value."
  @spec encode_by(by()) :: String.t()
  def encode_by(%{time: time, mode: mode, trace: trace}) do
    Integer.to_string(time) <>
      ";" <>
      if(mode == :return, do: "R", else: "N") <>
      if(trace, do: "T", else: "")
  end

  @doc "Parses an `RRVS` value: a date-time without fractions of a second, then `;R` or `;C`."
  @spec parse_rrvs(String.t()) :: {:ok, rrvs()} | :error
  def parse_rrvs(value) do
    {time, action} =
      case :binary.split(value, ";") do
        [time] -> {time, {:ok, :reject}}
        [time, action] -> {time, rrvs_action(String.upcase(action, :ascii))}
      end

    with false <- String.contains?(time, "."),
         {:ok, time} <- date_time(time),
         {:ok, action} <- action do
      {:ok, {time, action}}
    else
      _ -> :error
    end
  end

  @doc "Encodes an `RRVS` value."
  @spec encode_rrvs(rrvs()) :: String.t()
  def encode_rrvs({time, action}),
    do: format_time(time) <> if(action == :continue, do: ";C", else: ";R")

  defp rrvs_action("R"), do: {:ok, :reject}
  defp rrvs_action("C"), do: {:ok, :continue}
  defp rrvs_action(_action), do: :error

  defp by_mode("R"), do: {:ok, :return, false}
  defp by_mode("N"), do: {:ok, :notify, false}
  defp by_mode("RT"), do: {:ok, :return, true}
  defp by_mode("NT"), do: {:ok, :notify, true}
  defp by_mode(_mode), do: :error

  defp signed_seconds("-" <> digits) do
    with {:ok, seconds} <- seconds(digits), do: {:ok, -seconds}
  end

  defp signed_seconds("+" <> digits), do: seconds(digits)
  defp signed_seconds(digits), do: seconds(digits)

  defp seconds(digits) when byte_size(digits) in 1..9 do
    if String.match?(digits, ~r/\A[0-9]+\z/), do: {:ok, String.to_integer(digits)}, else: :error
  end

  defp seconds(_digits), do: :error

  defp date_time(value) when byte_size(value) <= 40 do
    with true <-
           String.match?(value, ~r/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)\z/),
         {:ok, time, _offset} <- DateTime.from_iso8601(value) do
      {:ok, time}
    else
      _ -> :error
    end
  end

  defp date_time(_value), do: :error
end
