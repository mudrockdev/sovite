defmodule Sovite.SMTP.ParamsTest do
  use ExUnit.Case, async: true

  alias Sovite.SMTP.Params

  doctest Params

  test "MT-PRIORITY" do
    for {value, priority} <- [{"0", 0}, {"9", 9}, {"-9", -9}, {"1", 1}],
        do: assert(Params.parse_priority(value) == {:ok, priority})

    for value <- ["-0", "+3", "10", "-10", "", "a", "03"],
        do: assert(Params.parse_priority(value) == :error, value)
  end

  test "HOLDFOR and HOLDUNTIL" do
    assert Params.parse_holdfor("3600") == {:ok, 3600}
    assert Params.parse_holdfor("0") == :error
    assert Params.parse_holdfor("1234567890") == :error
    assert Params.parse_holdfor("-5") == :error

    assert Params.parse_holduntil("2026-10-20T12:00:00Z") == {:ok, ~U[2026-10-20 12:00:00Z]}
    assert Params.parse_holduntil("2026-10-20T14:00:00+02:00") == {:ok, ~U[2026-10-20 12:00:00Z]}
    assert Params.parse_holduntil("2026-10-20 12:00:00Z") == :error
    assert Params.parse_holduntil("2026-10-20T12:00:00") == :error
    assert Params.parse_holduntil("tomorrow") == :error

    assert Params.format_time(~U[2026-10-20 12:00:00.123Z]) == "2026-10-20T12:00:00Z"
    assert Params.format_hold({:for, 60}) == "for;60"
    assert Params.format_hold({:until, ~U[2026-10-20 12:00:00Z]}) == "until;2026-10-20T12:00:00Z"
    assert Params.release_time({:for, 60}, ~U[2026-10-20 12:00:00Z]) == ~U[2026-10-20 12:01:00Z]
  end

  test "BY" do
    assert Params.parse_by("120;R") == {:ok, %{time: 120, mode: :return, trace: false}}
    assert Params.parse_by("-60;N") == {:ok, %{time: -60, mode: :notify, trace: false}}
    assert Params.parse_by("+60;nt") == {:ok, %{time: 60, mode: :notify, trace: true}}
    assert Params.parse_by("0;N") == {:ok, %{time: 0, mode: :notify, trace: false}}

    for value <- ["0;R", "-1;R", "60", "60;X", "60;RN", "1234567890;R", ";R", "a;R"],
        do: assert(Params.parse_by(value) == :error, value)

    assert Params.encode_by(%{time: -5, mode: :notify, trace: true}) == "-5;NT"
  end

  test "RRVS" do
    assert Params.parse_rrvs("2014-04-03T23:01:00Z") == {:ok, {~U[2014-04-03 23:01:00Z], :reject}}

    assert Params.parse_rrvs("2014-04-03T23:01:00-07:00;C") ==
             {:ok, {~U[2014-04-04 06:01:00Z], :continue}}

    assert Params.parse_rrvs("2014-04-03T23:01:00Z;r") ==
             {:ok, {~U[2014-04-03 23:01:00Z], :reject}}

    assert Params.parse_rrvs("2014-04-03T23:01:00.5Z") == :error
    assert Params.parse_rrvs("2014-04-03T23:01:00Z;X") == :error
    assert Params.parse_rrvs("yesterday") == :error
    assert Params.encode_rrvs({~U[2014-04-03 23:01:00Z], :continue}) == "2014-04-03T23:01:00Z;C"
  end
end
