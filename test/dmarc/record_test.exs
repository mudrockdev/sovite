defmodule Sovite.DMARC.RecordTest do
  use ExUnit.Case, async: true

  alias Sovite.DMARC.Record

  defp parse!(text) do
    {:ok, record} = Record.parse(text)
    record
  end

  test "parses every tag" do
    record =
      parse!(
        "v=DMARC1; p=reject; sp=quarantine; np=none; adkim=s; aspf=s; pct=50; " <>
          "rua=mailto:agg@example.com; ruf=mailto:forensic@example.com; fo=1:d; ri=3600; " <>
          "t=y; psd=n"
      )

    assert record == %Record{
             p: :reject,
             sp: :quarantine,
             np: :none,
             adkim: :strict,
             aspf: :strict,
             pct: 50,
             rua: [%{uri: "mailto:agg@example.com", max_size: nil}],
             ruf: [%{uri: "mailto:forensic@example.com", max_size: nil}],
             fo: "1:d",
             ri: 3600,
             testing: true,
             psd: :no
           }
  end

  test "fills in defaults, with sp from p and np from sp" do
    assert parse!("v=DMARC1; p=quarantine") == %Record{
             p: :quarantine,
             sp: :quarantine,
             np: :quarantine
           }

    assert %Record{p: :none, sp: :reject, np: :reject} = parse!("v=DMARC1; p=none; sp=reject")
  end

  test "allows whitespace, case differences, and an empty last tag" do
    assert %Record{p: :reject, adkim: :strict} =
             parse!("  v = DMARC1 ;P = Reject;  adkim=S ;")

    assert %Record{p: :reject} = parse!("v=DMARC1;p=reject")
  end

  test "requires v=DMARC1 first" do
    assert {:error, _} = Record.parse("p=reject; v=DMARC1")
    assert {:error, _} = Record.parse("v=DMARC2; p=reject")
    assert {:error, _} = Record.parse("v=dmarc1; p=reject")
    assert {:error, _} = Record.parse("v=DMARC10; p=reject")
    assert {:error, _} = Record.parse("v=spf1 -all")
    assert {:error, _} = Record.parse("")
  end

  test "takes p=none for a missing or invalid p with a valid rua" do
    assert %Record{p: :none, sp: :none, np: :none} = parse!("v=DMARC1; rua=mailto:d@example.com")
    assert %Record{p: :none} = parse!("v=DMARC1; p=bogus; rua=mailto:d@example.com")

    assert {:error, _} = Record.parse("v=DMARC1")
    assert {:error, _} = Record.parse("v=DMARC1; p=bogus")
    assert {:error, _} = Record.parse("v=DMARC1; rua=https://example.com/reports")
  end

  test "uses defaults for invalid values" do
    record =
      parse!(
        "v=DMARC1; p=reject; sp=x; np=y; adkim=x; aspf=; pct=many; fo=2; ri=-1; t=maybe; psd=x"
      )

    assert record == %Record{p: :reject, sp: :reject, np: :reject}
  end

  test "clamps pct to 0..100" do
    assert parse!("v=DMARC1; p=reject; pct=150").pct == 100
    assert parse!("v=DMARC1; p=reject; pct=-5").pct == 0
    assert parse!("v=DMARC1; p=reject; pct=0").pct == 0
    assert parse!("v=DMARC1; p=reject; pct=5.5").pct == 100
  end

  test "reads psd and t" do
    assert parse!("v=DMARC1; p=none; psd=y").psd == :yes
    assert parse!("v=DMARC1; p=none; psd=n").psd == :no
    assert parse!("v=DMARC1; p=none; psd=u").psd == nil
    assert parse!("v=DMARC1; p=none; t=n").testing == false
  end

  test "ignores unknown and malformed tags, and keeps the first of repeated tags" do
    assert parse!("v=DMARC1; p=reject; x-future=1; garbage; p=none") ==
             %Record{p: :reject, sp: :reject, np: :reject}
  end

  test "reads report URIs with size limits, keeping only mailto: URIs" do
    record =
      parse!(
        "v=DMARC1; p=none; rua=mailto:a@example.com!10m, https://example.com/r, " <>
          "MAILTO:b@example.com!512 ,mailto:c@example.com!1K,mailto:d@example.com!2g," <>
          "mailto:e@example.com!1t,mailto:f@example.com!big,mailto:,mailto:g@example.com!5x"
      )

    assert record.rua == [
             %{uri: "mailto:a@example.com", max_size: 10 * 1024 * 1024},
             %{uri: "MAILTO:b@example.com", max_size: 512},
             %{uri: "mailto:c@example.com", max_size: 1024},
             %{uri: "mailto:d@example.com", max_size: 2 * 1024 ** 3},
             %{uri: "mailto:e@example.com", max_size: 1024 ** 4}
           ]
  end

  test "dmarc?/1 checks only the version tag" do
    assert Record.dmarc?("v=DMARC1; p=reject")
    assert Record.dmarc?("v=DMARC1")
    assert Record.dmarc?(" v = DMARC1 ; bogus")
    refute Record.dmarc?("v=DMARC1x")
    refute Record.dmarc?("p=reject; v=DMARC1")
  end
end
