defmodule Sovite.Policy.ActionTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.Policy.Action

  doctest Sovite.Policy.Action

  describe "parse/1" do
    test "OK, DUNNO, and all-numerical results" do
      assert Action.parse("OK") == {:ok, :ok}
      assert Action.parse("ok") == {:ok, :ok}
      assert Action.parse("Ok whatever") == {:ok, :ok}
      assert Action.parse("DUNNO") == {:ok, :dunno}
      assert Action.parse("  dunno\t") == {:ok, :dunno}
      assert Action.parse("1730000000") == {:ok, :ok}
      assert Action.parse("250") == {:ok, :ok}
      assert Action.parse("600") == {:ok, :ok}
    end

    test "actions with an optional text" do
      for {word, kind} <- [
            {"REJECT", :reject},
            {"DEFER", :defer},
            {"DEFER_IF_REJECT", :defer_if_reject},
            {"DEFER_IF_PERMIT", :defer_if_permit},
            {"HOLD", :hold},
            {"DISCARD", :discard},
            {"WARN", :warn},
            {"INFO", :info}
          ] do
        assert Action.parse(word) == {:ok, {kind, nil}}
        assert Action.parse(String.downcase(word) <> "   ") == {:ok, {kind, nil}}
        assert Action.parse(word <> " Some  text here") == {:ok, {kind, "Some  text here"}}
        assert Action.parse(word <> "\tTabbed") == {:ok, {kind, "Tabbed"}}
      end

      assert Action.parse("REJECT 5.7.1 Go away") == {:ok, {:reject, "5.7.1 Go away"}}

      assert Action.parse("defer_if_permit Service temporarily unavailable") ==
               {:ok, {:defer_if_permit, "Service temporarily unavailable"}}
    end

    test "numeric replies" do
      assert Action.parse("550 5.7.23 SPF fail") == {:ok, {:reply, 550, "5.7.23", "SPF fail"}}
      assert Action.parse("450 4.7.1 Try later") == {:ok, {:reply, 450, "4.7.1", "Try later"}}
      assert Action.parse("554 Go away now") == {:ok, {:reply, 554, nil, "Go away now"}}
      assert Action.parse("421 4.3.2") == {:ok, {:reply, 421, "4.3.2", nil}}
      assert Action.parse("550") == {:ok, {:reply, 550, nil, nil}}
      assert Action.parse("599 5.999.999 x") == {:ok, {:reply, 599, "5.999.999", "x"}}
      assert Action.parse("450 version 1.2 text") == {:ok, {:reply, 450, nil, "version 1.2 text"}}
    end

    test "malformed numeric replies" do
      for action <- [
            "550 4.7.1 class mismatch",
            "450 5.7.1 class mismatch",
            "550 2.0.0 success class",
            "550 5.7.1234 too long",
            "550 3.0.0 bad class",
            "350 text",
            "250 text",
            "5500 text",
            "55 text",
            "550-5.7.1 text"
          ] do
        assert Action.parse(action) == {:error, :invalid_action}, action
      end
    end

    test "PREPEND" do
      assert Action.parse("PREPEND Received-SPF: Pass (mailfrom) identity=mailfrom") ==
               {:ok, {:prepend, "Received-SPF: Pass (mailfrom) identity=mailfrom"}}

      assert Action.parse("prepend X-Greylist:") == {:ok, {:prepend, "X-Greylist:"}}

      for action <- ["PREPEND", "PREPEND not a header", "PREPEND X Foo: bar", "PREPEND :bar"] do
        assert Action.parse(action) == {:error, :invalid_action}, action
      end
    end

    test "REDIRECT and BCC" do
      assert Action.parse("REDIRECT abuse@example.com") ==
               {:ok, {:redirect, "abuse@example.com"}}

      assert Action.parse("bcc archive@example.com") == {:ok, {:bcc, "archive@example.com"}}

      for action <- ["REDIRECT", "BCC", "REDIRECT nobody", "BCC a@example.com b@example.com"] do
        assert Action.parse(action) == {:error, :invalid_action}, action
      end
    end

    test "FILTER" do
      assert Action.parse("FILTER smtp:[127.0.0.1]:10025") ==
               {:ok, {:filter, "smtp:[127.0.0.1]:10025"}}

      assert Action.parse("filter amavis:") == {:ok, {:filter, "amavis:"}}

      for action <- ["FILTER", "FILTER nocolon", "FILTER :dest", "FILTER a b:c"] do
        assert Action.parse(action) == {:error, :invalid_action}, action
      end
    end

    test "unknown and malformed actions" do
      for action <- [
            "",
            "   ",
            "PERMIT",
            "permit_mynetworks",
            "reject_unauth_destination",
            "REJECTED text",
            "OKAY",
            <<255, 254>>,
            "12a"
          ] do
        assert Action.parse(action) == {:error, :invalid_action}, inspect(action)
      end

      assert Action.parse(nil) == {:error, :invalid_action}
    end

    test "creates no atoms" do
      word = "sovite_policy_keyword_#{System.unique_integer([:positive])}"
      assert Action.parse(word <> " text") == {:error, :invalid_action}
      assert Action.parse(String.upcase(word)) == {:error, :invalid_action}

      for atom <- [word, String.upcase(word)] do
        assert_raise ArgumentError, fn -> String.to_existing_atom(atom) end
      end
    end
  end

  describe "encode/1" do
    test "encodes every action" do
      assert Action.encode(:ok) == "OK"
      assert Action.encode(:dunno) == "DUNNO"
      assert Action.encode({:reject, nil}) == "REJECT"
      assert Action.encode({:reject, ""}) == "REJECT"
      assert Action.encode({:defer, "later"}) == "DEFER later"
      assert Action.encode({:defer_if_reject, "x"}) == "DEFER_IF_REJECT x"
      assert Action.encode({:defer_if_permit, "Greylisted"}) == "DEFER_IF_PERMIT Greylisted"
      assert Action.encode({:hold, nil}) == "HOLD"
      assert Action.encode({:discard, "spam"}) == "DISCARD spam"
      assert Action.encode({:warn, "odd"}) == "WARN odd"
      assert Action.encode({:info, "note"}) == "INFO note"
      assert Action.encode({:reply, 550, "5.7.1", "No"}) == "550 5.7.1 No"
      assert Action.encode({:reply, 450, nil, "Later"}) == "450 Later"
      assert Action.encode({:reply, 550, nil, nil}) == "550"
      assert Action.encode({:prepend, "X-Policy: yes"}) == "PREPEND X-Policy: yes"
      assert Action.encode({:redirect, "a@example.com"}) == "REDIRECT a@example.com"
      assert Action.encode({:bcc, "a@example.com"}) == "BCC a@example.com"
      assert Action.encode({:filter, "smtp:[::1]:10025"}) == "FILTER smtp:[::1]:10025"
    end

    test "replaces newlines" do
      assert Action.encode({:reject, "a\r\nb"}) == "REJECT a  b"
      assert Action.encode({:prepend, "X-A: b\nX-C: d"}) == "PREPEND X-A: b X-C: d"
    end

    test "raises on terms that are not actions" do
      for action <- [
            :reject,
            :permit,
            {:permit, nil},
            {:reject, 1},
            {:reply, 250, nil, "ok"},
            {:reply, 600, nil, "x"},
            {:reply, "550", nil, "x"},
            {:reply, 550, "4.7.1", "x"},
            {:reply, 550, "5.7.1 x", "y"},
            {:reply, 550, "bogus", "x"},
            {:reply, 550, nil, "4.7.1 mismatched text"},
            {:prepend, "no header"},
            {:prepend, nil},
            {:redirect, nil},
            {:redirect, "nobody"},
            {:bcc, "a b@example.com"},
            {:filter, "nocolon"},
            "OK"
          ] do
        assert_raise ArgumentError, fn -> Action.encode(action) end
      end
    end

    property "parse/1 reverses encode/1" do
      text = StreamData.string(:printable, min_length: 1) |> StreamData.map(&clean/1)

      action =
        StreamData.one_of([
          StreamData.member_of([:ok, :dunno]),
          StreamData.tuple(
            {StreamData.member_of([:reject, :defer, :hold, :discard, :warn, :info]),
             StreamData.one_of([StreamData.constant(nil), text])}
          ),
          StreamData.tuple(
            {StreamData.constant(:reply), StreamData.integer(400..599), StreamData.constant(nil),
             StreamData.map(text, &("x" <> &1))}
          )
        ])

      check all(action <- action) do
        assert Action.parse(Action.encode(action)) == {:ok, action}
      end
    end
  end

  # Texts as parse/1 returns them: no newlines, no surrounding blanks.
  defp clean(text) do
    case text |> String.replace(["\r", "\n"], " ") |> String.trim(" ") |> String.trim("\t") do
      "" -> "t"
      text -> if text =~ ~r/\A[ \t]|[ \t]\z/, do: "t", else: text
    end
  end
end
