defmodule Sovite.Message.AddressListTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.Message.AddressList

  doctest AddressList

  defp up(value), do: AddressList.rewrite(value, &String.upcase/1)

  test "rewrites display-name and bare addresses, keeping everything else" do
    value =
      ~S| "Alice, (work)" <alice@host.example>, bob@x (Bob) ,| <>
        "\r\n" <> ~S| Team: c@d, "q u"@e;|

    assert up(value) ==
             ~S| "Alice, (work)" <ALICE@HOST.EXAMPLE>, BOB@X (Bob) ,| <>
               "\r\n" <> ~S| Team: C@D, "Q U"@E;|
  end

  test "leaves what is not an address alone" do
    assert up(" <>, undisclosed-recipients:;") == " <>, undisclosed-recipients:;"
    assert up("x@y (unterminated") == "x@y (unterminated"
    assert up(~S|"unterminated <a@b>|) == ~S|"unterminated <a@b>|
    assert up("<a@b") == "<a@b"
    assert up("not an address") == "not an address"
    assert up("a@b (comment) c@d") == "a@b (comment) c@d"
    assert up("Doe, John <j@x>") == "Doe, John <J@X>"
  end

  test "keeps source routes" do
    assert up("<@r1,@r2:u@d>") == "<@r1,@r2:U@D>"
  end

  test "rewrites whole fields" do
    assert AddressList.rewrite_field("From: Al <a@b>\r\n", &String.upcase/1) ==
             "From: Al <A@B>\r\n"

    assert AddressList.rewrite_field("no colon", &String.upcase/1) == "no colon"
  end

  test "lists the addresses in a value" do
    value = ~S| "Alice, (work)" <alice@host.example>, bob@x (Bob) ,| <> "\r\n" <> ~S| Team: c@d;|
    assert AddressList.addresses(value) == {:ok, ["alice@host.example", "bob@x", "c@d"]}

    assert AddressList.addresses("<@r1:u@d>, undisclosed-recipients:;") == {:ok, ["u@d"]}
    assert AddressList.addresses("not an address, <>") == {:ok, []}
    assert AddressList.addresses(~S|"unterminated <a@b>|) == :error
  end

  property "the identity rewrite never changes a value" do
    check all(value <- string(:printable, max_length: 80)) do
      assert AddressList.rewrite(value, & &1) == value
    end
  end
end
