defmodule Sovite.Test.FakeMTATest do
  # Tests for the test harness itself, so failures in later phases can be
  # trusted to come from Sovite rather than the fakes.
  use ExUnit.Case, async: true

  alias Sovite.Test.{FakeMTA, SMTPClient}

  defp connect(opts \\ []) do
    {:ok, mta} = FakeMTA.start_link(opts)
    {:ok, client} = SMTPClient.connect(FakeMTA.port(mta))
    on_exit(fn -> SMTPClient.close(client) end)
    {mta, client}
  end

  test "accepts a message and reports it to the owner" do
    {mta, client} = connect()

    body = "Subject: hi\r\n\r\n.leading dot\r\nbody\r\n"

    assert {:ok, {250, _}} =
             SMTPClient.send_message(
               client,
               "a@example.com",
               ["b@example.net", "c@example.net"],
               body
             )

    assert_receive {:fake_mta, ^mta, {:message, message}}
    assert message.helo == "client.test"
    assert message.mail_from == "a@example.com"
    assert message.rcpt_to == ["b@example.net", "c@example.net"]
    assert message.data == body

    assert {:ok, {221, _}} = SMTPClient.command(client, "QUIT")
  end

  test "advertises extensions in a multi-line EHLO reply" do
    {_mta, client} = connect(extensions: ["PIPELINING", "STARTTLS"])

    assert {:ok, {220, _}} = SMTPClient.read_reply(client)

    assert {:ok, {250, ["fake-mta.test", "PIPELINING", "STARTTLS"]}} =
             SMTPClient.command(client, "EHLO x")
  end

  test "uses scripted responses and records only accepted recipients" do
    rcpt = fn
      "unknown@example.net" -> "550 5.1.1 No such user"
      _ -> "250 2.1.5 OK"
    end

    {mta, client} = connect(responses: %{rcpt: rcpt})

    assert {:ok, {220, _}} = SMTPClient.read_reply(client)
    assert {:ok, {250, _}} = SMTPClient.command(client, "EHLO x")
    assert {:ok, {250, _}} = SMTPClient.command(client, "MAIL FROM:<a@example.com> SIZE=100")

    assert {:ok, {550, ["5.1.1 No such user"]}} =
             SMTPClient.command(client, "RCPT TO:<unknown@example.net>")

    assert {:ok, {250, _}} = SMTPClient.command(client, "RCPT TO:<ok@example.net>")
    assert {:ok, {354, _}} = SMTPClient.command(client, "DATA")
    assert {:ok, {250, _}} = SMTPClient.send_data(client, "x")

    assert_receive {:fake_mta, ^mta,
                    {:message, %{rcpt_to: ["ok@example.net"], mail_from: "a@example.com"}}}
  end

  test "can reject at end of data and drop the connection" do
    {mta, client} = connect(responses: %{data_end: "451 4.3.0 Try later", quit: :close})

    assert {:ok, {451, ["4.3.0 Try later"]}} =
             SMTPClient.send_message(client, "a@x.test", ["b@y.test"], "x")

    refute_receive {:fake_mta, ^mta, {:message, _}}

    assert {:error, :closed} = SMTPClient.command(client, "QUIT")
  end

  test "returns temporary failures at greeting" do
    {_mta, client} = connect(responses: %{greeting: "421 4.3.2 Busy"})

    assert {:error, {:greeting, {421, ["4.3.2 Busy"]}}} =
             SMTPClient.send_message(client, "a@x.test", ["b@y.test"], "x")
  end
end
