defmodule Sovite.SMTP.ClientLMTPTest do
  use ExUnit.Case, async: true

  alias Sovite.SMTP.Client
  alias Sovite.Test.FakeMTA

  @body "Subject: hi\r\n\r\nbody\r\n"

  defp start_mta(opts) do
    start_supervised!({FakeMTA, [owner: self(), lmtp: true] ++ opts}, id: make_ref())
  end

  defp outcomes(results),
    do: Enum.map(results, fn {rcpt, stage, reply} -> {rcpt, stage, reply.code} end)

  # Unix socket paths are limited to about 100 bytes, too few for tmp_dir.
  setup do
    socket = Path.join(System.tmp_dir!(), "sovite-lmtp-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm(socket) end)
    %{socket: socket}
  end

  test "delivers over a Unix socket with a status per recipient", %{socket: socket} do
    data_end = fn
      "full@example.com" -> "452 4.2.2 Mailbox full"
      "gone@example.com" -> "550 5.1.1 No such user"
      _ -> "250 2.0.0 Saved"
    end

    rcpt = fn
      "unknown@example.com" -> "550 5.1.1 User unknown"
      _ -> "250 2.1.5 OK"
    end

    mta = start_mta(unix: socket, responses: %{lmtp_data_end: data_end, rcpt: rcpt})

    {:ok, client} =
      Client.connect({:local, socket}, 24, helo: "mx.example.org", protocol: :lmtp)

    recipients = ~w(a@example.com full@example.com unknown@example.com gone@example.com)
    assert {:ok, client, results} = Client.deliver(client, "s@example.net", recipients, [@body])

    assert outcomes(results) == [
             {"unknown@example.com", :rcpt, 550},
             {"a@example.com", :data_end, 250},
             {"full@example.com", :data_end, 452},
             {"gone@example.com", :data_end, 550}
           ]

    assert_receive {:fake_mta, ^mta, {:message, message}}
    assert message.helo == "mx.example.org"
    assert message.delivered == ["a@example.com"]
    assert message.data == @body

    # The connection carries another transaction.
    assert {:ok, client, [{"a@example.com", :data_end, %{code: 250}}]} =
             Client.deliver(client, "s@example.net", ["a@example.com"], [@body])

    assert {{:local, _}, 0} = Client.peer(client)
    assert :ok = Client.quit(client)
  end

  test "delivers over TCP" do
    mta = start_mta([])

    {:ok, client} =
      Client.connect({127, 0, 0, 1}, FakeMTA.port(mta), helo: "mx.example.org", protocol: :lmtp)

    assert {:ok, _client, [{"a@example.com", :data_end, %{code: 250}}]} =
             Client.deliver(client, "", ["a@example.com"], [@body])
  end

  test "an LHLO rejection ends the connection", %{socket: socket} do
    start_mta(unix: socket, responses: %{ehlo: "554 5.7.0 go away"})
    # The fake answers LHLO with its :ehlo response.
    assert {:error, {:lhlo, %{code: 554}}} =
             Client.connect({:local, socket}, 0, helo: "mx.example.org", protocol: :lmtp)
  end

  test "a missing socket is a connect error", %{socket: socket} do
    assert {:error, {:connect, :enoent}} =
             Client.connect({:local, socket}, 0, helo: "mx.example.org", protocol: :lmtp)
  end
end
