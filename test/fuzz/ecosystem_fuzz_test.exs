defmodule Sovite.EcosystemFuzzTest do
  # Fuzzing of the conversations with milters and policy servers, as a
  # whole: whatever they answer, a step ends in a reply or an error, and
  # what they change (header fields, recipients, the sender, reply texts)
  # cannot break the message, the envelope, or the SMTP session.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.Core.PolicyService
  alias Sovite.Message.Headers
  alias Sovite.Milter
  alias Sovite.Milter.Headers, as: MilterHeaders
  alias Sovite.Milter.Packet
  alias Sovite.SMTP.Reply
  alias Sovite.Test.Fuzz
  alias Sovite.Validators

  @moduletag :fuzz
  # `mix fuzz` runs each property many times.
  @moduletag timeout: :infinity

  @header "From: a@example.com\r\nSubject: hi\r\nX-Spam: no\r\n"

  # One reply per step: negotiation, connect, HELO, MAIL, RCPT, DATA, the
  # header fields, their end, the body, and the end of the message (with
  # modifications before its reply).
  @milter_steps [
    [
      {:optneg, 6, 0x1FF, 0, []},
      {:optneg, 2, 0x3F, 0, []},
      {:optneg, 6, 0x1FF, 0x1FFFFF, [{1, "{auth_type}"}]}
    ],
    [:continue, :accept, {:reply_code, "421 4.7.0 go"}],
    [:continue, :reject],
    [:continue, {:reply_code, "550 5.7.1 No\r\n"}],
    [:continue, :tempfail, :discard],
    [:continue, :skip],
    [:continue, :continue, :continue],
    [:continue, :progress],
    [:continue, :skip],
    [
      {:add_header, "X-Spam", "yes"},
      {:insert_header, 0, "X-First", "1"},
      {:change_header, 1, "Subject", "[SPAM] hi\r\n\tfolded"},
      {:change_header, 1, "X-Spam", ""},
      {:add_recipient, "<copy@example.net>"},
      {:add_recipient_with_args, "<b@example.net>", "NOTIFY=NEVER"},
      {:delete_recipient, "<b@example.com>"},
      {:change_sender, "<bounce@example.com>", nil},
      {:replace_body, "new body\r\n"},
      {:quarantine, "spam"}
    ],
    [:accept, :continue, :reject, {:reply_code, "554 5.7.1 Spam"}]
  ]

  property "a milter conversation ends in replies or an error, and its changes keep fields whole" do
    step = fn responses ->
      packets = Enum.map(responses, &IO.iodata_to_binary(Packet.encode_response(&1)))
      frequency([{16, member_of(packets)}, {1, Fuzz.mutated(packets, [<<0>>, "\r\n"])}])
    end

    check all(
            steps <- fixed_list(Enum.map(@milter_steps, step)),
            modifications <- list_of(step.(Enum.at(@milter_steps, 9)), max_length: 5),
            max_runs: Fuzz.runs()
          ) do
      {eom, others} = List.pop_at(steps, -1)
      groups = others ++ [Enum.join(modifications) <> eom]
      {port, server} = Fuzz.serve(groups)

      result = Fuzz.quick(fn -> milter_session(port) end, 10_000)
      assert result == :ok, inspect(result)
      Task.shutdown(server, :brutal_kill)
    end
  end

  property "policy server answers decide, or fall back to the default action" do
    seeds = [
      "action=DUNNO\n\n",
      "action=REJECT 5.7.1 Go away\n\n",
      "action=450 4.7.1 Greylisted, see https://example.net/?a=b\r\n\r\n",
      "action=PREPEND X-Greylist: delayed 300 seconds\n\n",
      "action=REDIRECT spam@example.com\nfoo=bar\n\n",
      "action=BCC archive@example.com\n\n",
      "action=FILTER smtp:[127.0.0.1]:10025\n\n",
      "action=HOLD\n\naction=OK\n\n"
    ]

    {:ok, default} = Sovite.Policy.parse_action("451 4.3.5 Server configuration problem")

    check all(
            reply <- Fuzz.input(seeds, ["\n", "=", "\r", "action=", " "]),
            max_runs: Fuzz.runs()
          ) do
      {port, server} = Fuzz.serve([reply])

      context = %{
        policy: %{timeout: 100, default_action: default},
        sender: "a@example.com",
        recipient: "b@example.com",
        client_ip: "192.0.2.1",
        helo: "client.example"
      }

      decision =
        Fuzz.quick(fn -> PolicyService.check("inet:127.0.0.1:#{port}", :rcpt, context) end, 5_000)

      assert decision?(decision), inspect(decision)
      Task.shutdown(server, :brutal_kill)
    end
  end

  defp milter_session(port) do
    opts = [command_timeout: 100, content_timeout: 100, connect_timeout: 1_000]

    with {:ok, milter} <- Milter.connect({:inet, {127, 0, 0, 1}, port}, opts),
         {:ok, _, milter} <- Milter.connect_info(milter, "client.example", {{192, 0, 2, 1}, 4000}),
         {:ok, _, milter} <- Milter.helo(milter, "client.example"),
         {:ok, _, milter} <- Milter.mail(milter, "a@example.com", ["SIZE=10"]),
         {:ok, _, milter} <- Milter.rcpt(milter, "b@example.com"),
         {:ok, _, milter} <- Milter.data(milter),
         {:ok, _, milter} <- Milter.header(milter, "Subject", " hi"),
         {:ok, _, milter} <- Milter.end_of_headers(milter),
         {:ok, _, milter} <- Milter.body(milter, "body\r\n"),
         {:ok, reply, modifications, milter} <- Milter.end_of_message(milter) do
      Milter.close(milter)
      check_reply(reply)
      check_modifications(modifications)
    else
      {:ok, reply, milter} ->
        Milter.close(milter)
        check_reply(reply)

      {:error, _reason} ->
        :ok
    end
  end

  defp check_reply({:reply, code, _enhanced, text}) do
    assert code in 400..599
    assert text |> List.wrap() |> Enum.all?(&clean?/1), inspect(text)
    :ok
  end

  defp check_reply(reply) when is_atom(reply), do: :ok

  # Applied to a header, the changes leave fields that read back the
  # same, and the addresses are mailboxes.
  defp check_modifications(modifications) do
    fields = @header |> Headers.parse() |> MilterHeaders.apply(modifications)
    header = IO.iodata_to_binary(Headers.encode(fields))
    assert Headers.parse(header) == fields, inspect(header)
    assert Enum.all?(fields, fn {name, _raw} -> name != nil end), inspect(header)

    for {kind, address, _args} <- modifications, kind in [:add_recipient, :change_sender] do
      assert address == "" or Validators.mailbox?(address, utf8: true), inspect(address)
    end

    :ok
  end

  defp decision?(decision) when decision in [:continue, :permit], do: true

  defp decision?({:reject, %Reply{code: code, lines: lines}}),
    do: code in 400..599 and Enum.all?(lines, &clean?/1)

  defp decision?({kind, text}) when kind in [:hold, :discard], do: clean?(text)

  defp decision?({:effect, {:prepend, header}}) do
    clean?(header) and match?([{name, _}] when name != nil, Headers.parse(header <> "\r\n"))
  end

  defp decision?({:effect, {kind, address}}) when kind in [:redirect, :bcc],
    do: Validators.mailbox?(address, utf8: true)

  defp decision?({:effect, {:filter, destination}}), do: clean?(destination)
  defp decision?(_decision), do: false

  defp clean?(text),
    do: String.valid?(text) and not String.match?(text, ~r/[\x00-\x08\x0a-\x1f\x7f]/)
end
