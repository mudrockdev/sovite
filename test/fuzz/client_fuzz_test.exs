defmodule Sovite.ClientFuzzTest do
  # Fuzzing of the SMTP and LMTP client against hostile servers: any
  # greeting, EHLO list, AUTH challenge, or reply, sent in any grouping
  # (pipelined or not). The client must end in a result or an error,
  # never crash or hang, and what it reports must be safe to store.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.SMTP.{Client, Reply}
  alias Sovite.Test.Fuzz

  @moduletag :fuzz
  # `mix fuzz` runs each property many times.
  @moduletag timeout: :infinity

  @ehlo "250-mx.remote.test Hello\r\n250-PIPELINING\r\n250-SIZE 1000\r\n250-8BITMIME\r\n" <>
          "250-DSN\r\n250-SMTPUTF8\r\n250-CHUNKING\r\n250-BINARYMIME\r\n250-ENHANCEDSTATUSCODES\r\n" <>
          "250-AUTH PLAIN LOGIN SCRAM-SHA-256\r\n250-MT-PRIORITY\r\n250-XFORWARD NAME ADDR PROTO HELO\r\n" <>
          "250 DELIVERBY 60\r\n"

  # A conversation that gets somewhere, in order: greeting, EHLO (or
  # LHLO), AUTH, MAIL, two RCPT, DATA, the end of data (one reply per
  # recipient for LMTP), QUIT.
  @conversation [
    ["220 mx.remote.test ESMTP\r\n", "220-mx.remote.test\r\n220 ESMTP\r\n", "554 No\r\n"],
    [@ehlo, "250 mx.remote.test\r\n", "502 5.5.1 No EHLO\r\n"],
    ["334 \r\n", "334 VXNlcm5hbWU6\r\n", "535 5.7.8 No\r\n"],
    ["235 2.7.0 Authentication successful\r\n", "334 UGFzc3dvcmQ6\r\n"],
    ["250 2.1.0 Ok\r\n", "250 Ok\r\n", "452 4.3.1 Full\r\n"],
    ["250 2.1.5 Ok\r\n", "550 5.1.1 No such user\r\n"],
    ["250 2.1.5 Ok\r\n", "451-4.7.1 Greylisted,\r\n451 4.7.1 come back later\r\n"],
    ["354 End data with <CR><LF>.<CR><LF>\r\n", "250 2.0.0 Chunk accepted\r\n"],
    ["250 2.0.0 Ok: queued as 4F2\r\n", "552 5.3.4 Too big\r\n"],
    ["250 2.1.5 Delivered\r\n", "452 4.2.2 Mailbox full\r\n"],
    ["221 2.0.0 Bye\r\n", "421 4.3.2 Shutting down\r\n"]
  ]

  @tokens ["\r\n", "-", " ", "250", "334 ", "SIZE ", "AUTH ", "\n"]

  property "SMTP and LMTP clients end in a result or an error, whatever the server says" do
    check all(
            replies <- conversation(),
            groups <- list_of(integer(1..3), length: 10),
            protocol <- member_of([:smtp, :lmtp]),
            authenticate <- boolean(),
            chunking <- boolean(),
            max_runs: Fuzz.runs()
          ) do
      {port, server} = Fuzz.serve(group(replies, groups), first: :send)

      opts = [helo: "mx.example.com", protocol: protocol, greeting_timeout: 500] ++ timeouts()

      result = Fuzz.quick(fn -> session(port, opts, authenticate, chunking) end, 10_000)
      assert result == :ok, inspect(result)
      Task.shutdown(server, :brutal_kill)
    end
  end

  # Each step one of its replies, sometimes mutated or left out.
  defp conversation do
    step = fn replies ->
      frequency([
        {12, member_of(replies)},
        {2, Fuzz.mutated(replies, @tokens)},
        {1, constant(nil)}
      ])
    end

    gen all(replies <- fixed_list(Enum.map(@conversation, step))) do
      Enum.reject(replies, &is_nil/1)
    end
  end

  defp session(port, opts, authenticate, chunking) do
    with {:ok, client} <- Client.connect({127, 0, 0, 1}, port, opts),
         :ok <- check_name(Client.server_name(client)),
         {:ok, client} <- maybe_authenticate(client, authenticate) do
      deliver(client, chunking)
    else
      {:error, {stage, reason}} when is_atom(stage) -> check_reason(reason)
      {:error, _client, reason} -> check_auth_error(reason)
    end
  end

  defp maybe_authenticate(client, false), do: {:ok, client}

  defp maybe_authenticate(client, true),
    do: Client.authenticate(client, %{username: "alice", password: "secret"})

  defp deliver(client, chunking) do
    opts = [
      size: 40,
      body_type: :"8bitmime",
      chunking: chunking,
      dsn: %{ret: :hdrs, envid: "QQ1", recipients: %{"b@remote.test" => %{notify: [:failure]}}},
      priority: 2,
      xforward: %{name: "client.example", addr: {192, 0, 2, 1}, proto: "ESMTP", helo: "client"}
    ]

    body = ["Subject: x\r\n\r\n", "body\r\n.\r\n"]

    case Client.deliver(client, "a@example.com", ["b@remote.test", "c@remote.test"], body, opts) do
      {:ok, client, results} ->
        for {_recipient, stage, %Reply{} = reply} <- results do
          assert is_atom(stage)
          assert_safe(reply)
        end

        Client.quit(client)
        :ok

      {:error, client, _refusal} ->
        Client.close(client)
        :ok

      {:error, {stage, reason}} when is_atom(stage) ->
        check_reason(reason)
    end
  end

  defp check_name(nil), do: :ok
  defp check_name(name), do: if(clean?(name), do: :ok, else: {:error, {:greeting, {:name, name}}})

  defp check_reason(%Reply{} = reply), do: assert_safe(reply)
  defp check_reason(reason) when is_atom(reason), do: :ok
  defp check_reason({:tls, _reason}), do: :ok
  defp check_reason(reason), do: {:unexpected, reason}

  defp check_auth_error({:rejected, %Reply{} = reply}), do: assert_safe(reply)
  defp check_auth_error(reason) when is_atom(reason), do: :ok
  defp check_auth_error({:sasl, _reason}), do: :ok
  defp check_auth_error(reason), do: {:unexpected, reason}

  defp assert_safe(%Reply{code: code, lines: lines}) do
    assert code in 200..599
    assert Enum.all?(lines, &clean?/1), inspect(lines)
    :ok
  end

  defp clean?(text),
    do: String.valid?(text) and not String.match?(text, ~r/[\x00-\x08\x0a-\x1f\x7f]/)

  defp timeouts do
    for key <- [:command_timeout, :data_timeout, :send_timeout, :data_end_timeout],
        do: {key, 300}
  end

  # The replies in groups of 1 to 3, each group sent at once.
  defp group(replies, sizes) do
    sizes
    |> Enum.reduce({replies, []}, fn
      _size, {[], groups} -> {[], groups}
      size, {left, groups} -> {Enum.drop(left, size), [Enum.take(left, size) | groups]}
    end)
    |> then(fn {left, groups} -> Enum.reverse(groups) ++ Enum.map(left, &[&1]) end)
  end
end
