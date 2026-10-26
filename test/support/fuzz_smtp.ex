defmodule Sovite.Test.Fuzz.SMTP do
  @moduledoc """
  Generators of SMTP client input for the fuzz tests: command lines, and
  whole sessions that get somewhere (a greeting, perhaps AUTH,
  transactions with `DATA` or `BDAT`, and stray commands), with some
  lines mutated. See `Sovite.Test.Fuzz`.
  """

  use ExUnitProperties

  alias Sovite.Test.Fuzz

  @mail [
    "MAIL FROM:<a@example.com>",
    "MAIL FROM:<a@example.com> SIZE=100 BODY=8BITMIME",
    "MAIL FROM:<> RET=HDRS ENVID=QQ314159",
    "MAIL FROM:<\"j d\"@example.com> MT-PRIORITY=3 BY=120;R",
    "MAIL FROM:<pelé@exämple.com> SMTPUTF8 AUTH=<>",
    "MAIL FROM:<a@example.com> BODY=BINARYMIME"
  ]

  @rcpt [
    "RCPT TO:<b@example.net>",
    "RCPT TO:<@a.example,@b.example:b@example.net> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;b@example.net",
    "RCPT TO:<Postmaster> RRVS=2014-04-03T23:01:00Z;C",
    "RCPT TO:<user@[IPv6:2001:db8::1]>",
    "RCPT TO:<ünïcode@exämple.com> NOTIFY=NEVER"
  ]

  @other [
    "EHLO client.example",
    "HELO [192.0.2.1]",
    "LHLO client.example",
    "MAIL FROM:<a@example.com> REQUIRETLS HOLDFOR=60",
    "DATA",
    "BDAT 0 LAST",
    "BDAT 18446744073709551616",
    "RSET",
    "QUIT",
    "NOOP x",
    "VRFY alice",
    "HELP mail",
    "STARTTLS",
    "AUTH PLAIN AGFsaWNlAHNlY3JldA==",
    "AUTH LOGIN YWxpY2U=",
    "AUTH SCRAM-SHA-256 =",
    "XCLIENT ADDR=192.0.2.1 NAME=[UNAVAILABLE] HELO=x+2Ey",
    "XFORWARD NAME=host.example ADDR=IPV6:2001:db8::1 PROTO=ESMTP",
    "ETRN @example.com",
    "ETRN #queue",
    "GET / HTTP/1.1",
    "Host: example.com"
  ]

  @tokens ["<", ">", ":", "=", " ", "\"", "\\", "@", ",", "FROM:", "TO:", "[IPv6:", "é"]

  @bodies ["Subject: x\r\n\r\nbody\r\n", ".\r\n..\r\n", "a\r\n" <> String.duplicate("b", 80)]

  @doc "Command lines to start from."
  def commands, do: @mail ++ @rcpt ++ @other

  @doc "Pieces of command lines to insert."
  def tokens, do: @tokens

  @doc """
  Whole sessions, as the bytes a client sends.

  Options replace the seeds: `:mail` and `:rcpt` (command lines),
  `:bodies` (message content, header and body), and `:auth` (lists of
  lines for one `AUTH` exchange).
  """
  def script(opts \\ []) do
    stray = Fuzz.input(commands() ++ Keyword.get(opts, :mail, []), @tokens)

    gen all(
          hello <- line(["EHLO client.example", "LHLO client.example", "HELO client.example"]),
          auth <- list_of(auth(opts[:auth]), max_length: 1),
          transactions <- list_of(transaction(opts), max_length: 3),
          stray <- list_of(stray, max_length: 3),
          parts <-
            shuffle_some([hello] ++ List.flatten(auth) ++ List.flatten(transactions), stray),
          ending <- frequency([{6, constant("\r\n")}, {1, constant("\n")}])
        ) do
      Enum.map_join(parts, fn
        {:raw, bytes} -> bytes
        line -> line <> ending
      end)
    end
  end

  defp line(seeds), do: frequency([{5, member_of(seeds)}, {1, Fuzz.mutated(seeds, @tokens)}])

  defp auth(nil) do
    auth([
      ["AUTH PLAIN AGFsaWNlAHNlY3JldA=="],
      ["AUTH LOGIN", "YWxpY2U=", "c2VjcmV0"],
      ["AUTH PLAIN", "*"],
      ["AUTH SCRAM-SHA-256 biwsbj1hbGljZSxyPWFiYw==", "Yz1iaXdzLHI9YWJj", "*"]
    ])
  end

  defp auth(exchanges) do
    gen all(
          exchange <- member_of(exchanges),
          lines <- fixed_list(Enum.map(exchange, &line([&1])))
        ) do
      lines
    end
  end

  defp transaction(opts) do
    gen all(
          mail <- line(Keyword.get(opts, :mail, @mail)),
          rcpts <- list_of(line(Keyword.get(opts, :rcpt, @rcpt)), min_length: 1, max_length: 3),
          content <- Fuzz.input(Keyword.get(opts, :bodies, @bodies)),
          kind <- member_of([:data, :bdat, :bdat_chunks])
        ) do
      [mail | rcpts] ++ content(kind, content)
    end
  end

  defp content(:data, content), do: ["DATA", {:raw, content <> "\r\n.\r\n"}]
  defp content(:bdat, content), do: ["BDAT #{byte_size(content)} LAST", {:raw, content}]

  defp content(:bdat_chunks, content) do
    half = div(byte_size(content), 2)
    <<first::binary-size(^half), second::binary>> = content
    ["BDAT #{half}", {:raw, first}, "BDAT #{byte_size(second)} LAST", {:raw, second}]
  end

  # The parts in order, with the stray ones in random places.
  defp shuffle_some(parts, stray) do
    gen all(places <- list_of(integer(0..length(parts)), length: length(stray))) do
      places
      |> Enum.zip(stray)
      |> Enum.sort_by(&elem(&1, 0), :desc)
      |> Enum.reduce(parts, fn {at, line}, parts -> List.insert_at(parts, at, line) end)
    end
  end
end
