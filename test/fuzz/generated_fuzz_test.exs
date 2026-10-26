defmodule Sovite.GeneratedFuzzTest do
  # Fuzzing of what Sovite writes itself from values others chose:
  # delivery status notifications built from remote replies and the
  # original message, and the Received:, Authentication-Results:,
  # Return-Path:, and Delivered-To: fields. They must always be
  # well-formed: whole fields, CRLF line endings, lines within limits,
  # and MIME structure the untrusted parts cannot break.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.{AuthResults, DSN}
  alias Sovite.Message.{Headers, Received, Trace}
  alias Sovite.Test.Fuzz

  @moduletag :fuzz
  # `mix fuzz` runs each property many times.
  @moduletag timeout: :infinity

  @texts [
    "550 5.1.1 <bob@example.net>: Recipient address rejected: User unknown",
    "451-4.7.1 Greylisted\r\n451 4.7.1 come back later",
    "Host or domain name not found. Name service error for name=example.net type=MX",
    "caf\xE9 \x00 \x1B[31m =?utf-8?q?x?= --boundary--",
    "ünïcode réply",
    String.duplicate("long ", 300)
  ]

  @addresses ["bob@example.net", "jürgen@bücher.example", "\"j d\"@example.com", "a@[192.0.2.1]"]

  @headers [
    "From: alice@example.com\r\nSubject: hi\r\n",
    "From: =?utf-8?q?J=C3=B6rg?= <jörg@exämple.com>\r\nSubject: Grüße\r\n\tfolded\r\n",
    "X-Weird: \xFF\xFE\r\nno colon line\r\n"
  ]

  @boundary "=_sovite_fuzz_boundary"

  property "notifications are well-formed MIME, whatever the remote servers said" do
    text = one_of([constant(nil), Fuzz.input(@texts, ["\r\n", "\n", "\r", ";", "--"])])
    address = Fuzz.input(@addresses, ["@", "\r\n", ";"]) |> filter(&String.valid?/1)

    recipient =
      fixed_map(%{
        recipient: address,
        status: member_of(["5.1.1", "4.4.1", "2.0.0", "5.0.0"]),
        diagnostic: text,
        reason: text,
        remote_mta: one_of([constant(nil), Fuzz.input(["mx.example.net"], [".", "\r\n"])]),
        original_recipient: one_of([constant(nil), map(address, &{"rfc822", &1})]),
        action: member_of([:delivered, :relayed, :expanded])
      })

    check all(
            kind <- member_of([:failure, :delay, :success]),
            recipients <- list_of(recipient, min_length: 1, max_length: 3),
            to <- address,
            headers <- map(Fuzz.input(@headers, ["\r\n", ":", "\t"]), &crlf/1),
            content <-
              one_of([
                constant(nil),
                map(Fuzz.input(@headers, ["\r\n"]), &(crlf(&1) <> "\r\nbody\r\n"))
              ]),
            envid <- one_of([constant(nil), text]),
            smtputf8 <- boolean(),
            max_runs: Fuzz.runs()
          ) do
      report = %{
        kind: kind,
        reporting_mta: "mx.example.com",
        from: "MAILER-DAEMON@mx.example.com",
        to: to,
        recipients: recipients,
        headers: headers,
        content: content,
        envid: envid,
        smtputf8: smtputf8,
        queue_id: "4F2",
        boundary: @boundary
      }

      {message, body_type} = Fuzz.quick(fn -> DSN.build(report) end)
      assert_message(message, body_type, headers <> (content || ""))
    end
  end

  property "trace and authentication fields stay single fields" do
    value = Fuzz.input(@texts ++ @addresses, ["\r\n", ";", "(", ")", "\"", "\\"])

    check all(
            comment <- one_of([constant(nil), value]),
            reason <- one_of([constant(nil), value]),
            property <- value,
            max_runs: Fuzz.runs()
          ) do
      result = %{
        method: "dkim",
        result: "fail",
        comment: comment,
        reason: reason,
        properties: [{"header.d", property}, {"header.s", "s1"}]
      }

      assert_field(AuthResults.field("mx.example.com", [result]))

      # Received: takes validated values; these are what the session lets through.
      assert_field(
        Received.build(%{
          helo: "client.example",
          remote_ip: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1},
          by: "mx.example.com",
          protocol: "UTF8SMTPSA",
          id: "4F2",
          for: "jürgen@bücher.example",
          tls: "TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)",
          priority: -3
        })
      )

      assert_field(Trace.return_path(""))
      assert_field(Trace.delivered_to("jürgen@bücher.example"))
    end
  end

  # CRLF line endings only, as messages are stored.
  defp crlf(text), do: String.replace(text, ~r/\r\n|\r|\n/, "\r\n")

  defp assert_message(message, body_type, returned) do
    refute message =~ ~r/\r(?!\n)|(?<!\r)\n/, "bare line ending"
    assert body_type == if(ascii?(message), do: :"7bit", else: :"8bitmime")

    {:ok, header, body} = Headers.split(message)
    fields = Headers.parse(header)
    assert Enum.all?(fields, &(elem(&1, 0) != nil)), inspect(header)
    assert Enum.all?(fields, &folded?/1), inspect(header)

    for name <- ~w(from to subject date message-id mime-version content-type) do
      assert Enum.count(fields, &(elem(&1, 0) == name)) == 1, name
    end

    # Three parts and the closing delimiter, unless the returned message
    # itself has the boundary.
    unless String.contains?(returned, @boundary) do
      assert length(:binary.matches(body, "\r\n--" <> @boundary <> "\r\n")) == 3
      assert String.ends_with?(body, "\r\n--" <> @boundary <> "--\r\n")
    end

    # What Sovite wrote (all but the returned part): lines within RFC 5322's
    # limit, and the delivery-status part made of fields.
    [_preamble, _text, status | _] = String.split(body, "\r\n--" <> @boundary <> "\r\n")
    {:ok, part_header, report} = Headers.split(status)
    assert part_header =~ "delivery-status"

    for block <- String.split(report, "\r\n\r\n", trim: true),
        line <- String.split(block, "\r\n", trim: true) do
      assert line =~ ~r/\A[A-Za-z-]+: /, inspect(line)
      assert byte_size(line) <= 998
    end
  end

  defp assert_field(field) do
    assert String.valid?(field), inspect(field)
    assert [{name, ^field}] = Headers.parse(field)
    assert name != nil
    assert folded?({name, field}), inspect(field)
  end

  defp folded?({_name, raw}), do: raw =~ ~r/\A[^\r\n]*(\r\n[ \t][^\r\n]*)*\r\n\z/

  defp ascii?(text), do: not String.match?(text, ~r/[\x80-\xff]/)
end
