defmodule Sovite.SMTPFuzzTest do
  # Fuzzing of what SMTP clients and servers send: command lines, whole
  # sessions, message data, replies, SASL exchanges, and the protocols
  # proxies, milters, and policy servers speak.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.Milter.Packet
  alias Sovite.Policy.Codec
  alias Sovite.ProxyProtocol
  alias Sovite.ProxyProtocol.Header
  alias Sovite.SASL.{Password, Server}
  alias Sovite.SMTP.{Command, DataDecoder, DSNParams, Params, Reply, XText}
  alias Sovite.SMTP.Server.Session
  alias Sovite.Test.Fuzz
  alias Sovite.Test.Fuzz.SMTP, as: FuzzSMTP

  @moduletag :fuzz
  # `mix fuzz` runs each property many times.
  @moduletag timeout: :infinity

  defmodule Handler do
    @moduledoc false
    # Accepts everything and keeps what it was given. AUTH goes to the
    # real SASL server.
    @behaviour Sovite.SMTP.Server.Handler

    @impl true
    def init(_connection, sasl), do: {:ok, %{sasl: sasl, auth: nil, events: []}}
    @impl true
    def handle_helo(kind, name, state), do: {:ok, event(state, {kind, name})}
    @impl true
    def handle_mail(sender, params, state), do: {:ok, event(state, {:mail, sender, params})}
    @impl true
    def handle_rcpt(rcpt, params, state), do: {:ok, event(state, {:rcpt, rcpt, params})}
    @impl true
    def handle_data(_transaction, state), do: {:ok, event(state, :data)}
    @impl true
    def handle_data_chunk(chunk, state),
      do: {:ok, event(state, {:chunk, IO.iodata_to_binary(chunk)})}

    @impl true
    def handle_data_end(transaction, state), do: {:ok, event(state, {:end, transaction})}
    @impl true
    def handle_data_abort(reason, state), do: event(state, {:abort, reason})
    @impl true
    def handle_rset(state), do: event(state, :rset)
    @impl true
    def handle_etrn(node, state), do: {:ok, event(state, {:etrn, node})}
    @impl true
    def handle_vrfy(argument, state), do: {:ok, event(state, {:vrfy, argument})}
    @impl true
    def handle_tls(_info, state), do: state
    @impl true
    def auth_mechanisms(_state), do: ["PLAIN", "LOGIN", "SCRAM-SHA-256"]

    @impl true
    def handle_auth(mechanism, initial, state),
      do: sasl(Server.start(mechanism, initial, state.sasl), state)

    @impl true
    def handle_auth_response(response, state), do: sasl(Server.step(state.auth, response), state)
    @impl true
    def handle_auth_abort(state), do: %{state | auth: nil}
    @impl true
    def terminate(_reason, _state), do: :ok

    defp sasl({:ok, identity}, state), do: {:ok, identity, %{state | auth: nil}}
    defp sasl({:challenge, data, auth}, state), do: {:challenge, data, %{state | auth: auth}}

    defp sasl({:error, _reason, _user}, state),
      do: {:error, Reply.new(535, "5.7.8", "Authentication failed"), %{state | auth: nil}}

    defp event(state, event), do: %{state | events: [event | state.events]}
  end

  defmodule Backend do
    @moduledoc false
    @behaviour Sovite.SASL.Backend

    @hash Password.hash("secret", :scram_sha256)

    @impl true
    def verify_password("alice", password, _opts) do
      if Password.verify(@hash, password) == :ok, do: {:ok, "alice"}, else: {:error, :invalid}
    end

    def verify_password(_user, _password, _opts), do: {:error, :invalid}

    @impl true
    def scram_credentials("alice", _opts) do
      {:ok, credentials} = Password.scram_credentials(@hash)
      {:ok, credentials, "alice"}
    end

    def scram_credentials(_user, _opts), do: {:error, :unknown_user}

    @impl true
    def verify_token("alice", "good-token", _opts), do: {:ok, "alice"}
    def verify_token(_user, _token, _opts), do: {:error, :invalid}
  end

  @commands FuzzSMTP.commands()
  @command_tokens FuzzSMTP.tokens()

  describe "command lines" do
    property "parse to a command or an error, and never let CR, LF, or NUL through" do
      check all(line <- Fuzz.input(@commands, @command_tokens), max_runs: Fuzz.runs()) do
        case Fuzz.quick(fn -> Command.parse(line) end) do
          {:ok, command} -> assert clean?(command), inspect(command)
          {:error, verb, reason} when is_atom(verb) and is_atom(reason) -> :ok
        end
      end
    end

    property "parameter values parse or are refused" do
      seeds = ["SUCCESS,FAILURE,DELAY", "NEVER", "rfc822;a+2Bb@example.com", "utf-8;a\\x{40}b"]
      seeds = seeds ++ ["60", "2026-10-18T10:00:00Z", "120;R", "-30;NT", "2014-04-03T23:01:00Z;C"]
      seeds = seeds ++ ["HDRS", "FULL", "QQ314159", "-9", "a+2Bb+40example.com"]

      check all(value <- Fuzz.input(seeds, ["+", ";", ",", "\\x{", "}"]), max_runs: Fuzz.runs()) do
        results = [
          DSNParams.parse_notify(value),
          DSNParams.parse_ret(value),
          DSNParams.parse_envid(value),
          DSNParams.parse_orcpt(value),
          DSNParams.parse_orcpt(value, utf8: true),
          Params.parse_priority(value),
          Params.parse_holdfor(value),
          Params.parse_holduntil(value),
          Params.parse_by(value),
          Params.parse_rrvs(value)
        ]

        for result <- results do
          assert result == :error or (match?({:ok, _}, result) and clean?(result)),
                 inspect(result)
        end

        with {:ok, decoded} <- XText.decode(value),
             do: assert(XText.decode(XText.encode(decoded)) == {:ok, decoded})
      end
    end
  end

  describe "sessions" do
    property "reply to any input with well-formed replies, however it is split" do
      check all(
              script <- FuzzSMTP.script(),
              chunks <- Fuzz.chunked(script),
              max_runs: Fuzz.runs()
            ) do
        {whole_out, whole_events} = run_session([script], session_opts())
        {chunked_out, chunked_events} = run_session(chunks, session_opts())

        assert_replies(whole_out)
        # Pipelined or not, the server must read the input the same way:
        # anything else is a smuggling bug.
        # (SCRAM challenges have a random nonce.)
        assert scram_free(chunked_out) == scram_free(whole_out)
        assert joined(chunked_events) == joined(whole_events)
      end
    end

    property "survive any input with every option on" do
      opts = [starttls: true, auth_required: true, forbid_unauth_pipelining: true, lmtp: true]
      opts = opts ++ [bare_line_endings: :normalize, max_line_length: 512, tarpit_after: 1]

      check all(
              script <- FuzzSMTP.script(),
              chunks <- Fuzz.chunked(script),
              max_runs: Fuzz.runs()
            ) do
        {out, _events} = run_session(chunks, Keyword.merge(session_opts(), opts))
        assert_replies(out)
      end
    end
  end

  describe "message data" do
    property "is read the same way however it is split, and never keeps a bare line ending" do
      seeds = ["Subject: x\r\n\r\n..dot\r\n.\r\nQUIT\r\n", "a\nb\r\n.\r\n", "a\r\n.\n.\r\n"]

      check all(
              data <- Fuzz.input(seeds, ["\r\n.\r\n", ".", "\r\n."]),
              policy <- member_of([:reject, :normalize]),
              dots <- boolean(),
              chunks <- Fuzz.chunked(data),
              max_runs: Fuzz.runs()
            ) do
        whole = decode_data([data], policy, dots)
        assert decode_data(chunks, policy, dots) == whole

        content =
          case whole do
            {:done, content, _rest} -> content
            {:more, content} -> content
            {:error, _reason, content} -> content
          end

        refute content =~ ~r/(?<!\r)\n|\r(?!\n)/, inspect(whole)
      end
    end
  end

  describe "replies" do
    property "decode to valid replies, however they are split" do
      seeds = ["250-mx.example\r\n250-SIZE 100\r\n250 8BITMIME\r\n", "550 5.1.1 No\r\nrest"]
      seeds = seeds ++ ["220 mx.example ESMTP\r\n", "421-4.4.2 a\r\n421 4.4.2 b\r\n"]

      check all(
              data <- Fuzz.input(seeds, ["\r\n", "-", " ", "250"]),
              chunks <- Fuzz.chunked(data),
              max_runs: Fuzz.runs()
            ) do
        whole = Fuzz.quick(fn -> Reply.decode(data, max_lines: 10) end)

        case whole do
          {:ok, %Reply{code: code, lines: lines}, rest} ->
            assert code in 200..599
            assert Enum.all?(lines, &(not String.contains?(&1, ["\r", "\n"])))
            assert String.ends_with?(data, rest)

          :more ->
            :ok

          {:error, reason} ->
            assert is_atom(reason) or is_tuple(reason)
        end

        # A client decodes what it has so far, until a reply is complete.
        assert decode_growing(chunks, "") == whole
      end
    end
  end

  describe "SASL" do
    @sasl [backend: {Backend, []}]

    property "exchanges end in a result, whatever the client sends" do
      seeds = [
        <<0, "alice", 0, "secret">>,
        "alice",
        "secret",
        "n,,n=alice,r=rOprNGfwEbeRWgbNEkqO",
        "n,a=alice,n=alice,r=x",
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
        "n,a=alice,\x01host=mx.example\x01auth=Bearer good-token\x01\x01",
        "user=alice\x01auth=Bearer good-token\x01\x01",
        "\x01"
      ]

      mechanisms = ["PLAIN", "LOGIN", "SCRAM-SHA-256", "OAUTHBEARER", "XOAUTH2", "CRAM-MD5"]
      message = Fuzz.input(seeds, [<<0>>, ",", "=", "\x01", "=2C", "=3D"])

      check all(
              mechanism <- member_of(mechanisms),
              initial <- one_of([constant(nil), message]),
              responses <- list_of(message, max_length: 4),
              max_runs: Fuzz.runs()
            ) do
        result = Server.start(mechanism, initial, @sasl)
        assert sasl_result?(run_sasl(result, responses))
      end
    end
  end

  describe "proxy, milter, and policy protocols" do
    property "PROXY protocol headers parse, ask for more, or are refused" do
      tlvs = [
        ProxyProtocol.tlv(:crc32c),
        ProxyProtocol.tlv(:alpn, "h2"),
        ProxyProtocol.tlv(:authority, "mx.example"),
        ProxyProtocol.tlv(:unique_id, "id"),
        ProxyProtocol.tlv(:netns, "blue"),
        ProxyProtocol.tlv(:ssl, %{client: [:ssl, :cert_conn], version: "TLSv1.3", cn: "Zoë"})
      ]

      headers = [
        %Header{transport: :tcp4, source: {{192, 0, 2, 1}, 1}, destination: {{192, 0, 2, 2}, 25}},
        %Header{
          transport: :tcp6,
          source: {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, 1234},
          destination: {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 2}, 587},
          tlvs: tlvs
        },
        %Header{transport: :unix, source: {:local, "/a"}, destination: {:local, "/b"}},
        %Header{transport: :unspec, tlvs: [{0xE0, "x"}]},
        %Header{command: :local}
      ]

      v2 = Enum.map(headers, &ProxyProtocol.encode_v2/1)
      v1 = Enum.map(Enum.take(headers, 2), &ProxyProtocol.encode_v1/1)
      seeds = v2 ++ Enum.map(v1, &(&1 <> "EHLO")) ++ ["PROXY UNKNOWN\r\n"]

      # Version 2 headers with a mutated body and the right length, so
      # they get past the framing.
      bodies = for <<_::binary-14, _length::16, body::binary>> <- v2, body != "", do: body

      framed =
        gen all(
              command <- member_of([0x20, 0x21, 0x22]),
              family <- member_of([0x00, 0x11, 0x12, 0x21, 0x22, 0x31, 0x32, 0x13]),
              body <- Fuzz.mutated(bodies, [<<0>>])
            ) do
          binary_part(hd(v2), 0, 12) <> <<command, family, byte_size(body)::16>> <> body
        end

      check all(
              data <- one_of([Fuzz.input(seeds, ["\r\n", " "]), framed]),
              max_runs: Fuzz.runs()
            ) do
        case ProxyProtocol.parse(data, max_length: 512) do
          {:ok, _header, rest} -> assert String.ends_with?(data, rest)
          {:more, n} -> assert n == :unknown or n > 0
          {:error, reason} -> assert reason
        end
      end
    end

    property "milter packets decode or are refused" do
      payloads = [
        {?O, <<6::32, 0x1FF::32, 0x1FFFFF::32>>},
        {?h, "X-Spam\0yes\0"},
        {?m, <<1::32, "Subject\0x\0">>},
        {?y, "550 5.7.1 no\0"},
        {?e, "<a@example.com>\0SIZE=1\0"},
        {?l, <<1::32, "{auth_type} {mail_addr}\0">>},
        {?C, <<"host\0", ?4, 25::16, "192.0.2.1\0">>},
        {?D, <<?C, "j\0mx.example\0">>},
        {?L, "Subject\0x\0"}
      ]

      packets =
        Enum.map(payloads, fn {command, data} ->
          IO.iodata_to_binary(Packet.frame(command, data))
        end)

      commands = payloads |> Enum.map(&elem(&1, 0)) |> Enum.uniq()
      commands = commands ++ ~c"+-24abcdefhlpqrsty" ++ ~c"ABEHKMNQRTU"

      check all(
              data <- Fuzz.input(packets, [<<0>>]),
              command <- member_of(commands),
              payload <- Fuzz.mutated(Enum.map(payloads, &elem(&1, 1)), [<<0>>]),
              max_runs: Fuzz.runs()
            ) do
        assert Packet.decode_command(command, payload)
        assert Packet.decode_response(command, payload)

        case Packet.decode(data, 65_536) do
          {:ok, {command, payload}, _rest} ->
            assert Packet.decode_command(command, payload)
            assert Packet.decode_response(command, payload)

          :more ->
            :ok

          {:error, _reason} ->
            :ok
        end
      end
    end

    property "policy requests and replies read the same way however they are split" do
      seeds = ["request=smtpd_access_policy\nsender=a@example.com\n\n", "action=DUNNO\r\n\r\nx"]
      limits = %{max_line: 100, max_attributes: 10, max_size: 1_000}

      check all(
              data <- Fuzz.input(seeds, ["\n", "=", "\r\n"]),
              chunks <- Fuzz.chunked(data),
              max_runs: Fuzz.runs()
            ) do
        whole = Codec.read(Codec.new(), data, limits)
        assert read_policy(chunks, limits) == policy_result(whole)
        assert Sovite.Policy.decode(data)
      end
    end
  end

  ## Helpers

  # Strings from a client are valid UTF-8 without CR, LF, or NUL: they
  # end up in headers (Received:, Return-Path:), replies, and queue files.
  defp clean?(term) when is_binary(term),
    do: String.valid?(term) and not String.contains?(term, ["\r", "\n", <<0>>])

  defp clean?(term) when is_tuple(term), do: term |> Tuple.to_list() |> clean?()
  defp clean?(term) when is_list(term), do: Enum.all?(term, &clean?/1)
  defp clean?(_term), do: true

  defp session_opts do
    [
      hostname: "mx.test",
      handler: {Handler, [backend: {Backend, []}]},
      auth: true,
      plaintext_auth: true,
      vrfy: true,
      chunking: true,
      binarymime: true,
      dsn: true,
      etrn: true,
      mt_priority: true,
      deliverby: true,
      rrvs: true,
      smtputf8: true,
      requiretls: true,
      max_message_size: 1_000,
      max_recipients: 5,
      xclient_networks: [{{192, 0, 2, 0}, 24}],
      xforward_networks: [{{192, 0, 2, 0}, 24}]
    ]
  end

  defp run_session(chunks, opts) do
    connection = %{remote_ip: {192, 0, 2, 7}, session_id: "S1"}
    {result, out, session} = Session.new(connection, opts)
    feed(chunks, result, [out], session)
  end

  defp feed(_chunks, result, out, session) when result != :continue,
    do: {IO.iodata_to_binary(out), Map.fetch!(session, :handler_state).events}

  defp feed([], _result, out, session),
    do: {IO.iodata_to_binary(out), Map.fetch!(session, :handler_state).events}

  defp feed([chunk | chunks], :continue, out, session) do
    {result, more, session} = Fuzz.quick(fn -> Session.handle_input(session, chunk) end)
    feed(chunks, result, [out, more], session)
  end

  # Message content comes in pieces as it arrives: join them. Content
  # before an abort is thrown away, so how much of it came does not matter.
  defp joined(events) do
    events
    |> Enum.reverse()
    |> Enum.chunk_by(&match?({:chunk, _}, &1))
    |> Enum.flat_map(fn
      [{:chunk, _} | _] = chunks -> [{:chunk, Enum.map_join(chunks, &elem(&1, 1))}]
      other -> other
    end)
    |> drop_aborted()
  end

  defp drop_aborted([{:chunk, _}, {:abort, _} = abort | rest]), do: [abort | drop_aborted(rest)]
  defp drop_aborted([event | rest]), do: [event | drop_aborted(rest)]
  defp drop_aborted([]), do: []

  defp scram_free(out), do: String.replace(out, ~r/^334 .*$/m, "334")

  # Every reply line is a code, "-" or " ", and text, and the output ends
  # with a whole reply.
  defp assert_replies(""), do: :ok

  defp assert_replies(out) do
    assert String.ends_with?(out, "\r\n"), inspect(out)

    for line <- String.split(out, "\r\n", trim: true) do
      assert line =~ ~r/\A[2-5][0-9][0-9][ -]/, inspect(line)
      refute String.contains?(line, ["\r", "\n", <<0>>]), inspect(line)
    end

    :ok
  end

  defp decode_data(chunks, policy, dots),
    do: feed_data(DataDecoder.new(policy, dots: dots), chunks, [])

  defp feed_data(decoder, [], acc) do
    case DataDecoder.finish(decoder) do
      {:ok, content} -> {:more, IO.iodata_to_binary([acc, content])}
      {:error, reason, content} -> {:error, reason, IO.iodata_to_binary([acc, content])}
    end
  end

  defp feed_data(decoder, [chunk | chunks], acc) do
    case Fuzz.quick(fn -> DataDecoder.decode(decoder, chunk) end) do
      {:more, content, decoder} ->
        feed_data(decoder, chunks, [acc, content])

      {:done, content, rest} ->
        {:done, IO.iodata_to_binary([acc, content]), IO.iodata_to_binary([rest | chunks])}

      {:error, reason, content} ->
        {:error, reason, IO.iodata_to_binary([acc, content])}
    end
  end

  defp decode_growing([], buffer), do: Reply.decode(buffer, max_lines: 10)

  defp decode_growing([chunk | chunks], buffer) do
    buffer = buffer <> chunk

    case Reply.decode(buffer, max_lines: 10) do
      :more -> decode_growing(chunks, buffer)
      {:ok, reply, rest} -> {:ok, reply, IO.iodata_to_binary([rest | chunks])}
      error -> error
    end
  end

  defp run_sasl({:challenge, data, server}, [response | responses]) do
    assert is_binary(data)
    run_sasl(Server.step(server, response), responses)
  end

  defp run_sasl(result, _responses), do: result

  defp sasl_result?({:ok, identity}), do: identity == "alice"
  defp sasl_result?({:challenge, data, _server}), do: is_binary(data)
  defp sasl_result?({:error, reason, _user}), do: is_atom(reason)
  defp sasl_result?(_other), do: false

  defp read_policy(chunks, limits, reader \\ Codec.new())
  defp read_policy([], _limits, _reader), do: :more

  defp read_policy([chunk | chunks], limits, reader) do
    case Codec.read(reader, chunk, limits) do
      {:more, reader} -> read_policy(chunks, limits, reader)
      # What follows the block is in the later chunks too.
      {:ok, attrs, reader} -> {:ok, attrs, IO.iodata_to_binary([Codec.buffer(reader) | chunks])}
      error -> error
    end
  end

  defp policy_result({:ok, attrs, reader}), do: {:ok, attrs, Codec.buffer(reader)}
  defp policy_result({:more, _reader}), do: :more
  defp policy_result(error), do: error
end
