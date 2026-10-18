defmodule Sovite.QueueFuzzTest do
  # Fuzzing of the queue file reader: a damaged file (a bad disk, a
  # crash, a careless edit) must be refused, never crash the queue
  # manager, and every envelope must survive the file format unchanged.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.Queue.{Entry, Envelope, ID, Record, Spool}
  alias Sovite.Test.Fuzz

  @moduletag :fuzz
  # `mix fuzz` runs each property many times.
  @moduletag timeout: :infinity
  @moduletag :tmp_dir

  @message "Received: from a by b\r\nFrom: a@example.net\r\nSubject: hi\r\n\r\nHello\r\n.\r\n"
  @errors [:invalid_header, :checksum_mismatch, :invalid_envelope, :invalid_record]

  setup %{tmp_dir: dir} do
    :ok = Spool.init(dir)
    paths = [full_file(dir), plain_file(dir)]
    %{paths: paths, files: Enum.map(paths, &File.read!/1)}
  end

  property "a queue file loads or is refused, whatever its bytes", %{tmp_dir: dir, files: files} do
    path = Path.join(dir, "fuzzed")

    check all(
            contents <- Fuzz.mutated(files, ["\n", "R ", "{", "}", "\"", "0"]),
            max_runs: Fuzz.runs()
          ) do
      File.write!(path, contents)
      assert_loads(path)
    end
  end

  property "envelopes and records with valid checksums load or are refused", %{
    tmp_dir: dir,
    paths: [full | _]
  } do
    path = Path.join(dir, "fuzzed")
    {:ok, loaded} = Spool.load(full)
    envelope = loaded.envelope |> Envelope.to_map() |> JSON.encode!()
    records = Enum.map(loaded.records, &(&1 |> Record.to_map() |> JSON.encode!()))
    json_tokens = ["\"", ":", ",", "{", "}", "[", "]", "null", "true", "1e999", "-0", "\\u0000"]

    check all(
            envelope <- Fuzz.input([envelope], json_tokens),
            records <- list_of(Fuzz.input(records, json_tokens), max_length: 4),
            prefix <- member_of(["", "DKIM-Signature: v=1\r\n"]),
            max_runs: Fuzz.runs()
          ) do
      File.write!(path, queue_file(envelope <> "\n", @message, prefix, records))
      assert_loads(path)
    end
  end

  property "any JSON value is an envelope or a record, or is refused" do
    check all(map <- json_object(), max_runs: Fuzz.runs()) do
      case Envelope.from_map(map) do
        {:ok, %Envelope{} = envelope} -> assert %Entry{} = Entry.new(envelope)
        {:error, :invalid_envelope} -> :ok
      end

      assert match?({:ok, _}, Record.from_map(map)) or Record.from_map(map) == :error
    end
  end

  property "envelopes come back from the file format unchanged" do
    check all(envelope <- envelope(), max_runs: Fuzz.runs()) do
      map = envelope |> Envelope.to_map() |> JSON.encode!() |> JSON.decode!()
      assert Envelope.from_map(map) == {:ok, envelope}
    end
  end

  # Loads `path` with and without verification. A file that loads gives
  # an entry, and its message can be read.
  defp assert_loads(path) do
    for opts <- [[], [verify: false], [records: false]], do: assert_loads(path, opts)
  end

  defp assert_loads(path, opts) do
    case Fuzz.quick(fn -> Spool.load(path, opts) end) do
      {:ok, loaded} -> assert_usable(path, loaded)
      {:error, reason} -> assert reason in @errors, inspect(reason)
    end
  end

  defp assert_usable(path, loaded) do
    entry = Entry.new(loaded.envelope, loaded.records)
    assert is_list(Entry.pending(entry)) and is_boolean(Entry.done?(entry))

    message =
      path
      |> Spool.stream_message(loaded.message_offset, loaded.message_size, loaded.prefix)
      |> Enum.join()

    assert byte_size(message) <= loaded.message_size
  end

  # A file with every envelope field, a prefix, and records.
  defp full_file(dir) do
    envelope = %Envelope{
      queue_id: ID.generate(),
      sender: "a@example.net",
      srs_sender: "SRS0=x=yy=example.net=a@fwd.example",
      recipients: ["b@example.com", "c@example.com", "Postmaster"],
      received_at: ~U[2026-10-18 12:00:00.123456Z],
      session_id: "s1",
      remote_ip: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 7},
      helo: "client.example.net",
      protocol: "ESMTPSA",
      body_type: :binarymime,
      auth_user: "alice",
      content_filter: "smtp:[127.0.0.1]:10024",
      requiretls: true,
      smtputf8: true,
      ret: :hdrs,
      envid: "QQ314159",
      dsn: %{
        "b@example.com" => %{notify: [:success, :failure], orcpt: {"rfc822", "b@example.com"}}
      },
      expanded: ["list@example.com"],
      priority: -3,
      hold: {:until, ~U[2026-10-19 00:00:00Z]},
      deliver_by: %{deadline: ~U[2026-10-18 13:00:00Z], mode: :notify, trace: true},
      rrvs: %{"c@example.com" => {~U[2014-04-03 23:01:00Z], :continue}},
      tenant: "acme",
      forwarded_from: "node2@mx2.example"
    }

    path = commit(dir, envelope, "DKIM-Signature: v=1; a=ed25519-sha256\r\n")

    details = %{
      status: "2.0.0",
      reply: "250 ok",
      remote: "mx[192.0.2.1]",
      smtp: true,
      at: ~U[2026-10-18 12:01:00Z]
    }

    {:ok, _} =
      Spool.append(path, File.stat!(path).size, [
        {:recipient, "b@example.com", :delivered, Map.put(details, :action, :relayed)},
        {:recipient, "c@example.com", :deferred,
         %{details | status: "4.2.0", reply: "451 later"}},
        {:retry, 1, ~U[2026-10-18 12:30:00Z]},
        {:notified, ["c@example.com"]},
        :warned
      ])

    path
  end

  defp plain_file(dir) do
    envelope = %Envelope{queue_id: ID.generate(), sender: "", recipients: ["b@example.com"]}
    commit(dir, envelope, "")
  end

  defp commit(dir, envelope, prefix) do
    {:ok, writer} = Spool.open(dir, envelope)
    {:ok, writer} = Spool.write(writer, @message)
    {:ok, path, _size} = Spool.commit(writer, prefix)
    path
  end

  defp queue_file(envelope_line, message, prefix, records) do
    data = envelope_line <> message <> prefix

    header =
      "SOVITE-QUEUE 3 " <>
        pad(byte_size(envelope_line), 10) <>
        " " <>
        pad(byte_size(message <> prefix), 20) <>
        " " <> pad(byte_size(prefix), 10) <> " " <> sha256(data) <> "\n"

    header <> data <> Enum.map_join(records, &("R " <> sha256(&1) <> " " <> &1 <> "\n"))
  end

  defp pad(integer, width), do: String.pad_leading(Integer.to_string(integer), width, "0")
  defp sha256(data), do: :sha256 |> :crypto.hash(data) |> Base.encode16(case: :lower)

  ## Generators

  @keys ~w(queue_id sender recipients srs_sender received_at remote_ip body_type notification
           ret dsn expanded priority hold deliver_by rrvs requiretls smtputf8 tenant
           type recipient status code reply remote smtp at action report attempts next
           notify orcpt deadline mode trace)

  defp json_object do
    value =
      tree(
        one_of([
          constant(nil),
          boolean(),
          integer(),
          map(integer(), &(&1 / 7)),
          string(:printable, max_length: 20),
          member_of(["", "2026-10-18T12:00:00Z", "192.0.2.1", "delivered", "for;60", "full"])
        ]),
        fn leaf ->
          one_of([
            list_of(leaf, max_length: 3),
            map_of(one_of([member_of(@keys), string(:alphanumeric)]), leaf, max_length: 4)
          ])
        end
      )

    map_of(member_of(@keys), resize(value, 8), max_length: 12)
  end

  defp envelope do
    address =
      member_of(["a@example.com", "pelé@exämple.com", "\"j d\"@example.net", "Postmaster"])

    text = string(:printable, max_length: 30)
    time = map(integer(0..4_102_444_800), &DateTime.from_unix!/1)

    gen all(
          recipients <- map(list_of(address, min_length: 1, max_length: 3), &Enum.uniq/1),
          sender <- one_of([constant(""), address]),
          optional <-
            fixed_map(%{
              srs_sender: one_of([constant(nil), address]),
              received_at: one_of([constant(nil), time]),
              session_id: one_of([constant(nil), text]),
              remote_ip:
                one_of([
                  constant(nil),
                  constant({192, 0, 2, 1}),
                  constant({0x2001, 0xDB8, 0, 0, 0, 0, 0, 1})
                ]),
              helo: one_of([constant(nil), text]),
              protocol: one_of([constant(nil), member_of(["SMTP", "ESMTPSA", "LMTP"])]),
              body_type: member_of([nil, :"7bit", :"8bitmime", :binarymime]),
              notification: member_of([nil, :failure, :delay, :success, :double_bounce]),
              auth_user: one_of([constant(nil), text]),
              content_filter: one_of([constant(nil), constant("smtp:[127.0.0.1]:10025")]),
              requiretls: boolean(),
              smtputf8: boolean(),
              ret: member_of([nil, :full, :hdrs]),
              envid: one_of([constant(nil), text]),
              expanded: list_of(address, max_length: 2),
              priority: integer(-9..9),
              hold:
                one_of([
                  constant(nil),
                  map(positive_integer(), &{:for, &1}),
                  map(time, &{:until, &1})
                ]),
              deliver_by:
                one_of([
                  constant(nil),
                  fixed_map(%{
                    deadline: time,
                    mode: member_of([:return, :notify]),
                    trace: boolean()
                  })
                ]),
              tenant: one_of([constant(nil), string(:alphanumeric, min_length: 1)]),
              forwarded_from: one_of([constant(nil), constant("n1@mx1.example")])
            }),
          dsn <- map_of(address, dsn(), max_length: 2),
          rrvs <- map_of(address, tuple({time, member_of([:reject, :continue])}), max_length: 2)
        ) do
      struct!(
        Envelope,
        Map.merge(optional, %{
          queue_id: ID.generate(),
          sender: sender,
          recipients: recipients,
          dsn: dsn,
          rrvs: rrvs
        })
      )
    end
  end

  defp dsn do
    fixed_map(%{
      notify:
        member_of([nil, :never, [:success], [:failure, :delay], [:delay, :success, :failure]]),
      orcpt:
        one_of([
          constant(nil),
          constant({"rfc822", "a@example.com"}),
          constant({"utf-8", "pelé@exämple.com"})
        ])
    })
  end
end
