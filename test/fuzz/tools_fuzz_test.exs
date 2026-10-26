defmodule Sovite.ToolsFuzzTest do
  # Fuzzing of the operators' tools and what they read: the Postfix
  # migration (main.cf, master.cf, and the tables they name), the log
  # reader and reports (logs hold what clients sent), and the state
  # other cluster nodes share, which may come from another version.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Sovite.Abuse.{Cache, Penalty, RateLimit}
  alias Sovite.Core.Cluster.Sync
  alias Sovite.Core.{Config, LogReader, LogReport}
  alias Sovite.Core.Postfix.Migration
  alias Sovite.Test.Fuzz

  @moduletag :fuzz
  # `mix fuzz` runs each property many times.
  @moduletag timeout: :infinity
  @moduletag :tmp_dir

  @postfix "test/fixtures/postfix/amavis/etc"

  describe "the Postfix migration" do
    setup %{tmp_dir: dir} do
      # Prints its arguments and its standard input.
      fake = Path.join(dir, "sovitectl")

      File.write!(
        fake,
        "#!/bin/sh\nprintf '%s\\0' \"$@\"\nprintf 'stdin:'\ncat\nprintf '\\n--\\n'\n"
      )

      File.chmod!(fake, 0o755)

      tables =
        for path <- Path.wildcard(Path.join(@postfix, "**/*")), File.regular?(path), into: %{} do
          {String.replace_prefix(path, @postfix, "/etc"), File.read!(path)}
        end

      %{fake: fake, tables: tables}
    end

    property "writes a config that parses, and a script that runs the commands it lists", %{
      fake: fake,
      tables: tables,
      tmp_dir: dir
    } do
      main = tables["/etc/postfix/main.cf"]
      master = tables["/etc/postfix/master.cf"]
      table_names = tables |> Map.keys() |> Enum.reject(&String.ends_with?(&1, ".cf"))
      tokens = ["\n", " = ", ",", "hash:", "$", "'", "\"", "\\", "#", "\t"]

      check all(
              main <- Fuzz.input([main], tokens),
              master <- one_of([constant(nil), Fuzz.input([master], tokens)]),
              fuzzed <- member_of(table_names),
              table <- Fuzz.input(Enum.map(table_names, &tables[&1]), tokens),
              # Each run migrates a whole setup and starts a shell.
              max_runs: max(div(Fuzz.runs(), 10), 10)
            ) do
        files = Map.put(tables, fuzzed, table)
        read = fn path -> Map.fetch(files, path) |> with_default({:error, :enoent}) end

        result =
          Fuzz.quick(
            fn ->
              Migration.migrate(main, master,
                read: read,
                defaults: %{"myhostname" => "mx.example.com", "inet_protocols" => "ipv4"},
                date: ~D[2026-01-02]
              )
            end,
            5_000
          )

        assert {:ok, _toml} = Toml.decode(result.config), result.config
        if result.errors == [], do: assert({:ok, _config} = Config.parse(result.config))

        if result.commands != [], do: assert_script(result, fake, dir)
      end
    end
  end

  describe "config files" do
    property "parse or are refused with errors" do
      example = File.read!("rel/overlays/etc/sovite.toml.example")

      small =
        ~s([server]\nhostname = "mx.example.com"\n[[listener]]\nport = 25\n[smtp]\nmax_hops = 30\n)

      tokens = ["\n", "=", "\"", "'''", "[", "]", "{", "}", "#", ",", "\\u", "1979-05-27"]

      check all(contents <- Fuzz.input([example, small], tokens), max_runs: Fuzz.runs()) do
        case Fuzz.quick(fn -> Config.parse(contents) end) do
          {:ok, %Config{}} ->
            :ok

          {:error, [_ | _] = errors} ->
            assert Enum.all?(errors, &is_binary(Exception.message(&1)))
        end
      end
    end
  end

  describe "logs" do
    @lines [
      "2026-10-04 12:00:00.100 [info] session_id=s1 remote_ip=192.0.2.7 event=smtp.server.command.stop smtp.server.command.stop: argument=<x@spam.example>, command=RCPT, duration=1, reply=554 5.7.1 <x@spam.example>: Relay access denied, reply_code=554",
      "2026-10-04 12:00:01.000 [info] queue_id=Q1 session_id=s1 event=queue.message.enqueued queue.message.enqueued: recipients=2, sender=alice@sender.example, size=2048",
      "2026-10-04 12:00:02.000 [info] queue_id=Q1 event=smtp.client.delivery.stop smtp.client.delivery.stop: duration=10, recipient=bob@example.net, relay=mx.example.net[192.0.2.25], reply=250 2.0.0 Ok, status=delivered",
      "2026-10-04 12:00:02.100 [info] queue_id=Q1 event=queue.notification.sent queue.notification.sent: kind=failure, notification_id=N1, recipients=1, to=alice@sender.example",
      "2026-10-04 13:20:00.000 [warning] session_id=s2 remote_ip=192.0.2.9 event=auth.failure auth.failure: mechanism=PLAIN, reason=invalid_credentials, username=mallory",
      "Oct  4 12:00:00 mx sovite[123]: queue_id=Q3 event=queue.message.removed queue.message.removed: reason=delivered",
      ~s({"time":"2026-10-04T12:00:00.123456Z","level":"info","msg":"queue.message.removed: reason=delivered","queue_id":"Q9","event":"queue.message.removed"})
    ]

    property "lines parse or are skipped, and reports are built from whatever parses" do
      line = Fuzz.input(@lines, ["=", ", ", ": ", " ", "\"", "[", "]", "{", "}"])

      check all(lines <- list_of(line, max_length: 10), max_runs: Fuzz.runs()) do
        entries =
          for line <- lines, entry = Fuzz.quick(fn -> LogReader.parse(line) end), do: entry

        for entry <- entries, do: assert(is_map(entry.fields)) and assert(is_binary(entry.line))

        report = Fuzz.quick(fn -> LogReport.build(entries) end)
        assert is_binary(LogReport.format(report))
      end
    end
  end

  describe "cluster sync" do
    setup context do
      names =
        for kind <- [:rate, :penalty, :cache],
            into: %{},
            do: {kind, :"#{kind}-#{System.unique_integer([:positive])}"}

      start_supervised!({RateLimit, name: names.rate})

      start_supervised!(
        {Penalty, name: names.penalty, max_failures: 3, window: 60_000, ban_time: 60_000}
      )

      start_supervised!({Cache, name: names.cache})

      # Not under its registered name: other tests may run one.
      {:ok, sync} =
        GenServer.start_link(Sync,
          interval: 3_600_000,
          rate_limit: names.rate,
          penalties: [names.penalty],
          suspensions: names.cache,
          repo: nil
        )

      Map.merge(context, %{names: names, sync: sync})
    end

    property "what other nodes send is merged or ignored, and nothing crashes", %{
      names: names,
      sync: sync
    } do
      term =
        tree(
          one_of([integer(), binary(max_length: 8), atom(:alphanumeric), constant(nil), float()]),
          fn leaf ->
            one_of([
              list_of(leaf, max_length: 3),
              tuple({leaf, leaf}),
              tuple({leaf, leaf, leaf, leaf}),
              map_of(leaf, leaf, max_length: 3)
            ])
          end
        )

      delta =
        tuple(
          {term, one_of([positive_integer(), term]), one_of([integer(), term]),
           one_of([positive_integer(), term])}
        )

      check all(
              rate <- one_of([list_of(delta, max_length: 4), term]),
              failures <-
                one_of([map_of(term, one_of([positive_integer(), term]), max_length: 3), term]),
              suspended <-
                one_of([
                  list_of(tuple({term, one_of([positive_integer(), term])}), max_length: 3),
                  term
                ]),
              greylist <- term,
              max_runs: Fuzz.runs()
            ) do
        payload = %{
          rate: rate,
          penalties: %{names.penalty => failures, :unknown => failures},
          suspended: suspended,
          greylist: greylist
        }

        send(sync, {:sync, payload})
        # Calls wait for the casts and messages before them.
        :sys.get_state(sync)
        :sys.get_state(names.penalty)

        for pid <- [
              sync,
              Process.whereis(names.rate),
              Process.whereis(names.penalty),
              Process.whereis(names.cache)
            ],
            do: assert(pid && Process.alive?(pid))

        assert is_boolean(Penalty.banned?(names.penalty, {192, 0, 2, 1}))
      end
    end
  end

  defp with_default({:ok, value}, _default), do: {:ok, value}
  defp with_default(:error, default), do: default

  # Runs import.sh with the fake sovitectl: each command gets exactly its
  # arguments (and its password on standard input).
  defp assert_script(result, fake, dir) do
    path = Path.join(dir, "import.sh")
    File.write!(path, result.script)

    {output, _status} =
      System.cmd("sh", ["-c", ~s(sh "$1" < /dev/null), "sh", path],
        env: [{"SOVITECTL", fake}],
        stderr_to_stdout: true
      )

    calls = output |> String.split("\n--\n", trim: true)

    expected =
      for command <- result.commands do
        case command do
          {:stdin, password, args} ->
            Enum.map_join(args, &(&1 <> <<0>>)) <> "stdin:" <> password <> "\n"

          args ->
            Enum.map_join(args, &(&1 <> <<0>>)) <> "stdin:"
        end
      end

    assert calls == expected
  end
end
