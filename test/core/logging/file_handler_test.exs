defmodule Sovite.Core.Logging.FileHandlerTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  require Logger

  alias Sovite.Core.Logging.FileHandler

  @moduletag :tmp_dir

  @formatter Logger.Formatter.new(format: "$message\n", colors: [enabled: false])
  @now {{2026, 10, 4}, {12, 0, 0}}

  defmodule NullHandler do
    @moduledoc false
    def log(_event, _config), do: :ok
  end

  setup do
    clock = start_supervised!({Agent, fn -> @now end})
    %{clock: clock}
  end

  # Starts a handler at level :none, so only log/2 below reaches it and
  # other tests' log events do not.
  defp start_handler(context, config \\ %{}, opts \\ []) do
    id = :"file_handler_test_#{System.unique_integer([:positive])}"

    config =
      Map.merge(
        %{
          directory: context.tmp_dir,
          file_name: "sovite.{date}.{n}.log",
          date_format: "%Y-%m-%d",
          max_size: 1024,
          rotation: :daily,
          max_files: 0,
          symlink: nil
        },
        config
      )

    clock = context.clock

    start_supervised!(
      {FileHandler,
       Keyword.merge(
         [
           id: id,
           config: config,
           formatter: @formatter,
           level: :none,
           clock: fn -> Agent.get(clock, & &1) end
         ],
         opts
       )}
    )

    id
  end

  defp log(id, messages) do
    {:ok, config} = :logger.get_handler_config(id)

    for message <- List.wrap(messages) do
      event = %{level: :info, msg: {:string, message}, meta: %{time: :logger.timestamp()}}
      FileHandler.log(event, config)
    end

    :ok = FileHandler.sync(id)
  end

  defp set_time(context, time), do: Agent.update(context.clock, fn _ -> time end)
  defp read(context, name), do: File.read!(Path.join(context.tmp_dir, name))
  defp files(context), do: context.tmp_dir |> File.ls!() |> Enum.sort()

  test "writes formatted lines to a dated, numbered file", context do
    id = start_handler(context)
    log(id, ["hello", "world"])

    assert files(context) == ["sovite.2026-10-04.1.log"]
    assert read(context, "sovite.2026-10-04.1.log") == "hello\nworld\n"

    assert File.stat!(Path.join(context.tmp_dir, "sovite.2026-10-04.1.log")).mode
           |> Bitwise.band(0o777) == 0o640
  end

  test "starts a new file before a line would exceed max_size", context do
    id = start_handler(context, %{max_size: 10})
    log(id, ["12345", "abcde", "x", "0123456789ABC", "y"])

    assert read(context, "sovite.2026-10-04.1.log") == "12345\n"
    assert read(context, "sovite.2026-10-04.2.log") == "abcde\nx\n"
    # A line longer than max_size still gets written, alone in its file.
    assert read(context, "sovite.2026-10-04.3.log") == "0123456789ABC\n"
    assert read(context, "sovite.2026-10-04.4.log") == "y\n"
  end

  test "starts a new file when the rotation period changes", context do
    id = start_handler(context)
    log(id, "monday")
    set_time(context, {{2026, 10, 5}, {0, 0, 1}})
    log(id, "tuesday")

    assert read(context, "sovite.2026-10-04.1.log") == "monday\n"
    assert read(context, "sovite.2026-10-05.1.log") == "tuesday\n"
  end

  test "numbers files within a date when rotating faster than the date format", context do
    id = start_handler(context, %{rotation: :hourly})
    log(id, "noon")
    set_time(context, {{2026, 10, 4}, {13, 0, 0}})
    log(id, "one")

    assert files(context) == ["sovite.2026-10-04.1.log", "sovite.2026-10-04.2.log"]
  end

  test "rotation :never only rotates by size", context do
    id = start_handler(context, %{rotation: :never, file_name: "sovite.{n}.log"})
    log(id, "a")
    set_time(context, {{2027, 1, 1}, {0, 0, 0}})
    log(id, "b")

    assert files(context) == ["sovite.1.log"]
  end

  test "keeps only the newest max_files files", context do
    File.write!(Path.join(context.tmp_dir, "unrelated.txt"), "keep me")
    id = start_handler(context, %{max_size: 5, max_files: 2})
    log(id, ["one", "two", "three", "four"])

    assert files(context) == [
             "sovite.2026-10-04.3.log",
             "sovite.2026-10-04.4.log",
             "unrelated.txt"
           ]
  end

  test "continues the newest file on restart, unless it is full", context do
    id = start_handler(context, %{max_size: 10})
    log(id, "first")
    stop_supervised!({FileHandler, id})

    id = start_handler(context, %{max_size: 10})
    log(id, "123")
    stop_supervised!({FileHandler, id})

    assert read(context, "sovite.2026-10-04.1.log") == "first\n123\n"

    id = start_handler(context, %{max_size: 10})
    log(id, "next")

    assert read(context, "sovite.2026-10-04.2.log") == "next\n"
  end

  test "keeps a symlink pointing at the current file", context do
    id = start_handler(context, %{max_size: 5, symlink: "current.log"})
    link = Path.join(context.tmp_dir, "current.log")

    log(id, "one")
    assert File.read_link!(link) == "sovite.2026-10-04.1.log"

    log(id, "two")
    assert File.read_link!(link) == "sovite.2026-10-04.2.log"
    assert File.read!(link) == "two\n"
  end

  test "reopens the file when it is deleted", context do
    id = start_handler(context)
    log(id, "before")
    File.rm!(Path.join(context.tmp_dir, "sovite.2026-10-04.1.log"))

    {:ok, %{config: %{writer: writer}}} = :logger.get_handler_config(id)
    send(writer, :check_file)
    log(id, "after")

    assert read(context, "sovite.2026-10-04.1.log") == "after\n"
  end

  test "fails to start when the directory cannot be created", context do
    file = Path.join(context.tmp_dir, "file")
    File.write!(file, "")

    assert {:error, {{:cannot_open_log_file, _path, :enotdir}, _child}} =
             start_supervised(
               {FileHandler,
                id: :file_handler_test_bad_dir,
                formatter: @formatter,
                config: %{
                  directory: Path.join(file, "logs"),
                  file_name: "{n}.log",
                  date_format: "",
                  max_size: 10,
                  rotation: :never,
                  max_files: 0,
                  symlink: nil
                }}
             )

    assert {:error, {:not_found, _}} = :logger.get_handler_config(:file_handler_test_bad_dir)
  end

  test "drops events when overloaded and reports how many", context do
    id = start_handler(context, %{max_size: 1024 * 1024})

    {:ok, %{config: %{writer: writer, atomics: atomics}} = config} =
      :logger.get_handler_config(id)

    :sys.suspend(writer)

    for i <- 1..300 do
      event = %{level: :info, msg: {:string, "event #{i}"}, meta: %{time: :logger.timestamp()}}
      spawn(fn -> FileHandler.log(event, config) end)
    end

    wait_until(fn -> :atomics.get(atomics, 1) + :atomics.get(atomics, 2) == 300 end)
    :sys.resume(writer)
    # Callers count an event as queued just before sending it.
    wait_until(fn -> :atomics.get(atomics, 1) == 0 end)
    :ok = FileHandler.sync(id)

    lines = context |> read("sovite.2026-10-04.1.log") |> String.split("\n", trim: true)

    assert Enum.count(lines, &(&1 =~ "event ")) == 200
    assert Enum.count(lines, &(&1 =~ "100 log events dropped")) == 1
  end

  test "goes through :logger and replaces another handler while running", context do
    replaced = :"file_handler_test_null_#{System.unique_integer([:positive])}"
    :ok = :logger.add_handler(replaced, NullHandler, %{level: :info, filter_default: :stop})
    on_exit(fn -> :logger.remove_handler(replaced) end)

    id = start_handler(context, %{}, level: :all, replace: replaced)

    assert {:ok, %{level: :none}} = :logger.get_handler_config(replaced)
    assert {:ok, %{filter_default: :stop}} = :logger.get_handler_config(id)

    stop_supervised!({FileHandler, id})

    assert {:ok, %{level: :info}} = :logger.get_handler_config(replaced)
    assert {:error, {:not_found, ^id}} = :logger.get_handler_config(id)
  end

  test "writes events logged through Logger", context do
    id = start_handler(context, %{}, level: :all)
    marker = "file handler test #{System.unique_integer([:positive])}"

    capture_log(fn -> Logger.error(marker) end)
    :ok = FileHandler.sync(id)

    assert read(context, "sovite.2026-10-04.1.log") =~ marker
  end

  defp wait_until(fun, attempts \\ 200) do
    cond do
      fun.() ->
        :ok

      attempts == 0 ->
        flunk("condition not met")

      true ->
        Process.sleep(5)
        wait_until(fun, attempts - 1)
    end
  end
end
