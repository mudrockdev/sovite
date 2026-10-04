defmodule Sovite.Core.LoggingTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Logging
  alias Sovite.Core.Logging.JSONFormatter

  @time 1_791_115_200_123_456

  defp format(msg, meta, config \\ %{metadata: Logging.metadata_keys()}) do
    event = %{level: :info, msg: msg, meta: Map.put(meta, :time, @time)}
    event |> JSONFormatter.format(config) |> IO.iodata_to_binary()
  end

  test "writes one JSON object per line with the standard fields" do
    line =
      format({:string, "accepted"}, %{queue_id: "4Xb2Kq", remote_ip: {192, 0, 2, 7}, pid: self()})

    assert String.ends_with?(line, "\n")

    assert JSON.decode!(line) == %{
             "time" => "2026-10-04T12:00:00.123456Z",
             "level" => "info",
             "msg" => "accepted",
             "queue_id" => "4Xb2Kq",
             "remote_ip" => "192.0.2.7"
           }
  end

  test "renders format strings and reports" do
    assert JSON.decode!(format({~c"~p items", [3]}, %{}))["msg"] == "3 items"
    assert JSON.decode!(format({:report, %{a: 1}}, %{}))["msg"] == "%{a: 1}"

    cb = fn report -> {~c"report: ~p", [report.a]} end
    assert JSON.decode!(format({:report, %{a: 1}}, %{report_cb: cb}))["msg"] == "report: 1"
  end

  test "supports two-arity report callbacks" do
    cb = fn report, _opts -> "two-arity: #{report.a}" end
    assert JSON.decode!(format({:report, %{a: 1}}, %{report_cb: cb}))["msg"] == "two-arity: 1"
  end

  test "never crashes the handler on a bad message" do
    line = format({~c"~p ~p", [:only_one]}, %{})
    assert line =~ "log formatting failed"
    assert String.ends_with?(line, "\n")
  end

  test "keeps invalid UTF-8 metadata readable" do
    line = format({:string, "x"}, %{session_id: <<0xFF, 0xFE>>})
    assert JSON.decode!(line)["session_id"] == inspect(<<0xFF, 0xFE>>)
  end

  test "includes all non-internal metadata with :all" do
    decoded =
      JSON.decode!(format({:string, "x"}, %{custom: :value, gl: self()}, %{metadata: :all}))

    assert decoded["custom"] == "value"
    refute Map.has_key?(decoded, "gl")
  end

  test "text formatter includes the standard metadata" do
    {Logger.Formatter, config} = Logging.formatter(:text)
    event = %{level: :info, msg: {:string, "hello"}, meta: %{time: @time, queue_id: "Q1"}}

    assert event |> Logger.Formatter.format(config) |> IO.iodata_to_binary() =~
             "[info] queue_id=Q1 hello"
  end
end
