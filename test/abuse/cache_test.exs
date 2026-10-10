defmodule Sovite.Abuse.CacheTest do
  use ExUnit.Case, async: true

  alias Sovite.Abuse.Cache

  defp start(opts \\ []) do
    name = :"cache_#{System.unique_integer([:positive])}"
    pid = start_supervised!({Cache, [name: name] ++ opts})
    {name, pid}
  end

  test "stores, overwrites, and deletes entries" do
    {name, _pid} = start()

    assert Cache.get(name, :ip) == :error
    assert Cache.put(name, :ip, :passed, 60_000) == :ok
    assert Cache.get(name, :ip) == {:ok, :passed}
    assert Cache.put(name, :ip, :failed, 60_000) == :ok
    assert Cache.get(name, :ip) == {:ok, :failed}
    assert Cache.size(name) == 1

    assert Cache.delete(name, :ip) == :ok
    assert Cache.delete(name, :ip) == :ok
    assert Cache.get(name, :ip) == :error
    assert Cache.size(name) == 0
  end

  test "entries expire" do
    {name, _pid} = start()

    assert Cache.put(name, :now, :value, 0) == :ok
    assert Cache.get(name, :now) == :error
    assert Cache.put(name, :soon, :value, 10) == :ok
    Process.sleep(20)
    assert Cache.get(name, :soon) == :error
    assert Cache.size(name) == 2
  end

  test "refuses new keys when full" do
    {name, _pid} = start(max_entries: 2)

    assert Cache.put(name, :a, 1, 60_000) == :ok
    assert Cache.put(name, :b, 2, 60_000) == :ok
    assert Cache.put(name, :c, 3, 60_000) == :full
    assert Cache.get(name, :c) == :error
    assert Cache.put(name, :a, 10, 60_000) == :ok
    assert Cache.get(name, :a) == {:ok, 10}
    assert Cache.size(name) == 2

    Cache.delete(name, :b)
    assert Cache.put(name, :c, 3, 60_000) == :ok
  end

  test "purges expired entries" do
    {name, pid} = start(max_entries: 2)
    Cache.put(name, :old, 1, 0)
    Cache.put(name, :new, 2, 60_000)
    assert Cache.put(name, :other, 3, 60_000) == :full

    send(pid, :cleanup)
    :sys.get_state(pid)
    assert Cache.size(name) == 1
    assert Cache.get(name, :new) == {:ok, 2}
    assert Cache.put(name, :other, 3, 60_000) == :ok
  end
end
