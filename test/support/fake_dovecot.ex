defmodule Sovite.Test.FakeDovecot do
  @moduledoc """
  A fake Dovecot auth server on a Unix socket, speaking the auth client
  protocol. Knows `PLAIN` and `LOGIN` against `:users` (name => password).
  Each `AUTH` line is sent to the owner as `{:dovecot, :auth, fields}`.
  The user `"tempfail"` gets a temporary failure.
  """

  use GenServer

  def start_link(opts) do
    opts = Keyword.put_new(opts, :owner, self())
    GenServer.start_link(__MODULE__, opts)
  end

  @impl true
  def init(opts) do
    path = Keyword.fetch!(opts, :path)
    File.rm(path)

    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, ifaddr: {:local, path}, active: false, packet: :line])

    config = Map.new(opts)
    spawn_link(fn -> accept(listen, config) end)
    {:ok, listen}
  end

  defp accept(listen, config) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        pid = spawn(fn -> receive(do: (:go -> serve(socket, config))) end)
        :gen_tcp.controlling_process(socket, pid)
        send(pid, :go)
        accept(listen, config)

      _ ->
        :ok
    end
  end

  defp serve(socket, config) do
    :gen_tcp.send(socket, [
      "VERSION\t1\t2\n",
      "MECH\tPLAIN\tplaintext\n",
      "MECH\tLOGIN\tplaintext\n",
      "SPID\t123\nCUID\t1\nCOOKIE\tabc\nDONE\n"
    ])

    loop(socket, config, nil)
  end

  defp loop(socket, config, state) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, line} ->
        fields = line |> String.trim_trailing("\n") |> String.split("\t")
        state = handle(fields, socket, config, state)
        loop(socket, config, state)

      _ ->
        :gen_tcp.close(socket)
    end
  end

  defp handle(["AUTH", id, mech | params] = fields, socket, config, _state) do
    send(config.owner, {:dovecot, :auth, fields})

    resp =
      Enum.find_value(params, fn
        "resp=" <> r -> Base.decode64!(r)
        _ -> nil
      end)

    case {mech, resp} do
      {"PLAIN", nil} ->
        reply(socket, "CONT\t#{id}\t")
        {:plain, id}

      {"PLAIN", resp} ->
        check_plain(socket, config, id, resp)

      {"LOGIN", nil} ->
        reply(socket, "CONT\t#{id}\t#{Base.encode64("Username:")}")
        {:login_user, id}

      _ ->
        reply(socket, "FAIL\t#{id}\treason=unsupported")
    end
  end

  defp handle(["CONT", id, data], socket, config, {:plain, id}),
    do: check_plain(socket, config, id, Base.decode64!(data))

  defp handle(["CONT", id, data], socket, _config, {:login_user, id}) do
    reply(socket, "CONT\t#{id}\t#{Base.encode64("Password:")}")
    {:login_pass, id, Base.decode64!(data)}
  end

  defp handle(["CONT", id, data], socket, config, {:login_pass, id, user}),
    do: check(socket, config, id, user, Base.decode64!(data))

  defp handle(_fields, _socket, _config, state), do: state

  defp check_plain(socket, config, id, resp) do
    [_authz, user, pass] = String.split(resp, <<0>>)
    check(socket, config, id, user, pass)
  end

  defp check(socket, _config, id, "tempfail", _pass),
    do: reply(socket, "FAIL\t#{id}\tuser=tempfail\ttemp")

  defp check(socket, config, id, user, pass) do
    if Map.get(config.users, user) == pass,
      do: reply(socket, "OK\t#{id}\tuser=#{user}"),
      else: reply(socket, "FAIL\t#{id}\tuser=#{user}\treason=Password mismatch")
  end

  defp reply(socket, line) do
    :gen_tcp.send(socket, line <> "\n")
    nil
  end
end
