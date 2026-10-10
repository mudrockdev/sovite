defmodule Sovite.Test.FakeMilter do
  @moduledoc """
  A scripted milter for tests: stands in for Rspamd, OpenDKIM, and the
  like on a local TCP port (or a Unix socket), speaking the milter
  protocol with `Sovite.Milter.Packet`.

      fake = start_supervised!({FakeMilter, replies: %{mail: :reject}})
      {:ok, milter} = Sovite.Milter.connect(FakeMilter.address(fake))

  It accepts any number of connections. Every command it receives is sent
  to the owner as `{:milter, command, data}`:

    * `{:milter, :optneg, %{version: 6, actions: [atom], protocol: [atom]}}`
      - what the MTA offered.
    * `{:milter, :macro, {stage, [{name, value}]}}` - `stage` is the
      command the macros belong to: `:connect`, `:helo`, `:mail`,
      `:rcpt`, `:data`, `:end_of_headers`, or `:end_of_message`.
    * `{:milter, :connect, {hostname, family, port, address}}` - family
      `:inet`, `:inet6`, `:unix`, or `:unknown` (port and address `nil`).
    * `{:milter, :helo, name}`, `{:milter, :unknown, line}`
    * `{:milter, :mail, ["<sender>" | args]}`, `{:milter, :rcpt,
      ["<recipient>" | args]}`
    * `{:milter, :header, {name, value}}` - the value as on the wire.
    * `{:milter, :body, chunk}`
    * `{:milter, command, nil}` for `:data`, `:end_of_headers`,
      `:end_of_message`, `:abort`, `:quit`, and `:quit_new_connection`.

  ## Options

    * `:owner` - the process that receives messages. Defaults to the caller.
    * `:path` - listen on this Unix socket path instead of a TCP port.
    * `:version` - the protocol version to answer with. Defaults to 6.
    * `:actions` - the actions to ask for (atoms, see
      `Sovite.Milter.Packet`). Defaults to all of them.
    * `:protocol` - the protocol flags to ask for, such as `:no_helo` or
      `:no_header_reply`. Defaults to none. Commands with a no-reply flag
      get no reply.
    * `:macros` - macros to ask for, a map of stage (`:connect`, `:helo`,
      `:mail`, `:rcpt`, `:data`, `:end_of_message`, `:end_of_headers`) to
      a list of names.
    * `:optneg` - a reply spec (see below) sent instead of the normal
      negotiation reply, to test broken milters.
    * `:replies` - how to answer each command, see below.
    * `:modifications` - modifications sent before the default `:accept`
      at the end of the message. Defaults to none.

  ## Replies

  `:replies` is a map of command (`:connect`, `:helo`, `:mail`, `:rcpt`,
  `:data`, `:header`, `:end_of_headers`, `:body`, `:end_of_message`,
  `:unknown`) to a reply spec, or to a function of the command's data (as
  in the messages above) and, optionally, the session, that returns one.
  It can also be a function of the command, its data, and the session.
  A function returning `:default` gets the default reply: `:continue`,
  and at the end of the message the `:modifications` and `:accept`.

  The session is a map of what the connection has seen: `:macros` (a map
  of all macros so far), `:helo`, `:mail` and `:rcpts` (as in the
  messages, the transaction's), `:headers` (`{name, value}` pairs), and
  `:body`. The transaction's parts are cleared by an abort and after the
  end of the message.

  A reply spec is a `t:Sovite.Milter.Packet.response/0` (such as
  `:reject`, `{:reply_code, "550 5.7.1 Spam"}`, or `{:add_header, "X-Spam",
  "yes"}`), `{:delete_header, index, name}`, `{:delay, ms}`, `{:bytes,
  binary}` (sent as they are), `:close` (drop the connection), `:none`
  (send nothing), or a list of those, sent in order.

      # Rspamd: tags every message, rejects mail from spam@example.net.
      replies: %{
        end_of_message: fn _data, session ->
          verdict = if hd(session.mail) == "<spam@example.net>", do: :reject, else: :accept
          [{:add_header, "X-Spam", "yes"}, verdict]
        end
      }
  """

  use GenServer

  import Bitwise

  alias Sovite.Milter.Packet

  @macro_stages %{
    connect: 0,
    helo: 1,
    mail: 2,
    rcpt: 3,
    data: 4,
    end_of_message: 5,
    end_of_headers: 6
  }

  # Commands that are answered, and their no-reply flags.
  @no_reply %{
    connect: 0x1000,
    helo: 0x2000,
    mail: 0x4000,
    rcpt: 0x8000,
    data: 0x10000,
    unknown: 0x20000,
    header: 0x80,
    end_of_headers: 0x40000,
    body: 0x80000,
    end_of_message: 0
  }

  @empty_transaction %{mail: nil, rcpts: [], headers: [], body: ""}

  def start_link(opts \\ []) do
    opts = Keyword.put_new(opts, :owner, self())
    GenServer.start_link(__MODULE__, opts)
  end

  @doc "Returns the address to pass to `Sovite.Milter.connect/2`."
  def address(server), do: GenServer.call(server, :address)

  @impl true
  def init(opts) do
    {listen_opts, address} =
      case Keyword.get(opts, :path) do
        nil ->
          {[ip: {127, 0, 0, 1}, reuseaddr: true], nil}

        path ->
          File.rm(path)
          {[:local, ifaddr: {:local, path}], {:unix, path}}
      end

    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, packet: :raw] ++ listen_opts)

    address =
      address ||
        with {:ok, port} <- :inet.port(listen), do: {:inet, {127, 0, 0, 1}, port}

    config = %{
      owner: Keyword.fetch!(opts, :owner),
      version: Keyword.get(opts, :version, 6),
      actions: Packet.action_mask(Keyword.get(opts, :actions, Packet.actions(0x1FF))),
      protocol: Packet.protocol_mask(Keyword.get(opts, :protocol, [])),
      macros: Keyword.get(opts, :macros, %{}),
      optneg: Keyword.get(opts, :optneg),
      replies: Keyword.get(opts, :replies, %{}),
      modifications: Keyword.get(opts, :modifications, [])
    }

    spawn_link(fn -> accept(listen, config) end)
    {:ok, %{listen: listen, address: address}}
  end

  @impl true
  def handle_call(:address, _from, state), do: {:reply, state.address, state}

  ## Connections

  defp accept(listen, config) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        pid = spawn_link(fn -> receive(do: (:go -> serve(socket, config))) end)
        :ok = :gen_tcp.controlling_process(socket, pid)
        send(pid, :go)
        accept(listen, config)

      {:error, _} ->
        :ok
    end
  end

  defp serve(socket, config) do
    session = Map.merge(%{socket: socket, buffer: "", macros: %{}, helo: nil}, @empty_transaction)
    loop(session, config)
  end

  defp loop(session, config) do
    case Packet.decode(session.buffer, 64 * 1024 * 1024) do
      {:ok, {byte, data}, rest} ->
        {:ok, command} = Packet.decode_command(byte, data)
        session = handle(command, %{session | buffer: rest}, config)
        loop(session, config)

      :more ->
        case :gen_tcp.recv(session.socket, 0) do
          {:ok, data} -> loop(%{session | buffer: session.buffer <> data}, config)
          {:error, _} -> :gen_tcp.close(session.socket)
        end
    end
  end

  defp handle({:optneg, version, actions, protocol}, session, config) do
    notify(config, :optneg, %{
      version: version,
      actions: Packet.actions(actions),
      protocol: Packet.protocol(protocol)
    })

    macros =
      for {stage, names} <- config.macros,
          do: {Map.fetch!(@macro_stages, stage), Enum.join(names, " ")}

    reply =
      config.optneg ||
        {:optneg, config.version, config.actions, config.protocol &&& protocol, macros}

    send_specs(session, reply)
  end

  defp handle({:macro, byte, pairs}, session, config) do
    notify(config, :macro, {macro_stage(byte), pairs})
    %{session | macros: Map.merge(session.macros, Map.new(pairs))}
  end

  defp handle({:connect, hostname, family, port, address}, session, config),
    do: answer(:connect, {hostname, family, port, address}, session, config)

  defp handle({:helo, name}, session, config),
    do: answer(:helo, name, %{session | helo: name}, config)

  defp handle({:mail, args}, session, config),
    do: answer(:mail, args, Map.merge(session, %{@empty_transaction | mail: args}), config)

  defp handle({:rcpt, args}, session, config),
    do: answer(:rcpt, args, %{session | rcpts: session.rcpts ++ [args]}, config)

  defp handle(:data, session, config), do: answer(:data, nil, session, config)

  defp handle({:header, name, value}, session, config),
    do:
      answer(
        :header,
        {name, value},
        %{session | headers: session.headers ++ [{name, value}]},
        config
      )

  defp handle(:end_of_headers, session, config), do: answer(:end_of_headers, nil, session, config)

  defp handle({:body, chunk}, session, config),
    do: answer(:body, chunk, %{session | body: session.body <> chunk}, config)

  defp handle(:end_of_message, session, config) do
    session = answer(:end_of_message, nil, session, config)
    Map.merge(session, @empty_transaction)
  end

  defp handle({:unknown, line}, session, config), do: answer(:unknown, line, session, config)

  defp handle(:abort, session, config) do
    notify(config, :abort, nil)
    Map.merge(session, @empty_transaction)
  end

  defp handle(:quit, session, config) do
    notify(config, :quit, nil)
    :gen_tcp.close(session.socket)
    exit(:normal)
  end

  defp handle(:quit_new_connection, session, config) do
    notify(config, :quit_new_connection, nil)
    session |> Map.merge(@empty_transaction) |> Map.merge(%{macros: %{}, helo: nil})
  end

  defp answer(command, data, session, config) do
    notify(config, command, data)

    if (config.protocol &&& Map.fetch!(@no_reply, command)) != 0 do
      session
    else
      send_specs(session, reply(command, data, session, config))
    end
  end

  defp reply(command, data, session, config) do
    spec =
      case config.replies do
        fun when is_function(fun, 3) -> fun.(command, data, session)
        replies -> replies |> Map.get(command, :default) |> call(data, session)
      end

    case {spec, command} do
      {:default, :end_of_message} -> config.modifications ++ [:accept]
      {:default, _} -> :continue
      {spec, _} -> spec
    end
  end

  defp call(fun, data, _session) when is_function(fun, 1), do: fun.(data)
  defp call(fun, data, session) when is_function(fun, 2), do: fun.(data, session)
  defp call(spec, _data, _session), do: spec

  defp send_specs(session, specs) do
    Enum.each(List.wrap(specs), &send_spec(session.socket, &1))
    session
  end

  defp send_spec(socket, :close) do
    :gen_tcp.close(socket)
    exit(:normal)
  end

  defp send_spec(_socket, :none), do: :ok
  defp send_spec(_socket, {:delay, ms}), do: Process.sleep(ms)
  defp send_spec(socket, {:bytes, bytes}), do: :gen_tcp.send(socket, bytes)

  defp send_spec(socket, {:delete_header, index, name}),
    do: send_spec(socket, {:change_header, index, name, ""})

  defp send_spec(socket, response), do: :gen_tcp.send(socket, Packet.encode_response(response))

  defp macro_stage(?C), do: :connect
  defp macro_stage(?H), do: :helo
  defp macro_stage(?M), do: :mail
  defp macro_stage(?R), do: :rcpt
  defp macro_stage(?T), do: :data
  defp macro_stage(?N), do: :end_of_headers
  defp macro_stage(?E), do: :end_of_message
  defp macro_stage(byte), do: byte

  defp notify(config, command, data), do: send(config.owner, {:milter, command, data})
end
