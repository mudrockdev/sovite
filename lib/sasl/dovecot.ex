defmodule Sovite.SASL.Dovecot do
  @moduledoc """
  Hands SASL authentication to a Dovecot auth server, over its client
  protocol (version 1.2), like Postfix's `smtpd_sasl_type = dovecot`.

  Dovecot runs the mechanism and checks the credentials against whatever
  it is set up with; Sovite only relays the exchange. Each exchange uses
  its own connection, opened by `start/3` and closed when it ends.

  ## Options

    * `:socket` - path of Dovecot's auth client socket, for example
      `/run/dovecot/auth-client`, or `{host, port}` for TCP. Required.
    * `:service` - the service name Dovecot sees. Defaults to `"smtp"`.
    * `:timeout` - milliseconds to wait for Dovecot. Defaults to 30 seconds.
    * `:client` - about the SMTP client, passed on for Dovecot's policies
      and logs: `:remote_ip`, `:remote_port`, `:local_ip`, `:local_port`,
      and `:secured` (the connection is encrypted).

  ## Errors

  As for `Sovite.SASL.Server`: `:invalid_credentials`, `:temporary` (Dovecot
  is down or said `temp`), or `:malformed`.
  """

  @enforce_keys [:socket, :id, :timeout]
  defstruct [:socket, :id, :timeout, buffer: ""]

  @opaque t :: %__MODULE__{}

  @type result ::
          {:ok, identity :: String.t()}
          | {:challenge, binary(), t()}
          | {:error, Sovite.SASL.Server.error(), username :: String.t() | nil}

  @doc "Asks Dovecot which mechanisms it offers."
  @spec mechanisms(keyword()) :: {:ok, [String.t()]} | {:error, term()}
  def mechanisms(opts) do
    with {:ok, conn, mechs} <- connect(opts) do
      :gen_tcp.close(conn.socket)
      {:ok, mechs}
    end
  end

  @doc "Starts an exchange. `initial` is as for `Sovite.SASL.Server.start/3`."
  @spec start(String.t(), binary() | nil, keyword()) :: result()
  def start(mechanism, initial, opts) do
    case connect(opts) do
      {:ok, conn, _mechs} ->
        params =
          ["service=" <> Keyword.get(opts, :service, "smtp")] ++
            client_params(Keyword.get(opts, :client, %{})) ++
            if(initial, do: ["resp=" <> Base.encode64(initial)], else: [])

        line = Enum.join(["AUTH", conn.id, mechanism | Enum.map(params, &escape/1)], "\t")

        case send_line(conn, line) do
          :ok -> read_result(conn)
          {:error, _reason} -> fail(conn, :temporary, nil)
        end

      {:error, _reason} ->
        {:error, :temporary, nil}
    end
  end

  @doc "Sends the client's response to Dovecot's last challenge."
  @spec step(t(), binary()) :: result()
  def step(%__MODULE__{} = conn, response) do
    case send_line(conn, "CONT\t#{conn.id}\t#{Base.encode64(response)}") do
      :ok -> read_result(conn)
      {:error, _} -> {:error, :temporary, nil}
    end
  end

  @doc "Abandons an exchange and closes its connection."
  @spec abort(t()) :: :ok
  def abort(%__MODULE__{socket: socket}) do
    _ = :gen_tcp.close(socket)
    :ok
  end

  defp client_params(client) do
    [
      client[:secured] && "secured",
      client[:remote_ip] && "rip=#{:inet.ntoa(client.remote_ip)}",
      client[:local_ip] && "lip=#{:inet.ntoa(client.local_ip)}",
      client[:remote_port] && "rport=#{client.remote_port}",
      client[:local_port] && "lport=#{client.local_port}"
    ]
    |> Enum.filter(& &1)
  end

  ## Connection and handshake

  defp connect(opts) do
    timeout = Keyword.get(opts, :timeout, 30_000)

    {address, port} =
      case Keyword.fetch!(opts, :socket) do
        {host, port} -> {to_charlist(host), port}
        path when is_binary(path) -> {{:local, path}, 0}
      end

    tcp_opts = [:binary, active: false, packet: :line, packet_size: 65_536]

    with {:ok, socket} <- :gen_tcp.connect(address, port, tcp_opts, timeout) do
      conn = %__MODULE__{socket: socket, id: "1", timeout: timeout}

      with :ok <- send_line(conn, "VERSION\t1\t2\nCPID\t#{System.pid()}"),
           {:ok, mechs} <- handshake(conn, []) do
        {:ok, conn, mechs}
      else
        error ->
          :gen_tcp.close(socket)
          error
      end
    end
  end

  # Reads until DONE, collecting MECH lines. A major version other than
  # 1 is not understood.
  defp handshake(conn, mechs) do
    case read_line(conn) do
      {:ok, ["VERSION", "1" | _]} -> handshake(conn, mechs)
      {:ok, ["VERSION" | _]} -> {:error, :unsupported_version}
      {:ok, ["MECH", mech | _]} -> handshake(conn, [mech | mechs])
      {:ok, ["DONE" | _]} -> {:ok, Enum.reverse(mechs)}
      {:ok, _other} -> handshake(conn, mechs)
      {:error, _} = error -> error
    end
  end

  ## Exchange

  defp read_result(conn) do
    id = conn.id

    case read_line(conn) do
      {:ok, [kind, ^id | rest]} when kind in ["OK", "CONT", "FAIL"] -> result(kind, rest, conn)
      _ -> fail(conn, :temporary, nil)
    end
  end

  defp result("OK", params, conn) do
    :gen_tcp.close(conn.socket)

    case parse_params(params)["user"] do
      user when is_binary(user) and user != "" -> {:ok, user}
      _ -> {:error, :temporary, nil}
    end
  end

  defp result("CONT", data, conn) do
    case Base.decode64(Enum.join(data)) do
      {:ok, challenge} -> {:challenge, challenge, conn}
      :error -> fail(conn, :temporary, nil)
    end
  end

  defp result("FAIL", params, conn) do
    params = parse_params(params)
    reason = if Map.has_key?(params, "temp"), do: :temporary, else: failure(params)
    fail(conn, reason, params["user"])
  end

  defp failure(%{"code" => "temp_fail"}), do: :temporary
  defp failure(_params), do: :invalid_credentials

  defp fail(conn, reason, username) do
    :gen_tcp.close(conn.socket)
    {:error, reason, username}
  end

  defp parse_params(params) do
    Map.new(params, fn param ->
      case :binary.split(param, "=") do
        [key, value] -> {key, unescape(value)}
        [flag] -> {flag, true}
      end
    end)
  end

  ## I/O

  defp send_line(conn, line), do: :gen_tcp.send(conn.socket, [line, "\n"])

  defp read_line(conn) do
    case :gen_tcp.recv(conn.socket, 0, conn.timeout) do
      {:ok, line} ->
        {:ok, line |> String.trim_trailing("\n") |> String.split("\t")}

      {:error, _} = error ->
        error
    end
  end

  # Dovecot's tab escaping: \001 is the escape character.
  defp escape(value) do
    value
    |> String.replace("\x01", "\x011")
    |> String.replace("\t", "\x01t")
    |> String.replace("\r", "\x01r")
    |> String.replace("\n", "\x01n")
  end

  defp unescape(value) do
    Regex.replace(~r/\x01(.)/, value, fn
      _, "1" -> "\x01"
      _, "t" -> "\t"
      _, "r" -> "\r"
      _, "n" -> "\n"
      _, other -> other
    end)
  end
end
