defmodule Sovite.Test.SMTPClient do
  @moduledoc """
  A minimal line-level SMTP client for driving servers in tests.

  It is deliberately dumb: it sends exactly what it is given, so tests can
  also send malformed or adversarial input.

      {:ok, client} = SMTPClient.connect(port)
      {:ok, {220, _}} = SMTPClient.read_reply(client)
      {:ok, {250, _}} = SMTPClient.command(client, "EHLO client.test")
  """

  @timeout 5_000

  defstruct [:socket, transport: :gen_tcp]

  @type t :: %__MODULE__{socket: term(), transport: :gen_tcp | :ssl}
  @type reply :: {code :: 100..599, lines :: [String.t()]}

  @doc """
  Connects to `host:port`. The greeting is not read. `opts` are extra
  `:gen_tcp` options, such as `ip: {127, 0, 0, 2}` for the source address.
  """
  @spec connect(:inet.port_number(), :inet.socket_address() | charlist(), keyword()) ::
          {:ok, t()} | {:error, term()}
  def connect(port, host \\ {127, 0, 0, 1}, opts \\ []) do
    opts = [:binary, active: false, packet: :line, buffer: 65_536] ++ opts

    with {:ok, socket} <- :gen_tcp.connect(host, port, opts, @timeout) do
      {:ok, %__MODULE__{socket: socket}}
    end
  end

  @doc "Connects with implicit TLS. The greeting is not read."
  def connect_tls(port, ssl_opts) do
    opts = [:binary, active: false, packet: :line, buffer: 65_536]

    with {:ok, socket} <- :ssl.connect({127, 0, 0, 1}, port, opts ++ ssl_opts, @timeout) do
      {:ok, %__MODULE__{socket: socket, transport: :ssl}}
    end
  end

  @doc "Sends STARTTLS and, on 220, runs the TLS handshake."
  def starttls(client, ssl_opts) do
    with {:ok, {220, _}} <- command(client, "STARTTLS"), do: upgrade(client, ssl_opts)
  end

  @doc "Runs a client TLS handshake on the connection."
  def upgrade(%__MODULE__{transport: :gen_tcp, socket: socket}, ssl_opts) do
    with {:ok, ssl} <- :ssl.connect(socket, ssl_opts, @timeout) do
      {:ok, %__MODULE__{socket: ssl, transport: :ssl}}
    end
  end

  @doc "Sends `line` followed by CRLF and reads the reply."
  @spec command(t(), iodata()) :: {:ok, reply()} | {:error, term()}
  def command(client, line) do
    with :ok <- send_raw(client, [line, "\r\n"]), do: read_reply(client)
  end

  @doc """
  Sends `body` as DATA content. Dot-stuffs it, ends it with `CRLF.CRLF`,
  and reads the reply. Send `DATA` with `command/2` first.
  """
  @spec send_data(t(), iodata()) :: {:ok, reply()} | {:error, term()}
  def send_data(client, body) do
    body = IO.iodata_to_binary(body)
    body = if String.ends_with?(body, "\r\n") or body == "", do: body, else: body <> "\r\n"
    stuffed = String.replace(body, ~r/^\./m, "..")

    with :ok <- send_raw(client, [stuffed, ".\r\n"]), do: read_reply(client)
  end

  @doc """
  Runs a whole transaction (EHLO, MAIL, RCPT, DATA). Returns the reply
  to the final dot. Stops at the first unexpected reply and returns it as
  `{:error, {stage, reply}}`.
  """
  @spec send_message(t(), String.t(), [String.t()], iodata(), keyword()) ::
          {:ok, reply()} | {:error, term()}
  def send_message(client, from, recipients, body, opts \\ []) do
    helo = Keyword.get(opts, :helo, "client.test")

    with {:ok, {220, _}} <- expect(read_reply(client), :greeting, 220),
         {:ok, _} <- expect(command(client, "EHLO #{helo}"), :ehlo, 250),
         {:ok, _} <- expect(command(client, "MAIL FROM:<#{from}>"), :mail, 250),
         :ok <- send_recipients(client, recipients),
         {:ok, _} <- expect(command(client, "DATA"), :data, 354) do
      send_data(client, body)
    end
  end

  @doc "Sends raw bytes as-is."
  @spec send_raw(t(), iodata()) :: :ok | {:error, term()}
  def send_raw(%__MODULE__{transport: transport, socket: socket}, data),
    do: transport.send(socket, data)

  @doc "Reads one (possibly multi-line) reply."
  @spec read_reply(t(), timeout()) :: {:ok, reply()} | {:error, term()}
  def read_reply(%__MODULE__{} = client, timeout \\ @timeout),
    do: read_lines(client, timeout, [])

  @doc "Closes the connection."
  @spec close(t()) :: :ok
  def close(%__MODULE__{transport: transport, socket: socket}) do
    _ = transport.close(socket)
    :ok
  end

  defp read_lines(%{transport: transport, socket: socket} = client, timeout, acc) do
    with {:ok, line} <- transport.recv(socket, 0, timeout) do
      case String.trim_trailing(line, "\r\n") do
        <<_code::binary-size(3), "-", text::binary>> ->
          read_lines(client, timeout, [text | acc])

        <<code::binary-size(3), " ", text::binary>> ->
          finish(code, [text | acc])

        <<code::binary-size(3)>> ->
          finish(code, ["" | acc])

        other ->
          {:error, {:malformed_reply, other}}
      end
    end
  end

  defp finish(code, acc) do
    case Integer.parse(code) do
      {n, ""} when n in 100..599 -> {:ok, {n, Enum.reverse(acc)}}
      _ -> {:error, {:malformed_reply, code}}
    end
  end

  defp send_recipients(client, recipients) do
    Enum.reduce_while(recipients, :ok, fn rcpt, :ok ->
      case expect(command(client, "RCPT TO:<#{rcpt}>"), {:rcpt, rcpt}, 250) do
        {:ok, _} -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp expect({:ok, {code, _} = reply}, _stage, code), do: {:ok, reply}
  defp expect({:ok, reply}, stage, _code), do: {:error, {stage, reply}}
  defp expect({:error, _} = error, _stage, _code), do: error
end
