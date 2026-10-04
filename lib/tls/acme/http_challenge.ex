defmodule Sovite.TLS.ACME.HTTPChallenge do
  @moduledoc """
  Answers ACME HTTP-01 challenges (RFC 8555 §8.3): a `Sovite.Listener`
  handler that serves `GET /.well-known/acme-challenge/<token>` from an
  ETS table of `{token, key_authorization}` and answers everything else
  with 404.

      table = :ets.new(:challenges, [:public])
      {Sovite.Listener, port: 80, handler: Sovite.TLS.ACME.HTTPChallenge, handler_opts: [table: table]}

  Requests larger than 8 KiB, or slower than 10 seconds, are dropped.
  """

  @behaviour Sovite.Listener.Handler

  @max_request 8192
  @timeout 10_000

  @impl true
  def start_link(info, opts), do: {:ok, spawn_link(fn -> serve(info, opts) end)}

  defp serve(info, opts) do
    with :ok <- Sovite.Listener.handshake(info),
         {:ok, request} <- read(info.socket, "") do
      :gen_tcp.send(info.socket, respond(request, Keyword.fetch!(opts, :table)))
    end

    :gen_tcp.close(info.socket)
  end

  defp read(socket, acc) do
    cond do
      String.contains?(acc, "\r\n\r\n") or String.contains?(acc, "\n\n") ->
        {:ok, acc}

      byte_size(acc) > @max_request ->
        :error

      true ->
        case :gen_tcp.recv(socket, 0, @timeout) do
          {:ok, data} -> read(socket, acc <> data)
          {:error, _} -> :error
        end
    end
  end

  defp respond(request, table) do
    with [line | _] <- String.split(request, ["\r\n", "\n"], parts: 2),
         ["GET", "/.well-known/acme-challenge/" <> token, "HTTP/1." <> _] <-
           String.split(line, " "),
         true <- Regex.match?(~r/\A[A-Za-z0-9_-]+\z/, token),
         [{^token, key_authorization}] <- :ets.lookup(table, token) do
      response(200, key_authorization)
    else
      _ -> response(404, "Not Found")
    end
  end

  defp response(status, body) do
    reason = if status == 200, do: "OK", else: "Not Found"

    [
      "HTTP/1.1 #{status} #{reason}\r\n",
      "Content-Type: text/plain\r\n",
      "Content-Length: #{byte_size(body)}\r\n",
      "Connection: close\r\n\r\n",
      body
    ]
  end
end
