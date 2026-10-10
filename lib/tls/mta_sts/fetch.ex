defmodule Sovite.TLS.MTASTS.Fetch do
  @moduledoc false
  # A minimal HTTP/1.1 client over :ssl for policy fetches (RFC 8461
  # §3.3). Written directly on the socket so the body size and one
  # deadline for the whole fetch are enforced, which :httpc cannot do.

  @max_head 16_384
  @max_chunk_line 1024

  @doc false
  @spec get(String.t(), String.t(), keyword()) :: {:ok, binary()} | {:error, term()}
  def get(host, path, opts) do
    deadline = System.monotonic_time(:millisecond) + Keyword.fetch!(opts, :timeout)
    {address, port} = target(host, opts)

    with {:ok, tcp} <- connect(address, port, deadline),
         {:ok, socket} <- upgrade(tcp, host, opts, deadline) do
      try do
        request(socket, host, path, Keyword.fetch!(opts, :max_size), deadline)
      after
        :ssl.close(socket)
      end
    end
  end

  defp target(host, opts) do
    case Keyword.fetch!(opts, :connect_to) do
      nil -> {String.to_charlist(host), Keyword.fetch!(opts, :port)}
      {address, port} -> {address, port}
      address when is_list(address) -> {address, Keyword.fetch!(opts, :port)}
    end
  end

  # gen_tcp tries IPv4 only for a host name; try IPv6 if it has no
  # IPv4 address.
  defp connect(address, port, deadline) do
    case tcp_connect(address, port, [], deadline) do
      {:error, {:connect, :nxdomain}} when is_list(address) ->
        tcp_connect(address, port, [:inet6], deadline)

      result ->
        result
    end
  end

  defp tcp_connect(address, port, family, deadline) do
    case :gen_tcp.connect(address, port, family ++ [:binary, active: false], remaining(deadline)) do
      {:ok, socket} -> {:ok, socket}
      {:error, :timeout} -> {:error, :timeout}
      {:error, reason} -> {:error, {:connect, reason}}
    end
  end

  defp upgrade(tcp, host, opts, deadline) do
    ssl_opts =
      Sovite.TLS.client_options(
        verify: :peer,
        hostname: host,
        cacerts: Keyword.fetch!(opts, :cacerts) || :public_key.cacerts_get()
      )

    result =
      try do
        :ssl.connect(tcp, ssl_opts ++ [mode: :binary, active: false], remaining(deadline))
      catch
        :exit, reason -> {:error, reason}
      end

    case result do
      {:ok, socket} ->
        {:ok, socket}

      {:error, reason} ->
        :gen_tcp.close(tcp)
        if reason == :timeout, do: {:error, :timeout}, else: {:error, {:tls, reason}}
    end
  end

  defp request(socket, host, path, max_size, deadline) do
    request = [
      "GET #{path} HTTP/1.1\r\n",
      "Host: #{host}\r\n",
      "User-Agent: sovite\r\n",
      "Connection: close\r\n\r\n"
    ]

    with :ok <- send_request(socket, request),
         {:ok, head, rest} <- read_head(socket, "", deadline),
         {:ok, status, headers} <- parse_head(head),
         :ok <- check_status(status),
         :ok <- check_content_type(headers) do
      read_body(socket, rest, headers, max_size, deadline)
    end
  end

  defp send_request(socket, request) do
    case :ssl.send(socket, request) do
      :ok -> :ok
      {:error, reason} -> {:error, {:connect, reason}}
    end
  end

  ## Head

  defp read_head(socket, buffer, deadline) do
    case Regex.run(~r/\r?\n\r?\n/, buffer, return: :index) do
      [{start, length}] ->
        rest = start + length
        {:ok, binary_part(buffer, 0, start), binary_part(buffer, rest, byte_size(buffer) - rest)}

      nil when byte_size(buffer) > @max_head ->
        {:error, {:invalid_response, :headers_too_large}}

      nil ->
        case recv(socket, deadline) do
          {:ok, data} -> read_head(socket, buffer <> data, deadline)
          :closed -> {:error, {:invalid_response, :truncated}}
          error -> error
        end
    end
  end

  defp parse_head(head) do
    [status_line | lines] = String.split(head, ["\r\n", "\n"])

    with {:ok, status} <- status(status_line),
         {:ok, headers} <- headers(lines, []) do
      {:ok, status, headers}
    end
  end

  defp headers([], acc), do: {:ok, Enum.reverse(acc)}

  defp headers([line | rest], acc) do
    case Regex.run(~r/\A([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*(.*?)[ \t]*\z/s, line) do
      [_, name, value] -> headers(rest, [{String.downcase(name, :ascii), value} | acc])
      nil -> {:error, {:invalid_response, :header}}
    end
  end

  defp status(line) do
    case Regex.run(~r/\AHTTP\/1\.[01] ([0-9]{3})(?: .*)?\z/s, line) do
      [_, code] -> {:ok, String.to_integer(code)}
      nil -> {:error, {:invalid_response, :status_line}}
    end
  end

  # RFC 8461 §3.3: "Senders MUST NOT follow HTTP redirects."
  defp check_status(200), do: :ok
  defp check_status(status), do: {:error, {:http_status, status}}

  # RFC 8461 §3.2: the media type is "text/plain"; parameters such as
  # charset are allowed.
  defp check_content_type(headers) do
    with {_, value} <- List.keyfind(headers, "content-type", 0),
         true <- Regex.match?(~r/\Atext\/plain[ \t]*(;|\z)/i, value) do
      :ok
    else
      _ -> {:error, :invalid_content_type}
    end
  end

  ## Body

  defp read_body(socket, buffer, headers, max_size, deadline) do
    case {List.keyfind(headers, "transfer-encoding", 0),
          List.keyfind(headers, "content-length", 0)} do
      {{_, coding}, _} ->
        if String.downcase(coding, :ascii) == "chunked",
          do: read_chunks(socket, buffer, "", max_size, deadline),
          else: {:error, {:invalid_response, :transfer_encoding}}

      {nil, {_, length}} ->
        with {:ok, length} <- content_length(length, max_size) do
          read_length(socket, buffer, length, deadline)
        end

      {nil, nil} ->
        read_until_close(socket, buffer, max_size, deadline)
    end
  end

  defp content_length(value, max_size) do
    cond do
      not Regex.match?(~r/\A[0-9]{1,15}\z/, value) ->
        {:error, {:invalid_response, :content_length}}

      String.to_integer(value) > max_size ->
        {:error, :too_large}

      true ->
        {:ok, String.to_integer(value)}
    end
  end

  defp read_length(socket, buffer, length, deadline) do
    with {:ok, data} <- read_at_least(socket, buffer, length, deadline) do
      {:ok, binary_part(data, 0, length)}
    end
  end

  defp read_until_close(_socket, buffer, max_size, _deadline) when byte_size(buffer) > max_size,
    do: {:error, :too_large}

  defp read_until_close(socket, buffer, max_size, deadline) do
    case recv(socket, deadline) do
      {:ok, data} -> read_until_close(socket, buffer <> data, max_size, deadline)
      :closed -> {:ok, buffer}
      error -> error
    end
  end

  # RFC 9112 §7.1: each chunk is a hex size line, the data, and CRLF; a
  # zero size ends the body. Extensions and trailers are ignored.
  defp read_chunks(socket, buffer, body, max_size, deadline) do
    case :binary.split(buffer, "\r\n") do
      [line, rest] ->
        with {:ok, size} <- chunk_size(line, byte_size(body), max_size) do
          next_chunk(socket, rest, size, body, max_size, deadline)
        end

      [_] when byte_size(buffer) > @max_chunk_line ->
        {:error, {:invalid_response, :chunk}}

      [_] ->
        with {:ok, data} <- read_at_least(socket, buffer, byte_size(buffer) + 1, deadline) do
          read_chunks(socket, data, body, max_size, deadline)
        end
    end
  end

  defp next_chunk(_socket, _rest, 0, body, _max_size, _deadline), do: {:ok, body}

  defp next_chunk(socket, rest, size, body, max_size, deadline) do
    case read_at_least(socket, rest, size + 2, deadline) do
      {:ok, <<chunk::binary-size(^size), "\r\n", rest::binary>>} ->
        read_chunks(socket, rest, body <> chunk, max_size, deadline)

      {:ok, _} ->
        {:error, {:invalid_response, :chunk}}

      error ->
        error
    end
  end

  defp chunk_size(line, received, max_size) do
    case Regex.run(~r/\A([0-9A-Fa-f]{1,8})[ \t]*(;.*)?\z/s, line) do
      [_, hex | _] ->
        size = String.to_integer(hex, 16)
        if received + size > max_size, do: {:error, :too_large}, else: {:ok, size}

      nil ->
        {:error, {:invalid_response, :chunk}}
    end
  end

  defp read_at_least(_socket, buffer, length, _deadline) when byte_size(buffer) >= length,
    do: {:ok, buffer}

  defp read_at_least(socket, buffer, length, deadline) do
    case recv(socket, deadline) do
      {:ok, data} -> read_at_least(socket, buffer <> data, length, deadline)
      :closed -> {:error, {:invalid_response, :truncated}}
      error -> error
    end
  end

  defp recv(socket, deadline) do
    case remaining(deadline) do
      0 ->
        {:error, :timeout}

      timeout ->
        case :ssl.recv(socket, 0, timeout) do
          {:ok, data} -> {:ok, data}
          {:error, :closed} -> :closed
          {:error, :timeout} -> {:error, :timeout}
          {:error, reason} -> {:error, {:tls, reason}}
        end
    end
  end

  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)
end
