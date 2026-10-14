defmodule Sovite.HTTP do
  @moduledoc """
  A small HTTP/1.1 server for admin APIs and metrics endpoints: a
  `Sovite.Listener` handler that reads one request per connection,
  passes it to a function, and sends back what it returns.

      {Sovite.Listener,
       port: 8025,
       ip: {127, 0, 0, 1},
       handler: Sovite.HTTP.Server,
       handler_opts: [handler: fn %Sovite.HTTP.Request{} = request -> Sovite.HTTP.text(200, "ok\\n") end]}

  A handler returns a response: `{status, headers, body}`, with header
  names in lower case and `body` as iodata. The helpers here build
  common ones. See `Sovite.HTTP.Server` for the options and limits.

      iex> Sovite.HTTP.json(200, %{status: "ok"})
      {200, [{"content-type", "application/json"}], ~s({"status":"ok"})}
  """

  @typedoc "A response: status, lower-case header names and values, and the body."
  @type response :: {100..599, [{String.t(), String.t()}], iodata()}

  @reasons %{
    200 => "OK",
    201 => "Created",
    202 => "Accepted",
    204 => "No Content",
    301 => "Moved Permanently",
    302 => "Found",
    304 => "Not Modified",
    400 => "Bad Request",
    401 => "Unauthorized",
    403 => "Forbidden",
    404 => "Not Found",
    405 => "Method Not Allowed",
    408 => "Request Timeout",
    409 => "Conflict",
    411 => "Length Required",
    413 => "Content Too Large",
    415 => "Unsupported Media Type",
    422 => "Unprocessable Content",
    429 => "Too Many Requests",
    431 => "Request Header Fields Too Large",
    500 => "Internal Server Error",
    501 => "Not Implemented",
    503 => "Service Unavailable"
  }

  @doc "A JSON response. `body` is encoded with `JSON.encode!/1`."
  @spec json(100..599, term(), [{String.t(), String.t()}]) :: response()
  def json(status, body, headers \\ []),
    do: {status, [{"content-type", "application/json"} | headers], JSON.encode!(body)}

  @doc "A plain text response."
  @spec text(100..599, iodata(), [{String.t(), String.t()}]) :: response()
  def text(status, body, headers \\ []),
    do: {status, [{"content-type", "text/plain; charset=utf-8"} | headers], body}

  @doc "A JSON error response: `{\"error\": message}`."
  @spec error(100..599, String.t()) :: response()
  def error(status, message), do: json(status, %{error: message})

  @doc """
  The reason phrase for a status code, such as `"Not Found"`.

      iex> Sovite.HTTP.reason(404)
      "Not Found"
  """
  @spec reason(100..599) :: String.t()
  def reason(status), do: Map.get(@reasons, status, "Unknown")
end
