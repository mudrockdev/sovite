defmodule Sovite.HTTP.Request do
  @moduledoc """
  An HTTP request, as `Sovite.HTTP.Server` passes it to its handler.

    * `method` - upper case, such as `"GET"`.
    * `path` - the decoded path, such as `"/api/queue/ABC"`, and
      `segments`, its non-empty parts: `["api", "queue", "ABC"]`.
    * `query` - the decoded query string parameters. With a parameter
      given twice, the last one wins.
    * `headers` - lower-case names, in order.
    * `body` - the request body, empty without one.
    * `remote_ip` - the client's address.
  """

  @enforce_keys [:method, :path]
  defstruct [
    :method,
    :path,
    :remote_ip,
    segments: [],
    query: %{},
    headers: [],
    body: ""
  ]

  @type t :: %__MODULE__{
          method: String.t(),
          path: String.t(),
          segments: [String.t()],
          query: %{optional(String.t()) => String.t()},
          headers: [{String.t(), String.t()}],
          body: binary(),
          remote_ip: :inet.ip_address() | nil
        }

  @doc """
  Returns the value of the first header named `name` (lower case), or
  `nil`.
  """
  @spec header(t(), String.t()) :: String.t() | nil
  def header(%__MODULE__{headers: headers}, name) do
    case List.keyfind(headers, name, 0) do
      {_name, value} -> value
      nil -> nil
    end
  end

  @doc """
  The token of an `Authorization: Bearer <token>` header, or `nil`.

      iex> request = %Sovite.HTTP.Request{method: "GET", path: "/", headers: [{"authorization", "Bearer abc"}]}
      iex> Sovite.HTTP.Request.bearer_token(request)
      "abc"
  """
  @spec bearer_token(t()) :: String.t() | nil
  def bearer_token(request) do
    with value when is_binary(value) <- header(request, "authorization"),
         [scheme, token] <- String.split(value, " ", parts: 2, trim: true),
         "bearer" <- String.downcase(scheme, :ascii) do
      String.trim(token)
    else
      _ -> nil
    end
  end
end
