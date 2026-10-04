defmodule Sovite.SASL.Backend.Introspection do
  @moduledoc """
  A `Sovite.SASL.Backend` for `OAUTHBEARER`: checks bearer tokens with
  OAuth 2.0 token introspection (RFC 7662) at the identity provider.

  The token must be `active`, not expired, and carry `:required_scope`
  if set. The user name is taken from the `:username_claim` of the
  introspection response.

  ## Options

    * `:url` - the introspection endpoint. Required.
    * `:client_id` / `:client_secret` - credentials for the endpoint, sent
      with HTTP Basic authentication.
    * `:username_claim` - defaults to `"username"`. Common alternatives
      are `"email"` and `"preferred_username"`.
    * `:required_scope` - a scope the token must have.
    * `:timeout` - milliseconds. Defaults to 10 seconds.
    * `:cacerts` - CAs to verify an `https` endpoint against. Defaults to
      the system's.
  """

  @behaviour Sovite.SASL.Backend

  @impl true
  def verify_token(_username, token, opts) do
    url = Keyword.fetch!(opts, :url)
    body = URI.encode_query(%{"token" => token, "token_type_hint" => "access_token"})

    headers =
      [{~c"accept", ~c"application/json"}] ++
        case {opts[:client_id], opts[:client_secret]} do
          {nil, _} ->
            []

          {id, secret} ->
            [
              {~c"authorization",
               ~c"Basic " ++ String.to_charlist(Base.encode64("#{id}:#{secret || ""}"))}
            ]
        end

    request = {String.to_charlist(url), headers, ~c"application/x-www-form-urlencoded", body}
    timeout = Keyword.get(opts, :timeout, 10_000)

    case :httpc.request(:post, request, http_options(url, timeout, opts), body_format: :binary) do
      {:ok, {{_, 200, _}, _headers, response}} -> check(response, opts)
      {:ok, {{_, status, _}, _headers, _}} -> {:error, {:temporary, {:http_status, status}}}
      {:error, reason} -> {:error, {:temporary, reason}}
    end
  end

  defp http_options(url, timeout, opts) do
    uri = URI.parse(url)

    ssl =
      if uri.scheme == "https" do
        tls =
          Sovite.TLS.client_options(
            verify: :peer,
            hostname: uri.host,
            cacerts: Keyword.get_lazy(opts, :cacerts, &:public_key.cacerts_get/0)
          )

        [ssl: tls]
      else
        []
      end

    [timeout: timeout, connect_timeout: timeout, autoredirect: false] ++ ssl
  end

  defp check(response, opts) do
    claim = Keyword.get(opts, :username_claim, "username")
    now = System.os_time(:second)

    with {:ok, %{"active" => true} = info} <- JSON.decode(response),
         true <- not is_integer(info["exp"]) or info["exp"] > now,
         true <- scope_ok?(info["scope"], opts[:required_scope]),
         username when is_binary(username) and username != "" <- info[claim] do
      {:ok, username}
    else
      {:error, _} -> {:error, {:temporary, :invalid_response}}
      _ -> {:error, :invalid}
    end
  end

  defp scope_ok?(_scope, nil), do: true
  defp scope_ok?(scope, required) when is_binary(scope), do: required in String.split(scope, " ")
  defp scope_ok?(_scope, _required), do: false
end
