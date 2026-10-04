defmodule Sovite.TLS.ACME do
  @moduledoc """
  An ACME client (RFC 8555) for getting certificates from a CA such as
  Let's Encrypt, with HTTP-01 challenges.

      {:ok, acme} = ACME.connect("https://acme-v02.api.letsencrypt.org/directory", account_key)
      {:ok, acme} = ACME.register(acme, "postmaster@example.com")

      {:ok, pem_chain, acme} =
        ACME.obtain(acme, ["mx.example.com"], certificate_key, fn
          {:put, token, key_authorization} -> :ets.insert(table, {token, key_authorization})
          {:delete, token} -> :ets.delete(table, token)
        end)

  The challenge function publishes the key authorization, for example
  through `Sovite.TLS.ACME.HTTPChallenge` on port 80, before the CA is
  asked to check it.

  Requests are signed with the account key (ECDSA P-256, `ES256`) as
  flattened JWS. Keys are `:public_key` EC private key records.

  ## Options

    * `:cacerts` - CAs to verify the ACME server against. Defaults to the
      system's. Plain `http` directory URLs are allowed for testing.
    * `:timeout` - per HTTP request, in milliseconds. Defaults to 30 seconds.
    * `:poll_interval` / `:poll_attempts` - how often and how many times
      to check a pending authorization or order. Default to 2 seconds and
      30 times.

  ## Errors

    * `{:acme, type, detail}` - an RFC 8555 problem document from the CA,
      such as `{:acme, "urn:ietf:params:acme:error:rateLimited", "..."}`.
    * `{:challenge_failed, domain, detail}` - the CA could not validate
      a domain.
    * `{:http, status}`, `{:invalid_response, what}`, `:timeout`, or an
      `:httpc` error.
  """

  alias Sovite.TLS.ACME.CSR

  @enforce_keys [:directory, :key, :jwk, :opts]
  defstruct [:directory, :key, :jwk, :opts, :kid, :nonce]

  @opaque t :: %__MODULE__{}

  @type challenge_fun :: ({:put, String.t(), String.t()} | {:delete, String.t()} -> any())

  @doc "Fetches the CA's directory."
  @spec connect(String.t(), tuple(), keyword()) :: {:ok, t()} | {:error, term()}
  def connect(directory_url, account_key, opts \\ []) do
    acme = %__MODULE__{
      directory: nil,
      key: account_key,
      jwk: jwk(account_key),
      opts: Map.new(opts)
    }

    case request(acme, :get, directory_url) do
      {:ok, 200, _headers, %{"newNonce" => _, "newAccount" => _, "newOrder" => _} = directory} ->
        {:ok, %{acme | directory: directory}}

      {:ok, 200, _headers, _body} ->
        {:error, {:invalid_response, :directory}}

      {:ok, status, _headers, _body} ->
        {:error, {:http, status}}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Creates the account, or finds the existing one for this key, agreeing
  to the CA's terms of service.
  """
  @spec register(t(), String.t()) :: {:ok, t()} | {:error, term()}
  def register(acme, email) do
    payload = %{"termsOfServiceAgreed" => true, "contact" => ["mailto:" <> email]}

    case post(acme, acme.directory["newAccount"], payload) do
      {:ok, status, headers, _body, acme} when status in [200, 201] ->
        case header(headers, "location") do
          nil -> {:error, {:invalid_response, :account_location}}
          kid -> {:ok, %{acme | kid: kid}}
        end

      other ->
        failure(other)
    end
  end

  @doc """
  Orders a certificate for `domains`, proves control of each with
  HTTP-01, and downloads the chain (PEM). `certificate_key` is the key
  the certificate is for.
  """
  @spec obtain(t(), [String.t(), ...], tuple(), challenge_fun()) ::
          {:ok, binary(), t()} | {:error, term()}
  def obtain(acme, domains, certificate_key, challenge_fun) do
    identifiers = Enum.map(domains, &%{"type" => "dns", "value" => &1})

    with {:ok, order_url, order, acme} <- new_order(acme, identifiers),
         {:ok, acme} <- authorize_all(acme, order["authorizations"] || [], challenge_fun),
         {:ok, acme} <- finalize(acme, order["finalize"], CSR.build(domains, certificate_key)),
         {:ok, order, acme} <- poll(acme, order_url, &(&1["status"] in ["valid", "invalid"])),
         {:ok, "valid"} <- {:ok, order["status"]},
         {:ok, 200, _headers, pem, acme} <- post(acme, order["certificate"], nil) do
      {:ok, pem, acme}
    else
      {:ok, "invalid"} -> {:error, {:invalid_response, :order_invalid}}
      other -> failure(other)
    end
  end

  @doc """
  The key authorization for a challenge token: the token and the
  account key's thumbprint (RFC 8555 §8.1, RFC 7638).
  """
  @spec key_authorization(t(), String.t()) :: String.t()
  def key_authorization(acme, token), do: token <> "." <> thumbprint(acme.jwk)

  ## Order steps

  defp new_order(acme, identifiers) do
    case post(acme, acme.directory["newOrder"], %{"identifiers" => identifiers}) do
      {:ok, 201, headers, %{} = order, acme} ->
        case header(headers, "location") do
          nil -> {:error, {:invalid_response, :order_location}}
          url -> {:ok, url, order, acme}
        end

      other ->
        failure(other)
    end
  end

  defp authorize_all(acme, urls, challenge_fun) do
    Enum.reduce_while(urls, {:ok, acme}, fn url, {:ok, acme} ->
      case authorize(acme, url, challenge_fun) do
        {:ok, acme} -> {:cont, {:ok, acme}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp authorize(acme, url, challenge_fun) do
    case post(acme, url, nil) do
      {:ok, 200, _headers, authz, acme} -> authorize(acme, url, authz, challenge_fun)
      other -> failure(other)
    end
  end

  defp authorize(acme, _url, %{"status" => "valid"}, _challenge_fun), do: {:ok, acme}

  defp authorize(acme, url, %{"status" => "pending"} = authz, challenge_fun) do
    domain = get_in(authz, ["identifier", "value"])

    case Enum.find(authz["challenges"] || [], &(&1["type"] == "http-01")) do
      %{"token" => token, "url" => challenge_url} ->
        challenge(acme, url, domain, token, challenge_url, challenge_fun)

      nil ->
        {:error, {:challenge_failed, domain, "the CA offers no http-01 challenge"}}
    end
  end

  defp authorize(_acme, _url, authz, _challenge_fun) do
    domain = get_in(authz, ["identifier", "value"])
    {:error, {:challenge_failed, domain, "authorization is #{authz["status"]}"}}
  end

  defp challenge(acme, authz_url, domain, token, challenge_url, challenge_fun) do
    challenge_fun.({:put, token, key_authorization(acme, token)})

    try do
      with {:ok, status, _headers, _body, acme} when status in 200..299 <-
             post(acme, challenge_url, %{}),
           {:ok, authz, acme} <-
             poll(acme, authz_url, &(&1["status"] not in ["pending", "processing"])) do
        case authz["status"] do
          "valid" -> {:ok, acme}
          _ -> {:error, {:challenge_failed, domain, challenge_error(authz)}}
        end
      else
        other -> failure(other)
      end
    after
      challenge_fun.({:delete, token})
    end
  end

  defp challenge_error(authz) do
    authz
    |> Map.get("challenges", [])
    |> Enum.find_value("validation failed", &get_in(&1, ["error", "detail"]))
  end

  defp finalize(acme, url, csr) do
    case post(acme, url, %{"csr" => Base.url_encode64(csr, padding: false)}) do
      {:ok, 200, _headers, _order, acme} -> {:ok, acme}
      other -> failure(other)
    end
  end

  defp poll(acme, url, done?) do
    attempts = Map.get(acme.opts, :poll_attempts, 30)
    interval = Map.get(acme.opts, :poll_interval, 2_000)
    poll(acme, url, done?, attempts, interval)
  end

  defp poll(_acme, _url, _done?, 0, _interval), do: {:error, :timeout}

  defp poll(acme, url, done?, attempts, interval) do
    case post(acme, url, nil) do
      {:ok, 200, _headers, %{} = resource, acme} ->
        if done?.(resource) do
          {:ok, resource, acme}
        else
          Process.sleep(interval)
          poll(acme, url, done?, attempts - 1, interval)
        end

      other ->
        failure(other)
    end
  end

  defp failure({:ok, _status, _headers, %{"type" => type} = problem, _acme}),
    do: {:error, {:acme, type, problem["detail"]}}

  defp failure({:ok, status, _headers, _body, _acme}), do: {:error, {:http, status}}
  defp failure({:error, _} = error), do: error

  ## JWS (RFC 7515, RFC 8555 §6.2)

  # POSTs a JWS. `payload` nil is POST-as-GET. Retries once on badNonce.
  defp post(acme, url, payload, retry \\ true) do
    with {:ok, acme} <- ensure_nonce(acme) do
      protected =
        %{"alg" => "ES256", "nonce" => acme.nonce, "url" => url}
        |> Map.merge(if acme.kid, do: %{"kid" => acme.kid}, else: %{"jwk" => acme.jwk})

      body = jws(acme.key, protected, if(payload, do: JSON.encode!(payload), else: ""))
      acme = %{acme | nonce: nil}

      case request(acme, :post, url, body) do
        {:ok, status, headers, response} ->
          posted(
            %{acme | nonce: header(headers, "replay-nonce")},
            {status, headers, response},
            url,
            payload,
            retry
          )

        {:error, _} = error ->
          error
      end
    end
  end

  defp posted(
         acme,
         {_status, _headers, %{"type" => "urn:ietf:params:acme:error:badNonce"}},
         url,
         payload,
         true
       ),
       do: post(acme, url, payload, false)

  defp posted(acme, {status, headers, response}, _url, _payload, _retry),
    do: {:ok, status, headers, response, acme}

  defp ensure_nonce(%{nonce: nonce} = acme) when is_binary(nonce), do: {:ok, acme}

  defp ensure_nonce(acme) do
    case request(acme, :head, acme.directory["newNonce"]) do
      {:ok, status, headers, _} when status in [200, 204] ->
        case header(headers, "replay-nonce") do
          nil -> {:error, {:invalid_response, :nonce}}
          nonce -> {:ok, %{acme | nonce: nonce}}
        end

      {:ok, status, _, _} ->
        {:error, {:http, status}}

      {:error, _} = error ->
        error
    end
  end

  defp jws(key, protected, payload) do
    protected = Base.url_encode64(JSON.encode!(protected), padding: false)
    payload = Base.url_encode64(payload, padding: false)
    der = :public_key.sign(protected <> "." <> payload, :sha256, key)

    JSON.encode!(%{
      "protected" => protected,
      "payload" => payload,
      "signature" => Base.url_encode64(raw_signature(der), padding: false)
    })
  end

  # JWS wants r || s, 32 bytes each; :public_key produces DER.
  defp raw_signature(der) do
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)
    <<r::unsigned-big-256, s::unsigned-big-256>>
  end

  @doc false
  def jwk({:ECPrivateKey, _, _, _params, <<4, x::binary-32, y::binary-32>>, _}) do
    %{
      "crv" => "P-256",
      "kty" => "EC",
      "x" => Base.url_encode64(x, padding: false),
      "y" => Base.url_encode64(y, padding: false)
    }
  end

  # RFC 7638: members in lexical order, no whitespace.
  defp thumbprint(jwk) do
    json = ~s({"crv":"#{jwk["crv"]}","kty":"#{jwk["kty"]}","x":"#{jwk["x"]}","y":"#{jwk["y"]}"})
    :sha256 |> :crypto.hash(json) |> Base.url_encode64(padding: false)
  end

  ## HTTP

  defp request(acme, method, url, body \\ nil) do
    timeout = Map.get(acme.opts, :timeout, 30_000)
    headers = [{~c"user-agent", ~c"sovite"}]

    request =
      if body,
        do: {String.to_charlist(url), headers, ~c"application/jose+json", body},
        else: {String.to_charlist(url), headers}

    http_opts =
      [timeout: timeout, connect_timeout: timeout, autoredirect: false] ++ ssl(url, acme.opts)

    case :httpc.request(method, request, http_opts, body_format: :binary) do
      {:ok, {{_, status, _}, headers, response}} ->
        headers = Enum.map(headers, fn {k, v} -> {to_string(k), to_string(v)} end)
        {:ok, status, headers, decode(headers, response)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp ssl("https:" <> _ = url, opts) do
    host = URI.parse(url).host
    cacerts = Map.get_lazy(opts, :cacerts, &:public_key.cacerts_get/0)
    [ssl: Sovite.TLS.client_options(verify: :peer, hostname: host, cacerts: cacerts)]
  end

  defp ssl(_url, _opts), do: []

  defp decode(headers, body) do
    if String.contains?(header(headers, "content-type") || "", "json") do
      case JSON.decode(body) do
        {:ok, decoded} -> decoded
        {:error, _} -> body
      end
    else
      body
    end
  end

  defp header(headers, name) do
    Enum.find_value(headers, fn {key, value} -> if String.downcase(key) == name, do: value end)
  end
end
