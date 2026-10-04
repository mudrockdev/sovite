defmodule Sovite.Test.FakeACME do
  @moduledoc """
  A small ACME CA (RFC 8555) for tests, over `Sovite.Test.FakeHTTP`.

  It checks every JWS signature and nonce, validates HTTP-01 challenges by
  fetching `http://127.0.0.1:<challenge_port>/.well-known/acme-challenge/<token>`,
  and issues certificates from the CSR with a test CA.

      acme = FakeACME.start!(challenge_port: port)
      FakeACME.directory_url(acme)

  Options: `:challenge_port`, `:bad_nonce_once` (reject the first nonce
  with badNonce), `:valid_days` (certificate lifetime, default 90).
  `FakeACME.orders/1` counts finalized orders; `FakeACME.ca/1` returns
  the issuing CA.
  """

  alias Sovite.Test.{Certs, FakeHTTP}

  @p256 {1, 2, 840, 10_045, 3, 1, 7}

  def start!(opts) do
    {:ok, agent} =
      Agent.start_link(fn ->
        %{
          opts: Map.new(opts),
          ca: Certs.ca(),
          base: nil,
          nonces: MapSet.new(),
          accounts: %{},
          orders: %{},
          authzs: %{},
          finalized: 0,
          next: 1,
          bad_nonce: Keyword.get(opts, :bad_nonce_once, false)
        }
      end)

    {:ok, http} = FakeHTTP.start_link(&handle(agent, &1))
    Agent.update(agent, &%{&1 | base: "http://127.0.0.1:#{FakeHTTP.port(http)}"})
    %{agent: agent, http: http}
  end

  def directory_url(%{agent: agent}), do: Agent.get(agent, & &1.base) <> "/directory"
  def orders(%{agent: agent}), do: Agent.get(agent, & &1.finalized)
  def ca(%{agent: agent}), do: Agent.get(agent, & &1.ca)
  def set(%{agent: agent}, key, value), do: Agent.update(agent, &put_in(&1, [:opts, key], value))

  defp handle(agent, %{method: "GET", path: "/directory"}) do
    base = Agent.get(agent, & &1.base)

    json(
      200,
      %{
        "newNonce" => base <> "/new-nonce",
        "newAccount" => base <> "/new-account",
        "newOrder" => base <> "/new-order"
      },
      agent
    )
  end

  defp handle(agent, %{method: "HEAD", path: "/new-nonce"}),
    do: {200, [{"replay-nonce", nonce(agent)}], ""}

  defp handle(agent, %{method: "POST", path: path, body: body}) do
    case verify(agent, path, body) do
      {:ok, account, payload} -> route(agent, path, account, payload)
      {:error, type} -> problem(400, type, agent)
    end
  end

  defp handle(_agent, _request), do: {404, [], ""}

  ## Routes

  defp route(agent, "/new-account", {:jwk, jwk}, _payload) do
    id = next(agent)
    Agent.update(agent, &put_in(&1, [:accounts, "acct/#{id}"], jwk))
    base = Agent.get(agent, & &1.base)
    json(201, %{"status" => "valid"}, agent, [{"location", "#{base}/acct/#{id}"}])
  end

  defp route(agent, "/new-order", {:kid, account}, %{"identifiers" => identifiers}) do
    base = Agent.get(agent, & &1.base)
    order_id = next(agent)

    authz_ids =
      for %{"value" => domain} <- identifiers do
        id = next(agent)
        token = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
        authz = %{status: "pending", domain: domain, token: token, account: account, error: nil}
        Agent.update(agent, &put_in(&1, [:authzs, id], authz))
        id
      end

    order = %{
      status: "pending",
      authzs: authz_ids,
      domains: Enum.map(identifiers, & &1["value"]),
      cert: nil
    }

    Agent.update(agent, &put_in(&1, [:orders, order_id], order))

    json(201, order_json(base, order_id, order), agent, [
      {"location", "#{base}/order/#{order_id}"}
    ])
  end

  defp route(agent, "/authz/" <> id, {:kid, _}, nil),
    do: json(200, authz_json(agent, String.to_integer(id)), agent)

  defp route(agent, "/chall/" <> id, {:kid, _}, %{}) do
    id = String.to_integer(id)
    authz = Agent.get(agent, &get_in(&1, [:authzs, id]))
    jwk = Agent.get(agent, &get_in(&1, [:accounts, authz.account]))
    port = Agent.get(agent, & &1.opts.challenge_port)
    expected = authz.token <> "." <> thumbprint(jwk)
    url = ~c"http://127.0.0.1:#{port}/.well-known/acme-challenge/#{authz.token}"

    {status, error} =
      case :httpc.request(:get, {url, []}, [timeout: 2_000], body_format: :binary) do
        {:ok, {{_, 200, _}, _, ^expected}} -> {"valid", nil}
        {:ok, {{_, code, _}, _, body}} -> {"invalid", "got #{code}: #{inspect(body)}"}
        {:error, reason} -> {"invalid", "connection failed: #{inspect(reason)}"}
      end

    Agent.update(
      agent,
      &update_in(&1, [:authzs, id], fn a -> %{a | status: status, error: error} end)
    )

    json(200, %{"type" => "http-01", "status" => status}, agent)
  end

  defp route(agent, "/order/" <> rest, {:kid, _}, payload) do
    base = Agent.get(agent, & &1.base)

    case String.split(rest, "/") do
      [id] ->
        id = String.to_integer(id)
        json(200, order_json(base, id, Agent.get(agent, &get_in(&1, [:orders, id]))), agent)

      [id, "finalize"] ->
        finalize(agent, base, String.to_integer(id), payload)
    end
  end

  defp route(agent, "/cert/" <> id, {:kid, _}, nil) do
    order = Agent.get(agent, &get_in(&1, [:orders, String.to_integer(id)]))

    {200, [{"content-type", "application/pem-certificate-chain"}, {"replay-nonce", nonce(agent)}],
     order.cert}
  end

  defp route(agent, _path, _account, _payload),
    do: problem(404, "urn:ietf:params:acme:error:malformed", agent)

  defp finalize(agent, base, id, %{"csr" => csr}) do
    order = Agent.get(agent, &get_in(&1, [:orders, id]))
    authzs = Agent.get(agent, & &1.authzs)

    if Enum.all?(order.authzs, &(authzs[&1].status == "valid")) do
      {public_key, names} = decode_csr(Base.url_decode64!(csr, padding: false))
      ca = Agent.get(agent, & &1.ca)
      days = Agent.get(agent, &Map.get(&1.opts, :valid_days, 90))

      cert =
        Certs.issue(ca,
          public_key: public_key,
          names: names,
          not_after: DateTime.add(DateTime.utc_now(), days, :day)
        )

      pem = Certs.pem_chain(cert.chain)
      order = %{order | status: "valid", cert: pem}

      Agent.update(
        agent,
        &(&1 |> put_in([:orders, id], order) |> Map.update!(:finalized, fn n -> n + 1 end))
      )

      json(200, order_json(base, id, order), agent)
    else
      problem(403, "urn:ietf:params:acme:error:orderNotReady", agent)
    end
  end

  defp decode_csr(der) do
    {:CertificationRequest, info, _alg, _sig} = :public_key.der_decode(:CertificationRequest, der)
    {:CertificationRequestInfo, _v, _subject, spki, attributes} = info
    {:CertificationRequestInfo_subjectPKInfo, {_, _oid, {:asn1_OPENTYPE, params}}, point} = spki
    params = :public_key.der_decode(:EcpkParameters, params)

    [{_attribute, _oid, [{:asn1_OPENTYPE, extensions}]}] = attributes
    [{:Extension, _, _, san}] = :public_key.der_decode(:Extensions, extensions)

    names =
      for {:dNSName, name} <- :public_key.der_decode(:SubjectAltName, san), do: to_string(name)

    {{{:ECPoint, point}, params}, names}
  end

  defp order_json(base, id, order) do
    %{
      "status" => order.status,
      "authorizations" => Enum.map(order.authzs, &"#{base}/authz/#{&1}"),
      "finalize" => "#{base}/order/#{id}/finalize"
    }
    |> Map.merge(if order.cert, do: %{"certificate" => "#{base}/cert/#{id}"}, else: %{})
  end

  defp authz_json(agent, id) do
    base = Agent.get(agent, & &1.base)
    authz = Agent.get(agent, &get_in(&1, [:authzs, id]))

    challenge = %{
      "type" => "http-01",
      "url" => "#{base}/chall/#{id}",
      "token" => authz.token,
      "status" => authz.status
    }

    challenge =
      if authz.error, do: Map.put(challenge, "error", %{"detail" => authz.error}), else: challenge

    %{
      "status" => authz.status,
      "identifier" => %{"type" => "dns", "value" => authz.domain},
      "challenges" => [
        %{"type" => "dns-01", "url" => "#{base}/unused", "token" => "x"},
        challenge
      ]
    }
  end

  ## JWS

  defp verify(agent, path, body) do
    with {:ok, %{"protected" => protected, "payload" => payload, "signature" => signature}} <-
           JSON.decode(body),
         {:ok, header} <- protected |> Base.url_decode64!(padding: false) |> JSON.decode(),
         :ok <- check_nonce(agent, header["nonce"]),
         true <-
           String.ends_with?(header["url"], path) ||
             {:error, "urn:ietf:params:acme:error:unauthorized"},
         {:ok, account, jwk} <- account(agent, header),
         true <-
           valid_signature?(jwk, protected <> "." <> payload, signature) ||
             {:error, "urn:ietf:params:acme:error:badSignature"} do
      decoded =
        if payload == "",
          do: nil,
          else: payload |> Base.url_decode64!(padding: false) |> JSON.decode!()

      {:ok, account, decoded}
    else
      {:error, type} when is_binary(type) -> {:error, type}
      _ -> {:error, "urn:ietf:params:acme:error:malformed"}
    end
  end

  defp check_nonce(agent, nonce) do
    Agent.get_and_update(agent, fn state ->
      cond do
        state.bad_nonce ->
          {{:error, "urn:ietf:params:acme:error:badNonce"}, %{state | bad_nonce: false}}

        MapSet.member?(state.nonces, nonce) ->
          {:ok, %{state | nonces: MapSet.delete(state.nonces, nonce)}}

        true ->
          {{:error, "urn:ietf:params:acme:error:badNonce"}, state}
      end
    end)
  end

  defp account(_agent, %{"jwk" => jwk}), do: {:ok, {:jwk, jwk}, jwk}

  defp account(agent, %{"kid" => kid}) do
    key = kid |> String.split("/") |> Enum.take(-2) |> Enum.join("/")

    case Agent.get(agent, &get_in(&1, [:accounts, key])) do
      nil -> {:error, "urn:ietf:params:acme:error:accountDoesNotExist"}
      jwk -> {:ok, {:kid, key}, jwk}
    end
  end

  defp valid_signature?(jwk, input, signature) do
    <<r::unsigned-big-256, s::unsigned-big-256>> = Base.url_decode64!(signature, padding: false)
    der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s})
    x = Base.url_decode64!(jwk["x"], padding: false)
    y = Base.url_decode64!(jwk["y"], padding: false)

    :public_key.verify(
      input,
      :sha256,
      der,
      {{:ECPoint, <<4, x::binary, y::binary>>}, {:namedCurve, @p256}}
    )
  end

  defp thumbprint(jwk) do
    json = ~s({"crv":"#{jwk["crv"]}","kty":"#{jwk["kty"]}","x":"#{jwk["x"]}","y":"#{jwk["y"]}"})
    :sha256 |> :crypto.hash(json) |> Base.url_encode64(padding: false)
  end

  ## Helpers

  defp nonce(agent) do
    nonce = Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
    Agent.update(agent, &%{&1 | nonces: MapSet.put(&1.nonces, nonce)})
    nonce
  end

  defp next(agent), do: Agent.get_and_update(agent, &{&1.next, %{&1 | next: &1.next + 1}})

  defp json(status, body, agent, headers \\ []) do
    {status, [{"content-type", "application/json"}, {"replay-nonce", nonce(agent)}] ++ headers,
     JSON.encode!(body)}
  end

  defp problem(status, type, agent) do
    {status, [{"content-type", "application/problem+json"}, {"replay-nonce", nonce(agent)}],
     JSON.encode!(%{"type" => type, "detail" => "fake"})}
  end
end
