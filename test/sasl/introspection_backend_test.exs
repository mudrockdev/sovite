defmodule Sovite.SASL.Backend.IntrospectionTest do
  use ExUnit.Case, async: true

  alias Sovite.SASL.Backend.Introspection
  alias Sovite.Test.FakeHTTP

  defp start_idp(test) do
    handler = fn request ->
      send(test, {:request, request})
      params = URI.decode_query(request.body)
      later = System.os_time(:second) + 600

      case params["token"] do
        "good" ->
          {200, [],
           JSON.encode!(%{
             active: true,
             username: "alice@example.com",
             scope: "mail openid",
             exp: later
           })}

        "expired" ->
          {200, [], JSON.encode!(%{active: true, username: "alice@example.com", exp: 1})}

        "noscope" ->
          {200, [], JSON.encode!(%{active: true, username: "alice@example.com", scope: "openid"})}

        "email" ->
          {200, [], JSON.encode!(%{active: true, email: "bob@example.com"})}

        "broken" ->
          {200, [], "not json"}

        "error" ->
          {503, [], ""}

        _ ->
          {200, [], ~s({"active":false})}
      end
    end

    {:ok, http} = FakeHTTP.start_link(handler)
    FakeHTTP.url(http, "/introspect")
  end

  test "accepts active tokens and authenticates the client" do
    opts = [
      url: start_idp(self()),
      client_id: "sovite",
      client_secret: "s3cret",
      required_scope: "mail"
    ]

    assert Introspection.verify_token(nil, "good", opts) == {:ok, "alice@example.com"}

    assert_received {:request,
                     %{method: "POST", path: "/introspect", headers: headers, body: body}}

    assert {"authorization", "Basic " <> creds} = List.keyfind(headers, "authorization", 0)
    assert Base.decode64!(creds) == "sovite:s3cret"
    assert URI.decode_query(body) == %{"token" => "good", "token_type_hint" => "access_token"}
  end

  test "rejects inactive, expired, and under-scoped tokens" do
    opts = [url: start_idp(self()), required_scope: "mail"]

    for token <- ["bad", "expired", "noscope"] do
      assert Introspection.verify_token(nil, token, opts) == {:error, :invalid}, token
    end
  end

  test "reads the user name from the configured claim" do
    url = start_idp(self())
    assert Introspection.verify_token(nil, "email", url: url) == {:error, :invalid}

    assert Introspection.verify_token(nil, "email", url: url, username_claim: "email") ==
             {:ok, "bob@example.com"}
  end

  test "server problems are temporary" do
    url = start_idp(self())

    assert {:error, {:temporary, {:http_status, 503}}} =
             Introspection.verify_token(nil, "error", url: url)

    assert {:error, {:temporary, :invalid_response}} =
             Introspection.verify_token(nil, "broken", url: url)

    assert {:error, {:temporary, _}} =
             Introspection.verify_token(nil, "x", url: "http://127.0.0.1:1/", timeout: 1000)
  end
end
