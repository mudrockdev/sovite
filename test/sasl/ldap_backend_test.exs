defmodule Sovite.SASL.Backend.LDAPTest do
  use ExUnit.Case, async: true

  alias Sovite.LDAP.Filter
  alias Sovite.SASL.Backend.LDAP
  alias Sovite.Test.{Certs, FakeLDAP}

  doctest Filter

  @alice "uid=alice,ou=people,dc=test"

  defp start_ldap(opts \\ []) do
    defaults = [
      entries: [
        {@alice, %{"mail" => ["alice@example.com"], "objectClass" => ["person"]}},
        {"uid=twin1,dc=test", %{"mail" => ["twin@example.com"]}},
        {"uid=twin2,dc=test", %{"mail" => ["twin@example.com"]}}
      ],
      passwords: %{@alice => "secret", "cn=svc,dc=test" => "svcpw"}
    ]

    ldap = start_supervised!({FakeLDAP, Keyword.merge(defaults, [owner: self()] ++ opts)})
    FakeLDAP.port(ldap)
  end

  defp opts(port, extra \\ []) do
    [servers: ["127.0.0.1"], port: port, security: :none, base: "dc=test"] ++ extra
  end

  test "searches for the user and binds as them" do
    opts = opts(start_ldap(), filter: "(&(objectClass=person)(mail=%u))")
    assert LDAP.verify_password("alice@example.com", "secret", opts) == {:ok, "alice@example.com"}
    assert_received {:fake_ldap, :bind, @alice}
    assert LDAP.verify_password("alice@example.com", "wrong", opts) == {:error, :invalid}
    assert LDAP.verify_password("bob@example.com", "x", opts) == {:error, :unknown_user}
  end

  test "searches with a service account" do
    port = start_ldap(require_bind: true)

    assert {:error, {:temporary, _}} =
             LDAP.verify_password("alice@example.com", "secret", opts(port))

    opts = opts(port, bind_dn: "cn=svc,dc=test", bind_password: "svcpw")
    assert LDAP.verify_password("alice@example.com", "secret", opts) == {:ok, "alice@example.com"}

    bad = opts(port, bind_dn: "cn=svc,dc=test", bind_password: "nope")

    assert {:error, {:temporary, {:service_bind, _}}} =
             LDAP.verify_password("alice@example.com", "secret", bad)
  end

  test "refuses empty passwords and ambiguous users" do
    opts = opts(start_ldap())
    assert LDAP.verify_password("alice@example.com", "", opts) == {:error, :invalid}
    assert LDAP.verify_password("twin@example.com", "x", opts) == {:error, :invalid}
  end

  test "user names cannot inject filter syntax" do
    opts = opts(start_ldap())
    assert LDAP.verify_password("*)(mail=*", "x", opts) == {:error, :unknown_user}

    assert_received {:fake_ldap, :search,
                     {:equalityMatch, {:AttributeValueAssertion, ~c"mail", ~c"*)(mail=*"}}}
  end

  test "binds directly with a DN template, escaping the name" do
    opts = opts(start_ldap(), dn_template: "uid=%n,ou=people,dc=test")
    assert LDAP.verify_password("alice@example.com", "secret", opts) == {:ok, "alice@example.com"}
    refute_received {:fake_ldap, :search, _}

    assert LDAP.dn_from_template("uid=%n,dc=test", "a,b=c@x") == ~c"uid=a\\2Cb\\3Dc,dc=test"
    assert LDAP.dn_from_template("cn=%u", " x ") == ~c"cn=\\ x\\ "
  end

  test "upgrades with StartTLS" do
    ca = Certs.ca()
    cert = Certs.issue(ca, names: ["localhost"])
    tls = Sovite.TLS.server_options(certs_keys: [Certs.certs_keys(cert)])
    port = start_ldap(tls: tls)

    tls_options =
      Sovite.TLS.client_options(verify: :peer, hostname: "localhost", cacerts: [ca.cert])

    opts = opts(port, security: :starttls, tls_options: tls_options)
    assert LDAP.verify_password("alice@example.com", "secret", opts) == {:ok, "alice@example.com"}
  end

  test "an unreachable server is a temporary failure" do
    {:ok, socket} = :gen_tcp.listen(0, [])
    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    assert {:error, {:temporary, _}} = LDAP.verify_password("a", "b", opts(port, timeout: 1000))
  end

  describe "filters" do
    test "parses RFC 4515 syntax" do
      for good <- [
            "(a=b)",
            "(!(a=b))",
            "(|(a=b)(c=*))",
            "(a>=1)",
            "(a<=1)",
            "(a~=x)",
            "(a=x*y*z)",
            "(a=*x)",
            "(1.2.3=x)",
            "(a=\\2a)"
          ] do
        assert {:ok, _} = Filter.parse(good), good
      end

      for bad <- ["a=b", "(a=b", "(&)", "(=b)", "(a=b))", "(a=\\zz)", "(a=**)"] do
        assert Filter.parse(bad) == :error, bad
      end
    end

    test "fills placeholders in values" do
      {:ok, filter} = Filter.parse("(|(uid=%n)(mail=%u)(domain=%d)(pct=100%%)(cn=%n*))")

      assert {:or,
              [
                {:equalityMatch, {_, ~c"uid", ~c"al@ice"}},
                {:equalityMatch, {_, ~c"mail", ~c"al@ice@example.com"}},
                {:equalityMatch, {_, ~c"domain", ~c"example.com"}},
                {:equalityMatch, {_, ~c"pct", ~c"100%"}},
                {:substrings, {_, ~c"cn", [initial: ~c"al@ice"]}}
              ]} = Filter.build(filter, Sovite.LDAP.user_values("al@ice@example.com"))
    end
  end
end
