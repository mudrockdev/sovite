defmodule Sovite.Core.Postfix.ParsersTest do
  use ExUnit.Case, async: true

  alias Sovite.Core.Postfix.{Convert, MainCf, MasterCf, Table, TomlWriter}

  doctest MainCf
  doctest MasterCf
  doctest Table
  doctest Convert
  doctest TomlWriter

  describe "main.cf" do
    test "reads comments, continuation lines, and whitespace around =" do
      main =
        MainCf.parse("""
        # comment
          # indented comment
        myhostname=mx.example.com
        mynetworks = 127.0.0.0/8
            192.0.2.0/24

        empty =
        myhostname = mail.example.com
        """)

      assert MainCf.names(main) == ["myhostname", "mynetworks", "empty"]
      assert MainCf.value(main, "myhostname") == "mail.example.com"
      assert MainCf.list(main, "mynetworks") == ["127.0.0.0/8", "192.0.2.0/24"]
      assert MainCf.value(main, "empty") == ""
      assert MainCf.set?(main, "empty")
      refute MainCf.set?(main, "relayhost")
      assert MainCf.raw(main, "relayhost") == nil
    end

    test "expands references recursively, with defaults" do
      main =
        MainCf.parse("""
        myhostname = mx.example.com
        a = $b and ${c} and $(d)
        b = [$c]
        c = C
        d = $$literal
        """)

      assert MainCf.value(main, "a") == "[C] and C and $literal"
      assert MainCf.value(main, "mydomain") == "example.com"
      assert MainCf.value(main, "myorigin") == "mx.example.com"

      assert MainCf.value(main, "mydestination") ==
               "mx.example.com, localhost.example.com, localhost"

      assert MainCf.value(main, "unknown") == ""
      assert MainCf.value(MainCf.parse("x = $\n"), "x") == "$"
      assert MainCf.value(MainCf.parse("x = ${broken\n"), "x") == "${broken"
    end

    test "mydomain is localdomain for a host name without dots" do
      assert MainCf.value(MainCf.parse("myhostname = mx\n"), "mydomain") == "localdomain"
      assert MainCf.value(MainCf.parse("", %{"mydomain" => "x.test"}), "mydomain") == "x.test"
    end

    test "expands the conditional forms" do
      main =
        MainCf.parse("""
        set = yes
        unset =
        a = ${set?on}
        b = ${unset?on}
        c = ${set:off}
        d = ${unset:off}
        e = ${set?{one}:{two}}
        f = ${unset?{one}:{two}}
        """)

      assert Enum.map(~w(a b c d e f), &MainCf.value(main, &1)) ==
               ["on", "", "", "off", "one", "two"]
    end

    test "stops at loops" do
      main = MainCf.parse("a = $b\nb = $a\n")
      assert MainCf.value(main, "a") == ""
    end

    test "the system defaults override Postfix's" do
      main = MainCf.parse("", %{"myhostname" => "host.example.org"})
      assert MainCf.value(main, "myorigin") == "host.example.org"
    end
  end

  describe "master.cf" do
    test "reads services, -o options, and grouped arguments" do
      [smtp, submission, pipe] =
        MasterCf.parse("""
        # comment
        smtp      inet  n       -       y       -       -       smtpd
        submission inet n       -       y       -       -       smtpd
          -o syslog_name=postfix/submission
          -o { smtpd_client_restrictions = permit_sasl_authenticated, reject }
          -osmtpd_tls_security_level=encrypt
        bsmtp unix - n n - - pipe flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -f $sender { $nexthop } $recipient
        broken line
        """)

      assert %{name: "smtp", type: "inet", command: "smtpd", args: [], options: []} = smtp
      assert smtp.line == 2

      assert submission.options == [
               {"syslog_name", "postfix/submission"},
               {"smtpd_client_restrictions", "permit_sasl_authenticated, reject"},
               {"smtpd_tls_security_level", "encrypt"}
             ]

      assert MasterCf.option(submission, "smtpd_tls_security_level") == "encrypt"
      assert MasterCf.option(submission, "missing") == nil

      assert MasterCf.attributes(pipe.args) == %{
               "flags" => "Fq.",
               "user" => "bsmtp",
               "argv" => ["/usr/lib/bsmtp/bsmtp", "-f", "$sender", "$nexthop", "$recipient"]
             }
    end

    test "inet service names" do
      assert MasterCf.inet_address("smtp") == {:ok, nil, 25}
      assert MasterCf.inet_address("submissions") == {:ok, nil, 465}
      assert MasterCf.inet_address("2525") == {:ok, nil, 2525}
      assert MasterCf.inet_address("[::1]:25") == {:ok, "::1", 25}
      assert MasterCf.inet_address("*:smtp") == {:ok, nil, 25}
      assert MasterCf.inet_address("::1:24") == {:ok, "::1", 24}
      assert MasterCf.inet_address("qmtp") == {:ok, nil, 209}
      assert MasterCf.inet_address("unknown") == :error
      assert MasterCf.inet_address("70000") == :error
    end
  end

  describe "lookup tables" do
    test "file types read the text source" do
      files = %{"/etc/postfix/virtual" => "A@Example.com b@example.org\nkey\n"}

      read = fn path ->
        with :error <- Map.fetch(files, path), do: {:error, :enoent}
      end

      for type <- ~w(hash btree lmdb cdb dbm sdbm texthash) do
        assert Table.read("#{type}:/etc/postfix/virtual", read) ==
                 {:ok, [{"a@example.com", "b@example.org"}, {"key", ""}]}
      end

      assert Table.read("proxy:hash:/etc/postfix/virtual", read) ==
               {:ok, [{"a@example.com", "b@example.org"}, {"key", ""}]}

      assert Table.read("hash:/etc/postfix/missing", read) ==
               {:error, {:unreadable, "/etc/postfix/missing", :enoent}}
    end

    test "inline and static tables" do
      read = fn _ -> flunk("no file") end

      assert Table.read("inline:{ A=1, { b = two words } }", read) ==
               {:ok, [{"a", "1"}, {"b", "two words"}]}

      assert Table.read("static:{ x y }", read) == {:ok, [{"*", "x y"}]}

      assert Table.read_aliases("inline:{ root=a@example.com }", read) ==
               {:ok, [{"root", ["a@example.com"]}]}

      assert Table.read_aliases("static:x", read) == {:error, {:unsupported, "static"}}
    end

    test "other types are unsupported" do
      for name <- ~w(mysql:/x pgsql:/x ldap:/x regexp:/x pcre:/x cidr:/x tcp:host:1) do
        assert {:error, {:unsupported, _}} = Table.read(name, &File.read/1)
      end

      assert Table.source("proxy:mysql:/x") == {:unsupported, "proxy:mysql"}
      assert Table.source("proxy:inline:{a=b}") == {:unsupported, "proxy"}
      assert Table.source("noname") == {:unsupported, "no type"}
    end

    test "aliases files" do
      assert Table.parse_aliases(~s(a: b\nc d\n"e"\n"f" g\n)) ==
               [{"a", ["b"]}, {"c d", []}, {"e", []}, {"f", ["g"]}]

      assert {:ok, [{"root", ["alice"]}]} =
               Table.read_aliases("hash:/etc/aliases", fn "/etc/aliases" ->
                 {:ok, "Root: alice\n"}
               end)
    end

    test "error messages" do
      assert Table.describe_error({:unsupported, "mysql"}) =~ "mysql: tables cannot be read"
      assert Table.describe_error({:unreadable, "/x", :enoent}) =~ "cannot read /x: no such file"

      assert Table.describe_error({:unreadable, "/x", {:weird, 1}}) ==
               "cannot read /x: {:weird, 1}"
    end
  end

  describe "values" do
    test "durations" do
      assert Convert.duration("300", "s") == {:ok, "300s"}
      assert Convert.duration("5d", "s") == {:ok, "5d"}
      assert Convert.duration("2w", "s") == {:ok, "14d"}
      assert Convert.duration("3", "d") == {:ok, "3d"}
      assert Convert.duration("0", "s") == :zero
      assert Convert.duration("soon", "s") == :error
      assert Convert.duration("9999999999", "s") == :error
      assert Convert.milliseconds("2m") == 120_000
      assert Convert.milliseconds("5ms") == 5
      assert Convert.milliseconds("1h") == 3_600_000
      assert Convert.milliseconds("1d") == 86_400_000
    end

    test "booleans and integers" do
      assert Convert.yes?("Yes")
      refute Convert.yes?(nil)
      assert Convert.no?("no")
      refute Convert.no?("yes")
      assert Convert.integer(" 12 ") == {:ok, 12}
      assert Convert.integer("-1") == :error
    end

    test "networks" do
      assert Convert.networks(["127.0.0.0/8", "[::1]/128", "[::ffff:127.0.0.0]/104", "192.0.2.1"]) ==
               {["127.0.0.0/8", "::1/128", "::ffff:127.0.0.0/104", "192.0.2.1"], []}

      assert {["10.1.0.0/16", "2001:db8::/32"], problems} =
               Convert.networks([
                 "10.1.2.3/16",
                 "2001:db8:1::/32",
                 "!192.0.2.5",
                 "/etc/postfix/networks",
                 "hash:/etc/postfix/networks",
                 "host.example.com"
               ])

      assert [
               {"10.1.2.3/16", "has bits set" <> _},
               {"2001:db8:1::/32", "has bits set" <> _},
               {"!192.0.2.5", "exclusions" <> _},
               {"/etc/postfix/networks", "network lists in files" <> _},
               {"hash:/etc/postfix/networks", "lookup tables" <> _},
               {"host.example.com", "host names" <> _}
             ] = problems
    end

    test "TLS protocol lists" do
      assert Convert.min_tls(">=TLSv1.2") == {:ok, "TLSv1.2"}
      assert Convert.min_tls(">=TLSv1.3") == {:ok, "TLSv1.3"}
      assert Convert.min_tls("<=TLSv1.3") == {:ok, "TLSv1"}
      assert Convert.min_tls("!SSLv2, !SSLv3, !TLSv1, !TLSv1.1") == {:ok, "TLSv1.2"}
      assert Convert.min_tls("!SSLv2 !SSLv3 !TLSv1 !TLSv1.1 !TLSv1.2") == {:ok, "TLSv1.3"}
      assert Convert.min_tls("TLSv1.3 TLSv1.2") == {:ok, "TLSv1.2"}
      assert Convert.min_tls(">=TLSv9") == {:ok, "TLSv1"}
      assert Convert.min_tls("!TLSv1 !TLSv1.1 !TLSv1.2 !TLSv1.3") == :error
    end

    test "table key forms" do
      assert Convert.form?("*", [:wildcard])
      assert Convert.form?("@example.com", [:catchall])
      assert Convert.form?(".example.com", [:subdomains])
      assert Convert.form?("a@example.com", [:address])
      assert Convert.form?("example.com", [:domain])
      assert Convert.form?("postmaster", [:local_part])
      refute Convert.form?("a@example.com", [:domain, :local_part])
      refute Convert.form?("@", [:catchall, :wildcard])
    end
  end

  describe "TOML" do
    test "renders tables, arrays of tables, comments, and values" do
      toml =
        TomlWriter.render([
          {:comment, "header"},
          {:entries, [{"listener", []}]},
          {:table, "empty", []},
          {:table, "a", [{"s", "x\u0001"}, {"n", 1, "a comment"}, {"b", true}], "a table"},
          {:array_table, "arr", [{"k", {:inline, [{"x.y", "z"}, {"n", [1, "two"]}]}}]},
          {:array_table, "arr", []}
        ])

      assert toml == """
             # header

             listener = []

             [a]
             # a table
             s = "x\\u0001"
             # check: a comment
             n = 1
             b = true

             [[arr]]
             k = { "x.y" = "z", n = [1, "two"] }

             [[arr]]
             """

      assert {:ok, %{"a" => %{"s" => "x\u0001"}}} = Toml.decode(toml)
    end

    test "wraps long text" do
      assert TomlWriter.wrap("aaa bbb ccc", 7) == ["aaa bbb", "ccc"]
      assert TomlWriter.wrap("", 7) == [""]
      assert TomlWriter.string("\b\f\r\n\u007f") == ~S("\b\f\r\n\u007F")
    end
  end
end
