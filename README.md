# Sovite

A modern, secure Mail Transfer Agent written in Elixir/OTP, meant as an alternative to Postfix.

> **Status:** early development. Sovite receives mail over SMTP, queues it durably, and relays it to other servers with retries and bounces (Phases 1–2). It speaks TLS both ways (STARTTLS, implicit TLS, SNI, ACME, DANE) and accepts mail from authenticated clients on submission ports (Phase 3). It routes mail by its own database: hosted domains, aliases, mailboxes, transports, address rewriting, BCC, and access rules at every SMTP stage, all managed with `sovitectl` (Phase 4). It hands mail to mailbox servers such as Dovecot over LMTP, delivers to Maildir folders and pipe commands, detects mail loops, and can itself listen for LMTP (Phase 5). It checks SPF, DKIM, ARC, and DMARC on received mail, DKIM signs and ARC seals what it sends and forwards, rewrites forwarded senders with SRS, sends DMARC reports, and prints the DNS records a domain needs (Phase 6). It follows the DANE and MTA-STS policies of recipient domains, serves its own MTA-STS policy, sends TLS-RPT reports, and supports REQUIRETLS (Phase 7). It screens clients as postscreen does (greeting delay, weighted DNSBL, DNSWL, and RHSBL scores), greylists, checks reverse DNS and `EHLO` names, rate-limits clients and users, tarpits, refuses pipelining abuse, and suspends accounts whose mail bounces too much (Phase 8). It works with the Postfix ecosystem: milters such as Rspamd and OpenDKIM, policy servers such as postgrey and policyd-spf, after-queue content filters, HAProxy's PROXY protocol, `XCLIENT` and `XFORWARD`, and `sendmail`, `mailq`, and `newaliases` for local programs; `sovitectl migrate postfix` converts a Postfix configuration (Phase 9). It handles internationalized mail: `SMTPUTF8` addresses, internationalized domain names (IDNA2008), UTF-8 header fields, and internationalized delivery status notifications, returning what a next hop without `SMTPUTF8` cannot take (Phase 10). Additional ESMTP extensions are next. See the [roadmap](ROADMAP.md).

Sovite is also a library: its components (address validators, DNS and MX resolution, an SMTP server and client, TLS with DANE and ACME, SASL, LDAP, RFC 5322 address lists, delivery status notifications, and later DKIM, SPF, ...) can be used from any Elixir project without running the MTA. See [STRUCTURE.md](STRUCTURE.md).

## Development

Requires Erlang/OTP 29 and Elixir 1.20 (see `mise.toml`).

```sh
mix setup           # deps.get, and enables the git pre-commit hook
mix test            # tests, including property tests
mix lint            # format check, warnings as errors, credo, xref cycles
mix dialyzer
```

The pre-commit hook (`.githooks/pre-commit`) runs `mix lint` and `mix dialyzer` and refuses the commit if either fails. The first Dialyzer run builds its PLT and takes a few minutes; later runs are incremental.

Manage routing data (stored in Sovite's database):

```sh
sovitectl domain add example.com hosted
sovitectl mailbox add alice@example.com
sovitectl alias add sales@example.com alice@example.com bob@example.com
sovitectl transport set example.com lmtp:unix:/run/dovecot/lmtp
sovitectl access set client 192.0.2 REJECT spam source   # used by client_access in [restrictions]
```

Run the MTA locally:

```sh
cp rel/overlays/etc/sovite.toml.example sovite.toml   # edit as needed
SOVITE_START_MTA=1 SOVITE_CONFIG=./sovite.toml iex -S mix
```

Build a release:

```sh
MIX_ENV=prod mix release
_build/prod/rel/sovite/bin/sovitectl config check _build/prod/rel/sovite/etc/sovite.toml.example
SOVITE_CONFIG=/etc/sovite/sovite.toml _build/prod/rel/sovite/bin/sovite start
```

## Documentation

- [Configuration](docs/configuration.md)
- [Logging and telemetry](docs/logging.md)
- [Security model](docs/security.md) and [vulnerability reporting](SECURITY.md)

## License

AGPL-3.0. See [LICENSE](LICENSE).
