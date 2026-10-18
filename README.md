# Sovite

A modern, secure Mail Transfer Agent written in Elixir/OTP, meant as an alternative to Postfix.

> **Status:** early development. Sovite receives mail over SMTP, queues it durably, and relays it to other servers with retries and bounces (Phases 1–2). It speaks TLS both ways (STARTTLS, implicit TLS, SNI, ACME, DANE) and accepts mail from authenticated clients on submission ports (Phase 3). It routes mail by its own database: hosted domains, aliases, mailboxes, transports, address rewriting, BCC, and access rules at every SMTP stage, all managed with `sovitectl` (Phase 4). It hands mail to mailbox servers such as Dovecot over LMTP, delivers to Maildir folders and pipe commands, detects mail loops, and can itself listen for LMTP (Phase 5). It checks SPF, DKIM, ARC, and DMARC on received mail, DKIM signs and ARC seals what it sends and forwards, rewrites forwarded senders with SRS, sends DMARC reports, and prints the DNS records a domain needs (Phase 6). It follows the DANE and MTA-STS policies of recipient domains, serves its own MTA-STS policy, sends TLS-RPT reports, and supports REQUIRETLS (Phase 7). It screens clients as postscreen does (greeting delay, weighted DNSBL, DNSWL, and RHSBL scores), greylists, checks reverse DNS and `EHLO` names, rate-limits clients and users, tarpits, refuses pipelining abuse, and suspends accounts whose mail bounces too much (Phase 8). It works with the Postfix ecosystem: milters such as Rspamd and OpenDKIM, policy servers such as postgrey and policyd-spf, after-queue content filters, HAProxy's PROXY protocol, `XCLIENT` and `XFORWARD`, and `sendmail`, `mailq`, and `newaliases` for local programs; `sovitectl migrate postfix` converts a Postfix configuration (Phase 9). It handles internationalized mail: `SMTPUTF8` addresses, internationalized domain names (IDNA2008), UTF-8 header fields, and internationalized delivery status notifications, returning what a next hop without `SMTPUTF8` cannot take (Phase 10). It speaks the additional ESMTP extensions: `CHUNKING` and `BINARYMIME`, `DSN` (with success notifications, `RET`, `ENVID`, and `ORCPT`), `ETRN`, `MT-PRIORITY`, `FUTURERELEASE`, `DELIVERBY`, and `RRVS` (Phase 11). It is run with `sovitectl`: the queue (list, show, flush, hold, release, delete, requeue), the configuration (show, diff, reload without downtime), how an address routes, status, message traces by queue ID or `Message-ID`, and pflogsumm-style log reports; it serves the web UI and an authenticated admin API (Plug and Cowboy), Prometheus metrics, and OpenTelemetry traces, logs to files, standard output, or syslog, drains gracefully on shutdown, integrates with systemd (notify, watchdog, socket activation, a hardened unit), and ships as a release tarball, `.deb` and `.rpm` packages, and a container image (Phase 12). Several servers can run as one cluster over Partisan, with mutual TLS between the nodes: they share a configuration pushed to all of them, rate limits, bans, and greylisting, keep copies of each other's queues and deliver the mail of a node that stays down, hand a leaving node's queue to the others, and can send all mail for a destination from one node; it hosts tenants with their own limits, DKIM keys, and IP pools, and sends from outbound IP pools with warm-up schedules and daily limits (Phase 13). Hardening for 1.0 is next. See the [roadmap](ROADMAP.md).

Sovite is also a library: its components (address validators, DNS and MX resolution, an SMTP server and client, TLS with DANE and ACME, SASL, LDAP, RFC 5322 address lists, delivery status notifications, and later DKIM, SPF, ...) can be used from any Elixir project without running the MTA. See [STRUCTURE.md](STRUCTURE.md).

## Development

Requires Erlang/OTP 29 and Elixir 1.20 (see `mise.toml`).

```sh
mix setup           # deps.get
mix test            # tests, including property tests
mix lint            # format check, warnings as errors, credo, xref cycles
mix dialyzer
```

The first Dialyzer run builds its PLT and takes a few minutes; later runs are incremental.

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
mix dev.mta         # the MTA: SMTP on 127.0.0.1:2525, web UI and admin API on 127.0.0.1:9025
mix dev             # the MTA and the web UI's dev server (bun dev, http://localhost:5173)
iex -S mix dev.mta  # with a shell
```

They use `--config PATH`, `$SOVITE_CONFIG`, or `sovite.toml` in the project if one of them is given; otherwise they write `development/sovite.toml`, with data in `development/`, local mail for `sovite.test` in Maildir folders there, and other mail relayed to `127.0.0.1:1025` for a mail catcher such as Mailpit, never to the internet. They print the admin token to sign in to the web UI with. The web UI's own checks run in the project root: `bun run check`, `bun run lint`, `bun run test`.

Build a release:

```sh
MIX_ENV=prod mix release
_build/prod/rel/sovite/bin/sovitectl config check _build/prod/rel/sovite/etc/sovite.toml.example
SOVITE_CONFIG=/etc/sovite/sovite.toml _build/prod/rel/sovite/bin/sovite start
```

## Documentation

- [Configuration](docs/configuration.md)
- [Logging and telemetry](docs/logging.md)
- [Operations](docs/operations.md): `sovitectl`, the web UI and admin API, metrics, reloads, clusters, systemd, packages
- [Security model](docs/security.md) and [vulnerability reporting](SECURITY.md)

## License

AGPL-3.0. See [LICENSE](LICENSE).
