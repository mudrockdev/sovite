# Sovite Roadmap

Sovite is a Mail Transfer Agent (MTA) written in Elixir/OTP, meant as a modern alternative to Postfix.
This document lists the features to build, the standards to implement, and the order to build them in.

---

## 1. Vision & Principles

- **Secure by default.** TLS everywhere it is possible, no open relay ever, modern crypto only, least privilege.
- **Correct before clever.** Strict RFC compliance on the wire, lenient-but-safe parsing of real-world input ("be liberal in what you accept" only where it is safe).
- **Crash-safe queue.** No accepted message is ever lost. `250 OK` means the message is durably on disk.
- **OTP-native.** One supervised process per connection / delivery attempt, isolated failures, hot config reload, built-in clustering as a long-term differentiator.
- **Ecosystem compatible.** Speak the protocols the existing mail ecosystem already uses (milter, Postfix policy delegation, LMTP, `sendmail(1)`) so users can migrate without replacing their filters, spam scanners, and mailbox servers.
- **Observable.** Every message has a traceable lifecycle; metrics and structured logs come built in.
- **Simple configuration.** One readable config file with validation and clear error messages, plus a migration helper for Postfix `main.cf` / `master.cf`.

### Non-goals

- IMAP / POP3 / JMAP server (use Dovecot, Stalwart, etc.; Sovite delivers to them via LMTP).
- Webmail or a GUI mail client.
- A built-in content-based spam classifier (integrate Rspamd / SpamAssassin via milter instead).
- Mailing list management (Mailman-style). Only list-related header standards are in scope.

---

## 2. Architecture Overview (target)

| Component | Role | Postfix equivalent |
|---|---|---|
| Listener | Accepts TCP connections, PROXY protocol, connection limits | `master`, `postscreen` |
| SMTP server | Inbound SMTP / Submission / LMTP-in session state machine | `smtpd` |
| Cleanup | Header normalization, address rewriting, `Received:` / `Message-ID:` / `Date:` insertion | `cleanup`, `trivial-rewrite` |
| Queue manager | Durable queue, scheduling, retry/backoff, per-destination concurrency | `qmgr` |
| SMTP client | Outbound delivery with MX resolution, TLS policy, connection reuse | `smtp` |
| Local/LMTP delivery | Hand-off to mailbox servers, pipes, Maildir | `local`, `lmtp`, `virtual`, `pipe` |
| Bounce service | DSN generation, delay warnings | `bounce` |
| Routing data | Domains, aliases, mailboxes, transports, access rules: typed tables in Sovite's database, managed with `sovitectl` | `*_maps`, `postmap` |
| CLI | Queue inspection, flush, hold, delete, config check | `postqueue`, `postsuper`, `postconf`, `mailq` |

---

## 3. Phased Roadmap

Each phase has a "Definition of Done". A phase is not finished until its interoperability tests pass.

### Phase 0 — Foundations

- [x] Project layout: OTP application, supervision tree design, release build (`mix release`)
- [x] Configuration system: file format, schema validation, defaults, `sovite config check`
- [x] Logging conventions: structured logs with a per-message queue ID
- [x] Telemetry events defined from day one (connection, command, queue, delivery)
- [x] Test harness: SMTP client test helpers, fake DNS resolver, fake remote MTAs
- [x] Property-based / fuzz testing setup for the parsers
- [x] CI: format, credo/dialyzer, tests, coverage
- [x] Security model doc: privileges, file ownership, threat model

**Done when:** the empty application builds as a release, loads and validates config, and has a working test harness.

### Phase 1 — Core SMTP Receiver (MVP inbound)

- [x] TCP listener with acceptor pool, connection limits (global and per-IP)
- [x] SMTP session state machine: `EHLO`/`HELO`, `MAIL`, `RCPT`, `DATA`, `RSET`, `NOOP`, `QUIT`, `VRFY` (disabled by default), `HELP`
- [x] Strict command-line parsing, line length limits, bare-LF / bare-CR handling (SMTP smuggling protection)
- [x] ESMTP extensions: `PIPELINING`, `SIZE`, `8BITMIME`, `ENHANCEDSTATUSCODES`
- [x] Timeouts per RFC 5321 §4.5.3.2
- [x] Dot-stuffing / un-stuffing, message size enforcement while streaming
- [x] `Received:` header with RFC 3848 transmission types
- [x] Recipient validation against configured local/relay domains (reject unknown users at RCPT time)
- [x] Open relay prevention: relay only for authenticated users or trusted networks
- [x] Durable spool: write + `fsync` before replying `250`

**Standards:** RFC 5321, RFC 5322, RFC 1870, RFC 6152, RFC 2920, RFC 2034, RFC 3463, RFC 5248, RFC 3848

**Done when:** Sovite accepts mail from Postfix, Exim, and `swaks`, stores it durably, and passes an open-relay test.

### Phase 2 — Queue & Outbound Delivery (MVP outbound)

- [x] Queue structure: incoming, active, deferred, hold, corrupt
- [x] Queue file format: versioned, checksummed envelope + message body, crash recovery on startup
- [x] Scheduler: exponential backoff, maximum queue lifetime (default 5 days), per-destination concurrency and rate limits
- [x] DNS resolution: MX, A/AAAA fallback (implicit MX), Null MX handling, preference ordering, randomization among equal-preference hosts
- [x] IPv4 + IPv6 dual-stack delivery with fallback
- [x] SMTP client: EHLO negotiation, pipelining, connection caching/reuse
- [x] Multi-recipient messages: per-recipient status tracking, partial failures
- [x] Bounces: DSN generation for permanent failures, delay warnings (configurable)
- [x] Double-bounce handling and null-sender (`<>`) rules
- [x] `postmaster@` and `abuse@` always accepted
- [x] Smart host / relayhost support

**Standards:** RFC 5321 §4.5.4 (retry strategy) & §5 (address resolution), RFC 7505 (Null MX), RFC 3461, RFC 3464, RFC 6522, RFC 3834

**Done when:** Sovite can relay to Gmail/Outlook/Postfix, retries correctly on 4xx, bounces correctly on 5xx, and survives `kill -9` mid-delivery with no lost or duplicated mail (beyond what SMTP inherently allows).

### Phase 3 — TLS & Submission

- [x] `STARTTLS` on port 25 (server and client side)
- [x] Implicit TLS submission on port 465
- [x] Submission on port 587 with mandatory auth
- [x] TLS 1.2 and 1.3 only; modern cipher suites; configurable per listener
- [x] Multiple certificates with SNI selection
- [x] Automatic certificate reload; optional ACME (Let's Encrypt) integration
- [x] Outbound opportunistic TLS by default; per-destination TLS policy (none / may / encrypt / verify / dane)
- [x] SMTP AUTH: `PLAIN`, `LOGIN` (legacy compat), `SCRAM-SHA-256`, `OAUTHBEARER`
- [x] Auth backends: static file, SQL (Sovite's own database via Ecto: SQLite by default, PostgreSQL or MySQL), LDAP, Dovecot SASL protocol
- [x] Auth only offered after TLS (configurable but secure default)
- [x] Brute-force protection: auth failure rate limiting and temporary bans
- [x] Sender login maps (authenticated user may only send as allowed addresses)
- [x] Message submission fixes: add missing `Date:` / `Message-ID:`, strip/rewrite client headers

**Standards:** RFC 3207, RFC 6409, RFC 8314, RFC 4954, RFC 4422, RFC 4616, RFC 5802, RFC 7677, RFC 7628, RFC 8446, RFC 8996, RFC 9325 (BCP 195), RFC 7817, RFC 9525, RFC 7435, RFC 6186

**Done when:** Thunderbird, Apple Mail, and Outlook can submit mail; testssl.sh reports no weak configuration.

### Phase 4 — Routing, Rewriting & Routing Data

- [x] Routing data in Sovite's database: a migration and typed schema per table (domains, aliases, mailboxes, moved users, transports, sender relays, access rules, address rewrites, BCC rules), managed with `sovitectl`
- [x] Aliases: full address, local part, and `@domain` catch-all, expanded recursively with loop and size limits
- [x] Domain classes: local, aliased, hosted (mailboxes), relay
- [x] Sender/recipient address rewriting, hiding subdomains, rewriting header addresses for trusted and authenticated clients
- [x] Moved users (`5.1.6`), recipient BCC, sender BCC, always-BCC
- [x] Transports: per-domain/per-recipient next hop and transport (`smtp`, `lmtp`, `local`, `mailbox`, `error`, `retry`, `discard`)
- [x] Sender-dependent relay host, outbound IP, and relay credentials
- [x] Address extensions (`user+tag@`) with configurable delimiter
- [x] Restriction chains with access rules at CONNECT, HELO, MAIL, RCPT, DATA, END-OF-DATA stages (reject, defer, discard, hold, warn)
- [x] Changes apply without restart (tables read live; domains cached for a few seconds)

**Done when:** a typical virtual-hosting setup (hosted domains + aliases + transport to LMTP) can be expressed in Sovite. (LMTP delivery itself arrives in Phase 5.)

### Phase 5 — Local Delivery & Mailbox Hand-off

- [x] LMTP client (to Dovecot, Cyrus, Stalwart) over TCP and Unix sockets
- [x] LMTP server mode (optional, for use behind other MTAs)
- [x] Maildir delivery (optional, for simple setups)
- [x] Pipe transport (deliver to external command, with sandboxing)
- [x] `Delivered-To:` header and mail loop detection (hop count limit)
- [x] `Return-Path:` insertion at final delivery

**Standards:** RFC 2033, RFC 9228, RFC 5321 §6.3 (loop detection)

**Done when:** end-to-end inbound → Dovecot LMTP works with per-recipient status codes.

### Phase 6 — Email Authentication

- [x] SPF verification for inbound (MAIL FROM and HELO identities), with DNS lookup limits enforced
- [x] DKIM verification (RSA-SHA256, Ed25519); reject RSA-SHA1 per RFC 8301
- [x] DKIM signing for outbound: multiple selectors, per-domain keys, dual signing (RSA + Ed25519), key rotation support
- [x] DMARC evaluation with alignment checks and policy enforcement (configurable: report-only / enforce)
- [x] DMARC aggregate report generation (optional, opt-in)
- [x] ARC verification and sealing (for forwarders and mailing lists)
- [x] `Authentication-Results:` header generation; strip forged incoming `Authentication-Results:` for our own authserv-id
- [x] Sender Rewriting Scheme (SRS) for forwarded mail
- [x] DNS helper CLI: print the SPF, DKIM, DMARC, MTA-STS, and TLS-RPT records a domain needs

**Standards:** RFC 7208, RFC 6376, RFC 8301, RFC 8463, RFC 7489 (and DMARCbis as it lands), RFC 8617, RFC 8601, RFC 7372, RFC 6591

**Done when:** outbound mail passes SPF/DKIM/DMARC at Gmail and Outlook; inbound verdicts match reference implementations on a test corpus.

### Phase 7 — Transport Security Policies

- [x] DNSSEC-validating resolver integration (or require a local validating resolver)
- [x] DANE outbound: TLSA lookup and verification (DANE-EE, DANE-TA)
- [x] MTA-STS outbound: policy fetch, caching, enforcement, testing mode
- [x] MTA-STS inbound: serve policy (or document how to host it)
- [x] TLS-RPT: collect TLS delivery results and send daily reports
- [x] REQUIRETLS extension
- [x] Precedence rules when DANE and MTA-STS both apply (DANE wins)

**Standards:** RFC 4033–4035, RFC 6698, RFC 7671, RFC 7672, RFC 8461, RFC 8460, RFC 8689

**Done when:** delivery to DANE-enabled and MTA-STS-enabled domains enforces policy; mismatch tests correctly defer mail.

### Phase 8 — Anti-Abuse (postscreen-like)

- [x] Pre-greeting ("early talker") detection
- [x] DNSBL / DNSWL checks with weighted scoring
- [x] RHSBL checks for sender/HELO domains
- [x] Greylisting (built in, optional)
- [x] Reverse DNS / FCrDNS checks (configurable strictness)
- [x] HELO validation policies
- [x] Rate limits: per-IP connections, messages, recipients; per authenticated user sending quotas
- [x] Tarpitting on suspicious behavior
- [x] Protocol hygiene: reject pipelining abuse, non-SMTP commands, bare LF (SMTP smuggling)
- [x] Outbound abuse protection: detect compromised accounts by volume / bounce rate spikes

**Standards:** RFC 5782 (DNSBL), RFC 5965 (ARF, for feedback loops)

**Done when:** bot traffic from a replay corpus is rejected before DATA with a low false-positive rate.

### Phase 9 — Ecosystem Compatibility

- [x] **Milter protocol** (Sendmail milter v6) client: works with Rspamd, OpenDKIM, OpenDMARC, ClamAV-milter
- [x] **Postfix policy delegation protocol**: works with policyd-spf, postgrey, and other existing policy servers
- [x] **`sendmail(1)`-compatible binary** (`sendmail`, `mailq`, `newaliases`) for local apps and cron
- [x] PROXY protocol v1/v2 (behind HAProxy / load balancers)
- [x] XCLIENT / XFORWARD (optional, for proxies and content filters)
- [x] Content filter re-injection (after-queue filtering via SMTP/LMTP)
- [x] Postfix config migration tool: read `main.cf` / `master.cf` and produce a Sovite config plus a report of unsupported settings

**Done when:** a stock Postfix + Rspamd + Dovecot setup can be migrated to Sovite + Rspamd + Dovecot with the migration tool.

### Phase 10 — Internationalization

- [x] `SMTPUTF8` extension (UTF-8 local parts and domains)
- [x] IDNA2008 domain handling (U-label / A-label conversion)
- [x] UTF-8 header handling
- [x] Downgrade behavior when next hop lacks `SMTPUTF8` (bounce with clear DSN)
- [x] Internationalized DSNs

**Standards:** RFC 6530, RFC 6531, RFC 6532, RFC 6533, RFC 5890–5893

### Phase 11 — Additional ESMTP Extensions

- [ ] `CHUNKING` / `BDAT` and `BINARYMIME`
- [ ] `DSN` extension (NOTIFY, RET, ENVID, ORCPT) — full support
- [ ] `ETRN` (queue run for a domain)
- [ ] `FUTURERELEASE` (optional)
- [ ] `DELIVERBY` (optional)
- [ ] `MT-PRIORITY` (optional)
- [ ] `RRVS` (optional)

**Standards:** RFC 3030, RFC 3461, RFC 1985, RFC 4865, RFC 2852, RFC 6710, RFC 7293

### Phase 12 — Operations & Observability

- [ ] CLI: `sovite queue list|show|flush|hold|release|delete|requeue`, `sovite config check|show|diff`, `sovite route ADDRESS` (show how the routing tables resolve an address), `sovite status`
- [ ] Message tracing: follow a message from connection to final delivery by queue ID or Message-ID
- [ ] Prometheus metrics endpoint; OpenTelemetry traces
- [ ] Structured JSON logs + classic syslog-style output
- [ ] Admin HTTP API (authenticated, local-only by default)
- [ ] Optional LiveDashboard-based status UI
- [ ] Graceful shutdown and drain; zero-downtime config reload
- [ ] systemd integration: socket activation, `sd_notify`, hardening directives
- [ ] Packaging: container image, `.deb` / `.rpm`, release tarballs
- [ ] Log-based tooling compatibility (pflogsumm-style summary report)

### Phase 13 — Scale & Clustering (differentiator)

- [ ] Multiple nodes sharing configuration
- [ ] Distributed queue / queue handover when a node goes down
- [ ] Cluster-wide rate limits and greylisting state
- [ ] Shared connection caching per destination across nodes
- [ ] Per-tenant isolation (multi-tenant hosting): separate limits, keys, IP pools
- [ ] Outbound IP pool management and warm-up schedules

### Phase 14 — Hardening for 1.0

- [ ] External security audit
- [ ] Fuzzing campaign on SMTP parser, MIME/header parser, DNS response handling, queue file reader
- [ ] Long-running soak tests (weeks) with real traffic mirrors
- [ ] Performance benchmarks vs Postfix (throughput, latency, memory per connection)
- [ ] Complete documentation: admin guide, config reference, migration guide, security guide
- [ ] Stable config format and queue format with documented upgrade path
- [ ] Interop test matrix against Postfix, Exim, Microsoft Exchange/365, Gmail, Stalwart, OpenSMTPD

---

## 4. Standards Compliance Matrix

**Level:** MUST = required for 1.0, SHOULD = planned for 1.0, MAY = optional / later.

### Core SMTP & Message Format

| Standard | Title | Level | Phase |
|---|---|---|---|
| RFC 5321 | Simple Mail Transfer Protocol | MUST | 1–2 |
| RFC 5322 | Internet Message Format | MUST | 1 |
| RFC 2045–2049 | MIME | MUST (parsing for DKIM/DSN) | 1–6 |
| RFC 6409 | Message Submission | MUST | 3 |
| RFC 8314 | Implicit TLS for Submission | MUST | 3 |
| RFC 3848 | ESMTP Transmission Types | MUST | 1 |
| RFC 7505 | Null MX | MUST | 2 |
| RFC 2033 | LMTP | MUST | 5 |
| RFC 9228 | Delivered-To Header Field | SHOULD | 5 |

### ESMTP Extensions

| Standard | Extension | Level | Phase |
|---|---|---|---|
| RFC 1870 | SIZE | MUST | 1 |
| RFC 6152 | 8BITMIME | MUST | 1 |
| RFC 2920 | PIPELINING | MUST | 1 |
| RFC 2034 / RFC 3463 / RFC 5248 | ENHANCEDSTATUSCODES | MUST | 1 |
| RFC 3207 | STARTTLS | MUST | 3 |
| RFC 4954 | AUTH | MUST | 3 |
| RFC 3461 | DSN | MUST | 11 |
| RFC 3030 | CHUNKING / BINARYMIME | SHOULD | 11 |
| RFC 6531 | SMTPUTF8 | SHOULD | 10 |
| RFC 8689 | REQUIRETLS | SHOULD | 7 |
| RFC 1985 | ETRN | MAY | 11 |
| RFC 4865 | FUTURERELEASE | MAY | 11 |
| RFC 2852 | DELIVERBY | MAY | 11 |
| RFC 6710 | MT-PRIORITY | MAY | 11 |
| RFC 7293 | RRVS | MAY | 11 |

### Delivery Status & Reporting

| Standard | Title | Level | Phase |
|---|---|---|---|
| RFC 3464 | DSN Message Format | MUST | 2 |
| RFC 6522 | multipart/report | MUST | 2 |
| RFC 3834 | Automatic Responses | MUST | 2 |
| RFC 6533 | Internationalized DSNs | SHOULD | 10 |
| RFC 5965 | Abuse Reporting Format (ARF) | MAY | 8 |
| RFC 6591 | Authentication Failure Reporting | MAY | 6 |

### Authentication & SASL

| Standard | Title | Level | Phase |
|---|---|---|---|
| RFC 4422 | SASL | MUST | 3 |
| RFC 4616 | PLAIN | MUST | 3 |
| RFC 5802 / RFC 7677 | SCRAM / SCRAM-SHA-256 | SHOULD | 3 |
| RFC 7628 | OAUTHBEARER | SHOULD | 3 |
| draft-murchison-sasl-login | LOGIN (legacy clients) | SHOULD | 3 |

### Email Authentication

| Standard | Title | Level | Phase |
|---|---|---|---|
| RFC 7208 | SPF | MUST | 6 |
| RFC 6376 | DKIM | MUST | 6 |
| RFC 8301 | DKIM Crypto Update | MUST | 6 |
| RFC 8463 | DKIM Ed25519 | SHOULD | 6 |
| RFC 7489 / DMARCbis | DMARC | MUST | 6 |
| RFC 8601 | Authentication-Results | MUST | 6 |
| RFC 7372 | Email Auth Status Codes | SHOULD | 6 |
| RFC 8617 | ARC | SHOULD | 6 |
| SRS (de-facto spec) | Sender Rewriting Scheme | SHOULD | 6 |

### Transport Security

| Standard | Title | Level | Phase |
|---|---|---|---|
| RFC 8446 | TLS 1.3 | MUST | 3 |
| RFC 8996 | Deprecate TLS 1.0 / 1.1 | MUST | 3 |
| RFC 9325 (BCP 195) | TLS Recommendations | MUST | 3 |
| RFC 7817 / RFC 9525 | TLS Server Identity for Email | MUST | 3 |
| RFC 7435 | Opportunistic Security | MUST | 3 |
| RFC 7672 / RFC 6698 / RFC 7671 | DANE for SMTP / TLSA | SHOULD | 7 |
| RFC 4033–4035 | DNSSEC | SHOULD | 7 |
| RFC 8461 | MTA-STS | SHOULD | 7 |
| RFC 8460 | SMTP TLS Reporting | SHOULD | 7 |

### Internationalization

| Standard | Title | Level | Phase |
|---|---|---|---|
| RFC 6530 | EAI Overview | SHOULD | 10 |
| RFC 6532 | Internationalized Headers | SHOULD | 10 |
| RFC 5890–5893 | IDNA2008 | SHOULD | 10 |

### Anti-Abuse & Lists

| Standard | Title | Level | Phase |
|---|---|---|---|
| RFC 5782 | DNS Blacklists / Whitelists | SHOULD | 8 |
| RFC 2369 | List-* Headers (pass-through, preserve for DKIM) | SHOULD | 6 |
| RFC 8058 | One-Click Unsubscribe (preserve for DKIM signing) | SHOULD | 6 |

### Ecosystem Protocols (non-RFC)

| Spec | Purpose | Level | Phase |
|---|---|---|---|
| Sendmail Milter protocol v6 | Content filters (Rspamd, OpenDKIM, ClamAV) | MUST | 9 |
| Postfix policy delegation | Policy servers (postgrey, policyd-spf) | SHOULD | 9 |
| HAProxy PROXY protocol v1/v2 | Load balancer client IP passthrough | SHOULD | 9 |
| Dovecot SASL auth protocol | Reuse Dovecot user database for SMTP AUTH | SHOULD | 3 |
| `sendmail(1)` CLI conventions | Local mail submission by apps | MUST | 9 |
| XCLIENT / XFORWARD | Proxy and content filter attribute passing | MAY | 9 |
| ACME (RFC 8555) | Automatic certificates | MAY | 3 |

---

## 5. Security Requirements (cross-cutting)

- Never an open relay; relay permission must be explicit (authenticated user or trusted network).
- Bind privileged ports without running the VM as root (systemd socket activation or `CAP_NET_BIND_SERVICE`).
- Queue files readable only by the Sovite user; secrets (DKIM keys, TLS keys, auth DB credentials) never logged.
- Hard limits on everything parsed from the network: line length, header count, header size, recipients per message, message size, nesting depth of MIME, DNS response size, SPF lookup count.
- No atom creation from untrusted input (BEAM atom table exhaustion).
- Protection against SMTP smuggling (strict `<CRLF>.<CRLF>` handling, bare LF/CR policy).
- Protection against STARTTLS command injection (discard buffered plaintext after TLS handshake).
- Constant-time comparison for credentials; password hashes with modern KDFs (Argon2id / bcrypt / SCRAM salted).
- Reproducible builds and signed releases.
- Documented responsible disclosure process (`SECURITY.md`).

---

## 6. Quality & Testing Strategy

- **Unit + property tests** for every parser (SMTP commands, addresses, headers, MIME, DNS records, SPF/DMARC records).
- **Conformance tests** derived from RFC examples and test suites (e.g. the SPF test suite (pyspf YAML), DKIM test vectors).
- **Interop tests** in CI using containers: Postfix, Exim, OpenSMTPD, Dovecot, Rspamd.
- **Chaos tests**: kill nodes and processes during delivery; corrupt queue files; DNS timeouts and SERVFAIL.
- **Load tests**: sustained throughput, connection storms, large messages, many recipients.
- **Fuzzing** of all network-facing parsers.

---

## 7. Milestones Summary

| Milestone | Phases | Outcome |
|---|---|---|
| **0.1 — "It relays"** | 0, 1, 2 | Receive, queue, and deliver mail reliably |
| **0.2 — "It's safe on the internet"** | 3, 4, 5 | TLS, submission, auth, virtual hosting, LMTP to Dovecot |
| **0.3 — "It's trusted by big providers"** | 6, 7 | SPF/DKIM/DMARC/ARC, DANE, MTA-STS |
| **0.4 — "It replaces Postfix"** | 8, 9 | Anti-abuse, milter, policy servers, migration tool |
| **0.5 — "It's complete"** | 10, 11, 12 | SMTPUTF8, full ESMTP, operations tooling |
| **0.6 — "It scales"** | 13 | Clustering, multi-tenant |
| **1.0 — "Production ready"** | 14 | Audited, benchmarked, documented, stable formats |
