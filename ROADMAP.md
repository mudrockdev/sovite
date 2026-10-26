# Sovite Roadmap

Sovite is a mail server written in Elixir/OTP: a whole stack in one application, with three parts that can each be turned on or off:

| Part | Replaces | Version |
|---|---|---|
| **MTA**: receiving, queuing, routing, and delivering mail | Postfix | 1.0 |
| **Filter**: spam, phishing, and malware filtering | Rspamd | 2.0 |
| **Mailbox**: mail storage, IMAP, POP3, Sieve | Dovecot | 3.0 |

All three are on by default. Each is optional: a part that is off can be replaced by the program it stands in for (Rspamd over milter, Dovecot over LMTP and its auth protocol), so Sovite can run as the whole stack, or as any one or two parts of it next to existing servers.

This document lists the features to build, the standards to implement, and the order to build them in.

---

## 1. Vision & Principles

- **Secure by default.** TLS everywhere it is possible, no open relay ever, modern crypto only, least privilege.
- **Correct before clever.** Strict RFC compliance on the wire, lenient-but-safe parsing of real-world input ("be liberal in what you accept" only where it is safe).
- **Crash-safe queue.** No accepted message is ever lost. `250 OK` means the message is durably on disk.
- **OTP-native.** One supervised process per connection / delivery attempt, isolated failures, hot config reload, built-in clustering as a long-term differentiator.
- **Ecosystem compatible.** Speak the protocols the existing mail ecosystem already uses (milter, Postfix policy delegation, LMTP, `sendmail(1)`) so users can migrate without replacing their filters, spam scanners, and mailbox servers.
- **Observable.** Every message has a traceable lifecycle; metrics and structured logs come built in.
- **Simple configuration.** One readable config file with validation and clear error messages, plus migration helpers for Postfix, Rspamd, and Dovecot configurations.
- **Modular whole stack.** The MTA, filter, and mailbox parts live in one application, share one config file, one CLI, one web UI, and one cluster, and are each optional (all on by default). Parts talk to each other through defined internal interfaces, so each can also run on its own nodes.
- **One database, separate parts.** All parts share Sovite's one database and one schema (SQLite by default, PostgreSQL or MySQL), with typed tables and migrations as today. Parts are kept apart in the code instead: each part reads and writes only its own tables, and reaches another part's data only through that part's internal interface, so the filter never sees passwords and the MTA hands mail to the mailbox part without reading the mail store.

### Non-goals

- Webmail or a GUI mail client (the web UI is for administration, and for users' own settings from 3.0 on).
- Calendars and contacts (CalDAV, CardDAV) before 3.0; reconsidered afterwards.
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

The filter part (2.0):

| Component | Role | Rspamd equivalent |
|---|---|---|
| Message analyzer | MIME, HTML, URL, and attachment extraction with hard limits | message parser, `lua_mime` |
| Rule engine | Symbols, scores, composites, actions; per-tenant and per-user settings | rules, composites, `settings` |
| Statistics | Bayesian classifier, autolearning | `classifier_bayes` |
| Fuzzy storage | Fuzzy hashes of known spam, shared by the cluster | `fuzzy_check`, `rspamd_fuzzy` |
| Reputation | IP, domain, URL, and sender reputation; RBL/URIBL lookups | `reputation`, `rbl`, `surbl` |
| Scanners | Antivirus (clamd) and attachment policies | `antivirus`, `mime_types` |
| Filter API | Rspamd-compatible HTTP protocol and milter server, for other MTAs | `rspamd_proxy`, `/checkv2` |

The mailbox part (3.0):

| Component | Role | Dovecot equivalent |
|---|---|---|
| Mail store | Crash-safe mailbox storage with indexes, quotas, optional encryption at rest | `mdbox`/`maildir`, indexes, quota |
| IMAP server | IMAP4rev2 with the extensions clients use | `imap` |
| POP3 server | POP3 for legacy clients | `pop3` |
| Sieve | Server-side filters, vacation replies, ManageSieve | Pigeonhole |
| Replication & proxy | Mailboxes replicated across cluster nodes; users routed to their node | `dsync`, `director`/proxy |
| Auth | Users and app passwords for SMTP, IMAP, POP3, and the web UI | `auth` |

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

- [x] `CHUNKING` / `BDAT` and `BINARYMIME`
- [x] `DSN` extension (NOTIFY, RET, ENVID, ORCPT) — full support
- [x] `ETRN` (queue run for a domain)
- [x] `FUTURERELEASE` (optional)
- [x] `DELIVERBY` (optional)
- [x] `MT-PRIORITY` (optional)
- [x] `RRVS` (optional)

**Standards:** RFC 3030, RFC 3461, RFC 1985, RFC 4865, RFC 2852, RFC 6710, RFC 7293

### Phase 12 — Operations & Observability

- [x] CLI: `sovite queue list|show|flush|hold|release|delete|requeue`, `sovite config check|show|diff`, `sovite route ADDRESS` (show how the routing tables resolve an address), `sovite status`
- [x] Message tracing: follow a message from connection to final delivery by queue ID or Message-ID
- [x] Prometheus metrics endpoint; OpenTelemetry traces
- [x] Structured JSON logs + classic syslog-style output
- [x] Admin HTTP API (authenticated, local-only by default)
- [x] Optional LiveDashboard-based status UI (the web server on Plug and Cowboy serves the static build of `lib/core/sovite_web` at `/` and the admin API at `/api`; the UI pages themselves are still to be written)
- [x] Graceful shutdown and drain; zero-downtime config reload
- [x] systemd integration: socket activation, `sd_notify`, hardening directives
- [x] Packaging: container image, `.deb` / `.rpm`, release tarballs
- [x] Log-based tooling compatibility (pflogsumm-style summary report)

### Phase 13 — Scale & Clustering (differentiator)

- [x] Multiple nodes sharing configuration
- [x] Distributed queue / queue handover when a node goes down
- [x] Cluster-wide rate limits and greylisting state
- [x] Shared connection caching per destination across nodes
- [x] Per-tenant isolation (multi-tenant hosting): separate limits, keys, IP pools
- [x] Outbound IP pool management and warm-up schedules

### Phase 14 — Hardening for 1.0

- [ ] External security audit
- [x] Fuzzing campaign on SMTP parser, MIME/header parser, DNS response handling, queue file reader (`test/fuzz/`, `mix fuzz`; also the SMTP handler and client, milters, policy servers, authentication backends, sendmail, generated messages, the admin API, config files, logs, the Postfix migration, and cluster sync)
- [ ] Long-running soak tests (weeks) with real traffic mirrors
- [ ] Performance benchmarks vs Postfix (throughput, latency, memory per connection)
- [ ] Complete documentation: admin guide, config reference, migration guide, security guide
- [ ] Stable config format and queue format with documented upgrade path
- [ ] Interop test matrix against Postfix, Exim, Microsoft Exchange/365, Gmail, Stalwart, OpenSMTPD

### Phase 15 — Modular Stack (groundwork for 2.0)

- [x] `[stack]` switches for the three parts, `mta`, `filter`, and `mailbox`, all on by default; a part that is off starts nothing and opens no port
- [x] Table ownership: each table belongs to one part (or is shared), and only that part's table modules use it; checked like the component boundaries
- [ ] Internal interfaces between parts (MTA → filter: scan; MTA → mailbox: deliver, quota, user lookup; mailbox → MTA: submit), in-process when parts share a node, over the cluster's mutual TLS when they do not. Done: MTA → mailbox deliver and the user directory (`Sovite.Core.Stack.Mailbox`). With the filter and the mailbox store: scan (2.0), quota and submit (3.0)
- [x] Fallbacks when a part is off: the MTA uses milters (Rspamd) instead of the filter, and LMTP and the Dovecot auth protocol instead of the mailbox part
- [x] Node roles in a cluster: which parts each node runs (for example MTA-only edge nodes, filter nodes, mailbox nodes)
- [x] Shared identity: one user directory (database, LDAP, or OAuth) for every part, owned by the mailbox part, used by the others only through the internal interface
- [x] `sovitectl` and the web UI show and manage only the parts that are on
- [x] Repository layout and boundary checks for the parts: the MTA in `lib/core/mta/` (`Sovite.Core.MTA.*`), the new parts in `lib/core/filter/` and `lib/core/mailbox/`, shared code (config, database, cluster, CLI and web UI shells) in `lib/core/`, reusable components in `lib/<component>/`

**Done when:** each part can be turned off without the others breaking, the MTA runs with external Rspamd and Dovecot in their place, and no part uses another part's tables except through its interface.

### Phase 16 — Filter Engine Core

- [x] Message analyzer: MIME tree with nesting, part-count, and size limits; charset decoding; HTML to text with a bounded, safe parser; URL and email extraction (text, HTML, redirects, obfuscation); attachment metadata and file types by content (magic numbers), not by name
- [x] Rule engine: symbols with scores and groups, regular expression rules on headers, body, MIME parts, and URLs (with a safe regex engine and time limits), composites, conditions, maps (lists of IPs, domains, addresses, hashes) reloaded without restart
- [x] Actions: reject, soft reject (`451`), greylist, add header, rewrite subject, quarantine, no action; thresholds per tenant and per user
- [x] Existing checks as symbols: SPF, DKIM, DMARC, ARC, DNSBL/DNSWL/RHSBL, reverse DNS, greylisting, rate limits, sender and recipient rules
- [ ] Header checks: missing or malformed `Date:`, `Message-ID:`, `From:`; forged `Received:` chains; mismatched display names; suspicious `Reply-To:`
- [ ] Scanning in the MTA's SMTP session (before `250`) and for outbound mail of authenticated users
- [ ] `X-Spam-*` and `Authentication-Results`-style result headers; per-symbol explanations in the message trace
- [ ] Rspamd-compatible HTTP protocol (`/checkv2`, `/symbols`, `/ping`) and a milter server mode, so other MTAs (Postfix, Exim) can use the filter
- [ ] Default rule set equivalent to Rspamd's common modules

**Done when:** the filter scores a reference corpus close to Rspamd with its default configuration, and Postfix can use it in place of Rspamd.

### Phase 17 — Statistics & Reputation

- [ ] Bayesian classifier (OSB tokenization, as Rspamd and CRM114): global, per-tenant, and per-user statistics; token storage in Sovite's database, in the filter part's tables, with expiry
- [ ] Learning: `sovitectl filter learn spam|ham`, the web UI, autolearning by score, and from users moving mail to and from Junk (with the mailbox part, Phase 23)
- [ ] Fuzzy hashes: shingles of text and images, hashes of attachments; fuzzy storage shared by the cluster; compatible import of public fuzzy feeds
- [ ] Reputation: IP, ASN, domain, URL, DKIM domain, and sender reputation from local history, with decay; shared by the cluster
- [ ] URIBL/SURBL/DBL lookups (Spamhaus DBL, SURBL, URIBL), with the RFC 5782 conventions and result caching
- [ ] Phishing checks: link text versus target, look-alike domains (IDN homographs, typosquatting), known phishing feeds (OpenPhish, PhishTank)
- [ ] Replies and known correspondents: lower scores for replies to mail the user sent (as Rspamd's `replies` module)
- [ ] Neural scoring (optional): a small model trained on the local corpus, as Rspamd's `neural` module

**Done when:** after training on a corpus, spam detection and false positives are at least on par with Rspamd with the same training data.

### Phase 18 — Content Protection

- [ ] Antivirus: clamd protocol (ClamAV) client, ICAP client, and results as symbols and actions
- [ ] Attachment policies: blocked and allowed types by content, archives inspected (zip, rar, 7z, tar, gzip) with depth and size limits, encrypted archives flagged, Office macros and PDF JavaScript detected
- [ ] Outbound protection: scanning of authenticated users' mail, combined with the MTA's suspension of compromised accounts
- [ ] Quarantine: messages held by the filter, released or deleted from the web UI and `sovitectl`, with notifications to recipients (optional)
- [ ] Feedback loops: Abuse Reporting Format (ARF, RFC 5965) reports received and sent, mailbox provider FBL processing

**Done when:** malware test files (EICAR and real samples in a sandbox) are caught in every supported container, and quarantined mail can be reviewed and released.

### Phase 19 — Filter Operations & Hardening for 2.0

- [ ] Web UI: scan history with symbols, learning, maps and rules editor, thresholds per tenant, quarantine, statistics
- [ ] `sovitectl filter scan|learn|stats|maps`
- [ ] Metrics and traces for every scan: duration per check, symbol hits, actions
- [ ] Rspamd configuration migration (`sovitectl migrate rspamd`): actions, scores, maps, settings, and statistics import (Bayes tokens, fuzzy hashes where possible)
- [ ] Corpus testing tools: replay a mailbox through the filter and compare with Rspamd
- [ ] Fuzzing of the MIME, HTML, URL, and archive parsers; external security audit of the filter
- [ ] Benchmarks against Rspamd: messages per second, latency, memory

**Done when:** an Rspamd installation can be migrated, and the filter has been audited, fuzzed, and benchmarked.

### Phase 20 — Mail Store (groundwork for 3.0)

- [ ] Storage engine: one file per message (Maildir-compatible layout) plus indexes and caches per mailbox, `fsync` discipline as strict as the queue's, crash recovery
- [ ] Mailbox metadata in the mailbox part's tables: mailboxes, UIDs, `UIDVALIDITY`, flags, keywords, `MODSEQ`, sizes
- [ ] Quotas per user, per domain, and per tenant (storage and message count), checked by the MTA at `RCPT` time
- [ ] Delivery from the MTA part in-process (no LMTP hop), with the LMTP server kept for other MTAs
- [ ] Optional encryption at rest per user (keys derived from the user's password, as Dovecot's `mail_crypt`)
- [ ] Deduplication of identical attachments (single-instance storage), optional
- [ ] Import from Maildir, mbox, and Dovecot mdbox; export to Maildir
- [ ] Expunge, retention, and trash policies; per-user backups

**Done when:** mail delivered by the MTA is stored durably, survives crashes and `kill -9` at any point, and can be imported from and exported to Dovecot.

### Phase 21 — IMAP Server

- [ ] IMAP4rev2 (RFC 9051) and IMAP4rev1 (RFC 3501) for older clients, with strict, bounded parsing of commands and literals
- [ ] TLS: STARTTLS and implicit TLS on port 993 (RFC 8314), with the MTA's certificate store and ACME
- [ ] Authentication with the shared SASL mechanisms, app passwords, and OAUTHBEARER; failed-login bans shared with SMTP
- [ ] Core extensions: IDLE, NAMESPACE, UIDPLUS, LITERAL+/LITERAL-, MOVE, SPECIAL-USE, ENABLE, ID, UNSELECT, CHILDREN, LIST-EXTENDED, LIST-STATUS, ESEARCH, SEARCHRES, SORT, THREAD, BINARY, APPENDLIMIT, COMPRESS=DEFLATE, UTF8=ACCEPT
- [ ] Mailbox hierarchy, subscriptions, and special-use mailboxes (Sent, Drafts, Junk, Trash, Archive) created automatically
- [ ] Interoperability with Thunderbird, Apple Mail (macOS and iOS), Outlook, Gmail's mobile app, K-9/Thunderbird for Android, mutt, and aerc

**Done when:** the client matrix can read, search, move, and send mail through Sovite alone, and an IMAP compliance test suite (such as imaptest) passes.

### Phase 22 — IMAP Synchronization & Search

- [ ] CONDSTORE and QRESYNC (RFC 7162) for fast resynchronization
- [ ] NOTIFY (RFC 5465), OBJECTID (RFC 8474), SAVEDATE (RFC 8514), STATUS=SIZE (RFC 8438), PREVIEW (RFC 8970)
- [ ] Full-text search with a built-in index (headers, bodies, and text from attachments), SEARCH=FUZZY (RFC 6203)
- [ ] METADATA (RFC 5464) and ACL (RFC 4314) for shared mailboxes and shared folders between users of a tenant
- [ ] QUOTA (RFC 9208)
- [ ] Performance: large mailboxes (a million messages), many concurrent clients, index caching

**Done when:** clients resynchronize large mailboxes in under a second after reconnecting, and search is fast enough for mailboxes of years of mail.

### Phase 23 — Sieve & Filtering for Users

- [ ] Sieve (RFC 5228) with extensions: fileinto, envelope, reject and ereject (RFC 5429), vacation (RFC 5230) and vacation-seconds (RFC 6131), relational (RFC 5231), subaddress (RFC 5233), body (RFC 5173), variables (RFC 5229), imap4flags (RFC 5232), date (RFC 5260), editheader (RFC 5293), mailbox (RFC 5490), duplicate (RFC 7352), include (RFC 6609), spamtest and virustest (RFC 5235) fed by the filter part
- [ ] ManageSieve (RFC 5804)
- [ ] IMAP Sieve (RFC 6785): moving mail to and from Junk teaches the filter part
- [ ] Global, per-tenant, and per-user scripts, with execution limits
- [ ] Vacation replies with the MTA's loop protection (RFC 3834)

**Done when:** users manage their filters from Thunderbird or Roundcube, and Junk folder moves train the classifier.

### Phase 24 — POP3 & Client Setup

- [ ] POP3 (RFC 1939) with CAPA (RFC 2449), STLS, SASL (RFC 5034), UIDL, and implicit TLS on port 995
- [ ] Automatic client setup: Thunderbird autoconfig, Outlook Autodiscover, Apple configuration profiles, DNS SRV records (RFC 6186, RFC 8314), served by the web server and printed by `sovitectl dns records`
- [ ] User self-service in the web UI: password, app passwords, two-factor authentication for the web, Sieve rules and vacation replies, quota usage, quarantine
- [ ] Submission referencing IMAP (BURL, RFC 4468), optional

**Done when:** a user can set up a client by entering only their address and password, and manage their own account in the web UI.

### Phase 25 — Mailbox Clustering & Hardening for 3.0

- [ ] Mailbox replication between cluster nodes (as Dovecot's `dsync` replication), with conflict resolution by UID and `MODSEQ`
- [ ] User placement: each user's mailbox has a home node; IMAP, POP3, and LMTP connections to any node are proxied to it (as Dovecot's director)
- [ ] Moving users between nodes without downtime; rebalancing
- [ ] Backups and point-in-time restore of mailboxes
- [ ] Dovecot migration (`sovitectl migrate dovecot`): configuration, users, passwords, Sieve scripts, and mailboxes (through IMAP or directly from Maildir/mdbox)
- [ ] Fuzzing of the IMAP, POP3, ManageSieve, and Sieve parsers; external security audit of the mailbox part
- [ ] Benchmarks against Dovecot: concurrent connections, memory per connection, search and synchronization times
- [ ] JMAP (RFC 8620, RFC 8621): evaluated for a later release

**Done when:** a Dovecot installation can be migrated without data loss, a mailbox node can fail without users losing access, and the mailbox part has been audited, fuzzed, and benchmarked.

---

## 4. Standards Compliance Matrix

**Level:** MUST = required for the release its phase belongs to (1.0 for Phases 1–14, 1.x for Phase 15, 2.0 for Phases 16–19, 3.0 for Phases 20–25), SHOULD = planned for that release, MAY = optional / later.

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

### Filtering (2.0)

| Standard / Spec | Title | Level | Phase |
|---|---|---|---|
| RFC 2045–2049 | MIME (analysis of every part) | MUST | 16 |
| RFC 2231 | MIME parameter encoding | MUST | 16 |
| RFC 3986 | URI syntax (URL extraction) | MUST | 16 |
| Rspamd HTTP protocol | `/checkv2` scanning API, for other MTAs | SHOULD | 16 |
| Sendmail Milter protocol v6 (server side) | Filter for Postfix and other MTAs | SHOULD | 16 |
| RFC 5782 | DNS lists for URLs (URIBL/SURBL/DBL) | MUST | 17 |
| clamd protocol | Antivirus scanning (ClamAV) | SHOULD | 18 |
| RFC 3507 | ICAP | MAY | 18 |
| RFC 5965 / RFC 6650 | Abuse Reporting Format and its use | SHOULD | 18 |

### Mailbox Access (3.0)

| Standard | Title | Level | Phase |
|---|---|---|---|
| RFC 9051 | IMAP4rev2 | MUST | 21 |
| RFC 3501 | IMAP4rev1 (older clients) | MUST | 21 |
| RFC 8314 | Implicit TLS for mail access | MUST | 21 |
| RFC 2177 | IDLE | MUST | 21 |
| RFC 2342 | NAMESPACE | MUST | 21 |
| RFC 4315 | UIDPLUS | MUST | 21 |
| RFC 7888 | LITERAL+ / LITERAL- | MUST | 21 |
| RFC 6851 | MOVE | MUST | 21 |
| RFC 6154 | SPECIAL-USE | MUST | 21 |
| RFC 5161 | ENABLE | MUST | 21 |
| RFC 2971 | ID | SHOULD | 21 |
| RFC 3691 | UNSELECT | SHOULD | 21 |
| RFC 5258 / RFC 5819 | LIST-EXTENDED / LIST-STATUS | SHOULD | 21 |
| RFC 4731 / RFC 5182 | ESEARCH / SEARCHRES | SHOULD | 21 |
| RFC 5256 | SORT and THREAD | SHOULD | 21 |
| RFC 3516 | BINARY | SHOULD | 21 |
| RFC 7889 | APPENDLIMIT | SHOULD | 21 |
| RFC 4978 | COMPRESS=DEFLATE | SHOULD | 21 |
| RFC 6855 | UTF8=ACCEPT | SHOULD | 21 |
| RFC 7162 | CONDSTORE and QRESYNC | MUST | 22 |
| RFC 5465 | NOTIFY | SHOULD | 22 |
| RFC 8474 | OBJECTID | SHOULD | 22 |
| RFC 8514 / RFC 8438 / RFC 8970 | SAVEDATE / STATUS=SIZE / PREVIEW | MAY | 22 |
| RFC 6203 | SEARCH=FUZZY | SHOULD | 22 |
| RFC 5464 | METADATA | SHOULD | 22 |
| RFC 4314 | ACL | SHOULD | 22 |
| RFC 9208 | QUOTA | MUST | 22 |
| RFC 5228 | Sieve | MUST | 23 |
| RFC 5230 / RFC 6131 | Vacation / vacation-seconds | MUST | 23 |
| RFC 5229 / RFC 5231 / RFC 5232 / RFC 5233 | Variables, relational, imap4flags, subaddress | SHOULD | 23 |
| RFC 5173 / RFC 5260 / RFC 5293 / RFC 5429 | Body, date, editheader, reject | SHOULD | 23 |
| RFC 5490 / RFC 7352 / RFC 6609 / RFC 5235 | Mailbox, duplicate, include, spamtest | SHOULD | 23 |
| RFC 5804 | ManageSieve | MUST | 23 |
| RFC 6785 | IMAP Sieve | SHOULD | 23 |
| RFC 1939 | POP3 | MUST | 24 |
| RFC 2449 | POP3 extensions (CAPA) | MUST | 24 |
| RFC 5034 | POP3 SASL | MUST | 24 |
| RFC 6186 | SRV records for mail clients | SHOULD | 24 |
| RFC 4468 | BURL | MAY | 24 |
| RFC 8620 / RFC 8621 | JMAP / JMAP for Mail | MAY | 25 |

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
- **Interop tests** in CI using containers: Postfix, Exim, OpenSMTPD, Dovecot, Rspamd; for the filter, the same corpus through Rspamd and Sovite; for the mailbox part, imaptest and the client matrix.
- **Chaos tests**: kill nodes and processes during delivery; corrupt queue files; DNS timeouts and SERVFAIL.
- **Load tests**: sustained throughput, connection storms, large messages, many recipients.
- **Fuzzing** of all network-facing parsers, and of every parser of message content (MIME, HTML, archives, Sieve scripts).
- **Part isolation tests**: each combination of parts on and off; boundary checks that no part uses another part's tables or internals.

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
| **1.0 — "Production ready"** | 14 | Audited, benchmarked, documented, stable formats: a Postfix replacement |
| **1.x — "It's modular"** | 15 | Parts that turn on and off, clear part boundaries, node roles |
| **2.0 — "It replaces Rspamd"** | 16, 17, 18, 19 | Built-in spam, phishing, and malware filtering, usable by other MTAs too |
| **3.0 — "It replaces Dovecot"** | 20, 21, 22, 23, 24, 25 | Mail storage, IMAP, POP3, Sieve, replication: the whole stack |
