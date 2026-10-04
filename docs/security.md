# Security Model

This document describes what Sovite defends against, the privileges it runs with, and the rules every component must follow. It is a living document; each roadmap phase extends it. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

---

## 1. Assets

| Asset | Why it matters |
|---|---|
| Queued mail | Confidential content. A `250 OK` is a promise to deliver it. |
| Relay permission | An open relay gets the host blocklisted and used for abuse. |
| Credentials | SMTP AUTH passwords and backend (SQL/LDAP) credentials. |
| Private keys | TLS keys and DKIM signing keys. A leaked DKIM key lets anyone forge the domain's mail. |
| Configuration and lookup tables | Decide who may relay and where mail goes. |
| Availability | Mail delayed by more than the queue lifetime is bounced. |

## 2. Threat Actors

| Actor | Capabilities |
|---|---|
| Remote unauthenticated client | Opens TCP connections to ports 25/465/587 and sends arbitrary bytes. This is the main attack surface. |
| Authenticated user | Valid credentials (possibly stolen); tries to relay, spoof senders, or exceed quotas. |
| Malicious remote server | Answers our outbound connections; sends hostile replies, TLS certificates, or DSNs. |
| DNS attacker | Spoofs or manipulates DNS answers (MX, TLSA, SPF, DKIM records). |
| Local unprivileged user | Shell on the host; uses `sendmail(1)` and may read world-readable files. |

Out of scope: an attacker with root, or with the Sovite user's privileges, on the host.

## 3. Privileges and Files

- Sovite runs as a dedicated unprivileged user (`sovite`), never as root.
- Ports below 1024 are bound with systemd socket activation or `CAP_NET_BIND_SERVICE`. The VM never needs root.
- The spool directory (`[queue] directory`) is owned by `sovite`, mode `0700`. Queue files are `0600`.
- The config file and lookup tables are owned by `root`, group `sovite`, mode `0640`. Sovite reads them but cannot modify them.
- TLS and DKIM private keys are owned by `root`, group `sovite`, mode `0640`.
- The `sendmail(1)` compatibility binary (Phase 9) submits mail over a local socket and is not setuid.

## 4. Rules for All Code

These apply to every component and are checked in code review.

1. **Never an open relay.** Relay requires an explicit grant: an authenticated user or a configured trusted network. The default config relays for no one.
2. **Durability before `250`.** A message is written and `fsync`ed (file and directory) before the reply is sent.
3. **Bounded parsing.** Everything parsed from the network has a hard limit: line length, command count, header count and size, recipients per message, message size, MIME nesting depth, DNS response size, SPF lookup count. Limits are checked while streaming, not after buffering.
4. **No atoms from untrusted input.** The BEAM atom table is never garbage-collected. Network input, DNS data, and config keys are mapped to atoms only through fixed tables, as the config loader does.
5. **SMTP smuggling.** Only `<CRLF>.<CRLF>` ends DATA. Bare LF and bare CR are rejected or normalized by an explicit policy, never interpreted inconsistently.
6. **STARTTLS injection.** Any plaintext buffered after the `STARTTLS` command is discarded once the handshake completes, on both server and client side.
7. **Secrets are never logged** (see [Logging](logging.md)) and never appear in crash reports. Processes holding secrets use `:sensitive` process flags or keep secrets out of their state.
8. **Credential checks are constant-time.** Password storage uses Argon2id, bcrypt, or salted SCRAM.
9. **Modern TLS only.** TLS 1.2 and 1.3 with BCP 195 (RFC 9325) cipher suites. Certificates are verified wherever the policy says so.
10. **Untrusted text is escaped in logs and headers.** Values from the network cannot inject log lines or header fields (CR/LF in `EHLO` names, addresses, and similar).
11. **Least data.** Message bodies are streamed, not held in memory, and are not copied into crash dumps or logs.

## 5. Defenses by Phase

| Threat | Defense | Phase |
|---|---|---|
| Open relay | Explicit relay permission, open-relay test in the definition of done | 1 |
| Resource exhaustion | Connection limits (global and per IP), timeouts, bounded parsing | 1 |
| SMTP smuggling | Strict end-of-data handling | 1 |
| Lost mail on crash | `fsync` before `250`, delivery results `fsync`ed before they count, crash recovery | 1–2 |
| Hostile remote servers | Bounded reply parsing (line length and count), timeouts on every wait, remote text sanitized before it goes into notifications or logs | 2 |
| Mail loops | Notifications sent from `<>` and never answered; double-bounce reports never reported again; MX hosts at or below this server's preference skipped; a server greeting with our own name treated as a loop | 2 |
| Credential theft in transit | AUTH only after TLS by default | 3 |
| Brute-force AUTH | Failure rate limits and temporary bans | 3 |
| Sender spoofing by authenticated users | Sender login maps | 3 |
| Downgrade and MITM on outbound TLS | DANE, MTA-STS | 7 |
| Spam and bot traffic | postscreen-style checks, DNSBL, rate limits | 8 |
| Compromised accounts | Outbound volume and bounce-rate detection | 8 |

## 6. Supply Chain

- Dependencies are kept minimal and pinned in `mix.lock`. CI fails on unused locked dependencies.
- Release builds are reproducible and release artifacts are signed (Phase 12).
