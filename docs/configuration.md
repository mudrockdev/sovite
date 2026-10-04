# Configuration

Sovite reads one TOML file:

- `$SOVITE_CONFIG`, if set
- otherwise `/etc/sovite/sovite.toml`

Validate a file without starting the MTA:

```sh
sovitectl config check                 # default path
sovitectl config check ./sovite.toml   # explicit path
```

The command exits with `0` if the file is valid. Otherwise it prints every problem with the path of the bad key and exits with `1`:

```
./sovite.toml: queue.directory: "spool" is not an absolute path
./sovite.toml: log.level: expected one of "debug", "info", "notice", "warning", "error", got "loud"
```

The MTA runs the same validation at startup and will not start with an invalid file. Unknown keys are errors, so typos are caught instead of being silently ignored.

Every setting is optional. A release ships a commented example at `etc/sovite.toml.example`.

---

## `[server]`

| Key | Type | Default | Description |
|---|---|---|---|
| `hostname` | hostname | system hostname | Fully qualified name used in the SMTP greeting, `EHLO`, and `Received:` headers. Set it explicitly: the system hostname is often not fully qualified. |

## `[database]`

Sovite keeps its own data (login users and the addresses they may send as) in a database, managed with Ecto. The schema is created and upgraded automatically at startup.

| Key | Type | Default | Description |
|---|---|---|---|
| `adapter` | `sqlite` \| `postgres` \| `mysql` | `sqlite` | SQLite needs no server: the database is one file. Use PostgreSQL or MySQL to share users between several Sovite servers. |
| `path` | absolute path | `/var/lib/sovite/sovite.db` | The SQLite file. Its directory is created if missing; the file gets mode `0600`. |
| `url` | URL | unset | For `postgres` and `mysql`, required: `postgres://user:password@host/database` or `mysql://user:password@host/database`. |
| `pool_size` | integer | `5` | Database connections. |
| `ssl` | boolean | `false` | For `postgres` and `mysql`: connect with TLS, verifying the server's certificate against the system CAs. |

Sovite releases include the drivers for all three. (When Sovite is used as a library, `postgrex` and `myxql` are optional dependencies; `sovitectl config check` says so if one is missing.)

## `[queue]`

| Key | Type | Default | Description |
|---|---|---|---|
| `directory` | absolute path | `/var/spool/sovite` | Spool directory, created with mode `0700` if missing. Must be owned by the Sovite user. See [the queue](#the-queue) below. |
| `max_lifetime` | duration | `5d` | How long to keep trying a message. Recipients still not delivered after this are bounced (RFC 5321 §4.5.4.1 asks for at least 4–5 days). |
| `min_backoff` | duration | `5m` | Wait after the first failed attempt. The wait doubles after each attempt, with ±10% jitter. |
| `max_backoff` | duration | `1h` | Longest wait between attempts. Must not be less than `min_backoff`. |
| `delay_warning` | duration | unset | Tell the sender once when a message is still not delivered after this long, for example `"4h"`. Unset: no delay warnings. |

### The queue

Each message is one file in one of these directories:

| Directory | Contents |
|---|---|
| `incoming/` | Accepted, not yet picked up for delivery. |
| `active/` | Being delivered. |
| `deferred/` | Waiting for the next attempt. |
| `hold/` | Held: not delivered until moved back to `incoming/`. |
| `corrupt/` | Failed the checksum or could not be read. Kept for inspection, never delivered. |
| `tmp/` | Being received. Cleaned at startup. |

Delivery results are appended to the message's file and `fsync`ed as they come in. If Sovite stops for any reason, even `kill -9` or a power failure, messages in `active/` go back to `incoming/` at startup and only the recipients without a recorded result are tried again. A recipient whose delivery was in progress may receive the message twice, which SMTP allows; a message is never lost.

## `[[listener]]`

An array of tables: one per address and port to accept mail on. Without any `[[listener]]` table, Sovite listens on `0.0.0.0:25`. Write `listener = []` (before the first table) to listen nowhere.

```toml
[[listener]]            # MX: mail from the Internet
address = "0.0.0.0"
port = 25

[[listener]]            # mail clients, STARTTLS (RFC 6409)
address = "0.0.0.0"
mode = "submission"

[[listener]]            # mail clients, implicit TLS (RFC 8314)
address = "0.0.0.0"
mode = "submissions"
```

| Key | Type | Default | Description |
|---|---|---|---|
| `address` | IP address | `0.0.0.0` | Address to bind. IPv6 listeners are IPv6-only, so add both `0.0.0.0` and `::` for dual stack. |
| `mode` | `smtp` \| `submission` \| `submissions` | `smtp` | What the listener is for, which sets the defaults below. |
| `port` | integer | `25` / `587` / `465` | TCP port, by mode. Ports below 1024 need `CAP_NET_BIND_SERVICE` or socket activation, see [Security](security.md). |
| `auth` | boolean | `false` / `true` / `true` | Offer `AUTH`. It is only offered over TLS, unless `auth.plaintext` is set. |
| `require_tls` | boolean | `false` / `true` / `true` | Refuse `MAIL`, `RCPT`, `DATA`, `VRFY`, and `AUTH` with `530 5.7.0` until the client has sent `STARTTLS`. Do not set it on port 25: senders on the Internet may not support TLS. |
| `require_auth` | boolean | `false` / `true` / `true` | Refuse `MAIL` with `530 5.7.0` until the client has authenticated. Needs `auth = true`. |
| `tls_min_version` | `"1.2"` \| `"1.3"` | `tls.min_version` | Override for this listener. |
| `tls_ciphers` | array of cipher names | `tls.ciphers` | Override for this listener. |

`STARTTLS` is offered on `smtp` and `submission` listeners whenever a certificate is configured in [`[tls]`](#tls). A `submissions` listener starts TLS right after the connection opens, so it needs a certificate.

## `[tls]`

Certificates for `STARTTLS` and implicit TLS, and the TLS settings for all listeners. Only TLS 1.2 and 1.3 are enabled (RFC 8996), and only forward-secret AEAD cipher suites (BCP 195, RFC 9325): ECDHE with AES-GCM or ChaCha20-Poly1305. The server chooses the cipher, and renegotiation started by a client is refused.

```toml
[[tls.certificate]]
cert_file = "/etc/sovite/tls/mx.example.com.pem"   # certificate, then intermediates
key_file = "/etc/sovite/tls/mx.example.com.key"

[[tls.certificate]]                                 # another name, or an RSA twin of the one above
cert_file = "/etc/sovite/tls/mail.example.org.pem"
key_file = "/etc/sovite/tls/mail.example.org.key"
```

| Key | Type | Default | Description |
|---|---|---|---|
| `certificate` | array of tables | `[]` | Certificate chains and keys, PEM files: `cert_file` holds the certificate followed by its intermediates, `key_file` an unencrypted RSA, EC, or PKCS #8 key. Each key is checked against its certificate at startup. |
| `min_version` | `"1.2"` \| `"1.3"` | `"1.2"` | Lowest TLS version accepted. |
| `ciphers` | array of cipher names | see below | Cipher suites in order of preference, as OpenSSL (`ECDHE-RSA-AES128-GCM-SHA256`) or IANA (`TLS_AES_128_GCM_SHA256`) names. Suites without forward secrecy or AEAD are refused. |
| `reload_interval` | duration | `1m` | How often to check the certificate files. Changed files are loaded for new connections, without a restart; a file that fails to load keeps the previous certificate in use (the error is logged). |

The default cipher list is `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` (TLS 1.3), then `ECDHE-ECDSA-AES128-GCM-SHA256`, `ECDHE-RSA-AES128-GCM-SHA256`, `ECDHE-ECDSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES256-GCM-SHA384`, `ECDHE-ECDSA-CHACHA20-POLY1305`, `ECDHE-RSA-CHACHA20-POLY1305` (TLS 1.2). testssl.sh rates it A+ with a trusted certificate.

**Choosing a certificate (SNI).** A client that names the server it wants (SNI, RFC 6066) gets every certificate valid for that name; with both an RSA and an ECDSA certificate for a name, the client's preference decides. Wildcards match one label. Clients that send no name, or an unknown one, get the first certificate (and any other with exactly the same names).

### `[tls.acme]`

Get and renew a certificate automatically from an ACME CA (RFC 8555), Let's Encrypt by default, with HTTP-01 challenges.

```toml
[tls.acme]
enabled = true
domains = ["mx.example.com", "mail.example.com"]
email = "postmaster@example.com"
accept_terms = true
```

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | Use ACME. |
| `domains` | array of host names | `[]` | Names the certificate is for. Each must resolve to this server. |
| `email` | email address | unset | Contact for the CA account (expiry notices). |
| `accept_terms` | boolean | `false` | Must be `true`: you agree to the CA's terms of service. |
| `directory_url` | URL | Let's Encrypt | The CA's directory. For testing, Let's Encrypt staging is `https://acme-staging-v02.api.letsencrypt.org/directory`. |
| `storage` | absolute path | `/var/lib/sovite/acme` | Where the account key, certificate, and key are kept (mode `0700`). |
| `http_address` | IP address | `0.0.0.0` | Address for the HTTP challenge listener. |
| `http_port` | integer | `80` | The CA connects to port 80; change it only behind a port redirect. The listener only runs while a certificate is being ordered. |
| `renew_before` | duration | `30d` | Renew when the certificate expires within this time. Checked at startup and every 12 hours; failed attempts are retried hourly while the current certificate stays in use. |

The ACME certificate is used like the files in `[[tls.certificate]]`, after them; with no other certificate it is the default.

## `[smtp]`

Settings for all listeners. Limits apply per listener.

| Key | Type | Default | Description |
|---|---|---|---|
| `max_message_size` | size | `25M` | Largest accepted message, advertised with `SIZE` and enforced while receiving (`552 5.3.4`). Bytes, or a number with `K`, `M`, or `G`. |
| `max_recipients` | integer | `100` | Recipients per message. Extra `RCPT` commands get `452 4.5.3`, and the client sends the message again for the rest. |
| `max_connections` | integer | `1000` | Concurrent connections. Extra connections get `421 4.7.0` and are closed. |
| `max_connections_per_ip` | integer | `20` | Concurrent connections from one client address. |
| `max_errors` | integer | `10` | Error replies before the session is closed with `421 4.7.0`. |
| `command_timeout` | duration | `5m` | How long to wait for the next command (RFC 5321 §4.5.3.2.7). A number of seconds, or a number with `ms`, `s`, `m`, `h`, or `d`. |
| `data_timeout` | duration | `5m` | How long to wait for more message data. |
| `bare_line_endings` | `reject` \| `normalize` | `reject` | What to do with a bare LF or CR (one not in a CRLF pair). `reject` closes the session with `521 5.5.2`; `normalize` turns it into CRLF. Either way only `<CRLF>.<CRLF>` ends a message, so SMTP smuggling is not possible. Use `normalize` only for old clients that send bare LF. |
| `vrfy` | boolean | `false` | Answer `VRFY` from `domains.local_recipients`. When off, `VRFY` gets `252`. |
| `trusted_networks` | array of networks | `[]` | Clients that may relay mail to any domain, such as your own servers. Addresses or CIDR networks: `["127.0.0.1", "192.0.2.0/24", "2001:db8::/32"]`. |

## `[domains]`

| Key | Type | Default | Description |
|---|---|---|---|
| `local` | array of domains | `[server.hostname]` | Domains this server is the final destination for. |
| `relay` | array of domains | `[]` | Domains accepted from anyone and forwarded elsewhere, for example as a backup MX. |
| `local_recipients` | array of addresses | unset | The only addresses that exist at local domains. Unknown ones get `550 5.1.1` at `RCPT` time. Unset: every address at a local domain is accepted. |

### Who may send what

Each recipient is checked when the client sends `RCPT TO`:

1. `postmaster` and `abuse` at a local domain, or a bare `<Postmaster>`, are always accepted (RFC 5321 §4.5.1, RFC 2142).
2. Local domain: accepted if `local_recipients` is unset or lists the address.
3. Relay domain: accepted.
4. Any other domain: accepted only from `trusted_networks` or after `AUTH`, otherwise `554 5.7.1 Relay access denied`.

Domains are compared case-insensitively, and only the domain of the parsed address counts: tricks like `user%other.example@local` or source routes never relay. The default config trusts no one, so a fresh install is never an open relay.

A message is accepted with `250 2.0.0 Ok: queued as <queue ID>` only after it is written and `fsync`ed in the queue directory.

## `[delivery]`

Outbound delivery over SMTP. Mail for `domains.local` is not delivered by this section: local delivery comes in a later release, and until then such mail is deferred.

| Key | Type | Default | Description |
|---|---|---|---|
| `relayhost` | relay host | unset | Send all outbound mail through this server (a "smart host"). `"host"` or `"host:port"` delivers to the MX hosts of `host`; `"[host]"`, `"[host]:port"`, `"[192.0.2.1]"`, or `"[2001:db8::1]:587"` delivers to that host directly. The port defaults to 25. Unset: deliver to each recipient domain's MX hosts. |
| `max_deliveries` | integer | `100` | Deliveries in progress at once. |
| `destination_concurrency` | integer | `20` | Deliveries in progress at once to one destination (a recipient domain, or the relay host). |
| `destination_rate_delay` | duration | unset | Wait this long between two deliveries to the same destination, for receivers that limit how fast they accept mail. |
| `max_recipients` | integer | `50` | Recipients per SMTP transaction. Messages with more recipients at one destination are sent in several transactions. |
| `max_addresses` | integer | `5` | Server addresses tried per delivery attempt, across all MX hosts. |
| `ip_versions` | array of `ipv6` \| `ipv4` | `["ipv6", "ipv4"]` | IP versions to deliver over, in order of preference. When an MX host has both, the first version is tried first and the other is the fallback. Use `["ipv4"]` on hosts without IPv6 connectivity. |
| `connect_timeout` | duration | `30s` | How long to wait for a TCP connection. The SMTP protocol timeouts are those of RFC 5321 §4.5.3.2 (5 minutes for most replies, 10 minutes after the message data). |
| `tls` | `none` \| `may` \| `encrypt` \| `verify` \| `dane` | `may` | TLS for outbound connections, see [Outbound TLS](#outbound-tls). |
| `tls_policy` | table | `{}` | Per-destination levels, overriding `tls`: `{ "example.com" = "verify", "[192.0.2.1]" = "encrypt" }`. Keys are recipient domains, the relay host's name, or address literals. |
| `tls_ca_file` | absolute path | system CAs | PEM file of CAs to trust for `verify`. |
| `relayhost_username` | string | unset | Log in to the relay host with SASL (`SCRAM-SHA-256`, `PLAIN`, or `LOGIN`, whichever it offers first). Credentials are only sent over TLS. |
| `relayhost_password` | string | unset | Password for `relayhost_username`. |

### How mail is delivered

For each recipient domain, Sovite looks up the MX records, tries the hosts from the best preference down (hosts with the same preference in random order), and each host's addresses in `ip_versions` order. A domain without MX records is its own mail host. A connection failure, a rejected greeting, or a connection lost before the message is sent moves on to the next address.

| Result | What happens |
|---|---|
| 2xx after the message | Delivered. |
| 4xx, no reachable host, DNS failure | Deferred and retried with backoff, until `queue.max_lifetime`. |
| 5xx | Bounced: the sender gets a delivery status notification. |
| Domain does not exist, or publishes a Null MX (RFC 7505) | Bounced without trying. |
| The best MX host, or the server answering, is this server | Bounced as a mail loop (`5.4.6`). |

Recipients at the same destination share a transaction, and other recipients of the same message are unaffected by one recipient's result. An idle connection is reused for the next message to the same destination.

### Outbound TLS

| Level | What happens |
|---|---|
| `none` | Never use TLS. |
| `may` | Opportunistic TLS (RFC 7435): `STARTTLS` when the server offers it, without checking its certificate. If the handshake fails, the address is tried again without TLS, so mail always gets through. |
| `encrypt` | TLS is required, but the certificate is not checked. Protects against passive eavesdropping only. |
| `verify` | TLS is required, and the certificate must be valid for the MX host (or relay host) name, from a trusted CA. MX names come from DNS, so without DNSSEC an attacker who can forge DNS answers can still redirect mail. |
| `dane` | DANE (RFC 7672): when an MX host has DNSSEC-validated TLSA records, TLS is required and the certificate must match them (DANE-EE or DANE-TA records); otherwise as `may`. A host whose TLSA lookup fails is skipped. **Needs a validating DNS resolver you trust**, normally one on the same host such as Unbound on `127.0.0.1` set in `/etc/resolv.conf`: Sovite relies on the resolver's AD flag. |

When TLS is required and cannot be used, that address is skipped (`4.7.4` not offered, `4.7.5` handshake or certificate failure) and the message is retried later. A relay host on port 465 is reached with implicit TLS. Delivery log lines show the TLS version and cipher (`tls=TLSv1.3 with cipher ...`).

## `[auth]`

SMTP authentication (`AUTH`, RFC 4954) for mail clients on listeners with `auth = true`. An authenticated client may relay to any domain, but only from the addresses its login maps to.

| Key | Type | Default | Description |
|---|---|---|---|
| `backend` | `database` \| `file` \| `ldap` \| `dovecot` | `database` | Where users and passwords come from, see below. |
| `mechanisms` | array of `SCRAM-SHA-256` \| `PLAIN` \| `LOGIN` \| `OAUTHBEARER` | by backend | SASL mechanisms to offer, in order. Default: `SCRAM-SHA-256`, `PLAIN`, `LOGIN` (only `PLAIN` and `LOGIN` for `ldap` and `dovecot`), plus `OAUTHBEARER` when `[auth.oauth]` is set. |
| `plaintext` | boolean | `false` | Also offer `AUTH` on unencrypted connections. Leave it off: with it, passwords cross the network in the clear. |
| `max_failures` | integer | `10` | Failed logins from one client address (one /64 for IPv6) within `failure_window` before it is banned. |
| `failure_window` | duration | `10m` | See `max_failures`. |
| `ban_time` | duration | `1h` | How long a ban lasts. A banned address gets `454 4.7.0` to `AUTH`, and `421` at connect on listeners with `require_auth`. Bans are kept in memory. |
| `failure_delay` | duration | `1s` | Wait before answering a failed login, to slow down guessing. After 3 failures in one session the connection is closed. |
| `sender_check` | boolean | `true` | Enforce sender login maps (below). |
| `senders` | table | `{}` | Extra sender addresses per login, see below. |

**Sender login maps.** An authenticated user may use as `MAIL FROM` their login (when it is an address), and any address matching a pattern listed for the login in `auth.senders` or added with `sovitectl user sender add`. A pattern is an address, `@domain` for every address at a domain, or `*` for any address. Anything else gets `553 5.7.1 Sender address rejected: not owned by user`. The null sender `<>` is always allowed.

```toml
[auth.senders]
"alice@example.com" = ["sales@example.com", "@example.org"]
"relay-bot" = ["*"]
```

**Messages from authenticated clients** are fixed up as RFC 6409 §8 allows: a missing `Date:` or `Message-ID:` is added, and the fields in `submission.strip_headers` are removed. Their `Received:` header uses `ESMTPSA` and shows the TLS version and cipher.

### `database` backend

Users are kept in the [database](#database). Passwords are stored as `SCRAM-SHA-256` hashes, so all three password mechanisms work. Manage them with `sovitectl`:

```sh
sovitectl user add alice@example.com            # asks for the password
sovitectl user passwd alice@example.com
sovitectl user disable alice@example.com        # or enable
sovitectl user sender add alice@example.com @example.org
sovitectl user sender remove alice@example.com @example.org
sovitectl user list
sovitectl user delete alice@example.com
```

User names are compared case-insensitively. The commands work whether or not the MTA is running.

### `file` backend: `[auth.file]`

| Key | Type | Default | Description |
|---|---|---|---|
| `file.path` | absolute path | unset | Users file, required. Re-read when it changes. |

One user per line, `name:hash`, compatible with Dovecot's `passwd-file` (more fields after the hash are ignored, `#` starts a comment). Make hashes with `sovitectl hash-password`, which reads the password from standard input. Supported hashes: `{SCRAM-SHA-256}...` (the default, works with every mechanism), `$6$...` / `{SHA512-CRYPT}` and `$5$...` / `{SHA256-CRYPT}` (only `PLAIN` and `LOGIN`), and `{PLAIN}password` (not recommended).

```
alice@example.com:{SCRAM-SHA-256}4096,dGhpc2lzc2FsdA==,...
bob@example.com:$6$rounds=5000$saltsalt$...
```

### `ldap` backend: `[auth.ldap]`

Checks passwords by binding to the directory as the user. Only `PLAIN` and `LOGIN` work.

| Key | Type | Default | Description |
|---|---|---|---|
| `ldap.servers` | array of host names | `[]` | Required. Tried in order. |
| `ldap.port` | integer | `389`, or `636` for `ldaps` | Server port. |
| `ldap.security` | `starttls` \| `ldaps` \| `none` | `starttls` | The server's certificate is verified against the system CAs. |
| `ldap.base` | string | unset | Search base, such as `ou=people,dc=example,dc=com`. |
| `ldap.filter` | LDAP filter | `(mail=%u)` | Finds the user's entry. `%u` is the login, `%n` the part before `@`, `%d` the part after. Values are inserted after the filter is parsed, so logins cannot inject filter syntax. |
| `ldap.dn_template` | string | unset | Bind as this DN directly instead of searching, such as `uid=%n,ou=people,dc=example,dc=com`. |
| `ldap.bind_dn` / `ldap.bind_password` | string | unset | Account for the search. Anonymous if unset. |
| `ldap.timeout` | duration | `10s` | For the whole check. |

An empty password is always refused, since LDAP treats it as an anonymous bind.

### `dovecot` backend: `[auth.dovecot]`

Hands authentication to Dovecot's auth service, like Postfix's `smtpd_sasl_type = dovecot`. Dovecot then decides which users exist and checks their credentials.

| Key | Type | Default | Description |
|---|---|---|---|
| `dovecot.socket` | string | unset | Required. Path of Dovecot's auth client socket, such as `/run/dovecot/auth-client`, or `host:port`. |
| `dovecot.timeout` | duration | `30s` | How long to wait for Dovecot. |

In Dovecot, give Sovite's user access to the socket:

```
service auth {
  unix_listener auth-client {
    mode = 0660
    user = sovite
  }
}
```

Set `auth.mechanisms` to what Dovecot offers if it is more than `PLAIN` and `LOGIN`.

### `[auth.oauth]`

`OAUTHBEARER` (RFC 7628): clients log in with an OAuth 2.0 access token from your identity provider, checked by token introspection (RFC 7662).

| Key | Type | Default | Description |
|---|---|---|---|
| `introspection_url` | URL | unset | The provider's introspection endpoint. |
| `client_id` / `client_secret` | string | unset | Credentials for the endpoint. |
| `username_claim` | string | `username` | Claim of the introspection response that holds the login, such as `email` or `preferred_username`. |
| `required_scope` | string | unset | A scope the token must have. |

## `[submission]`

| Key | Type | Default | Description |
|---|---|---|---|
| `strip_headers` | array of strings | `["Return-Path"]` | Header fields removed from messages of authenticated clients. Add `"X-Originating-IP"` and similar to hide client details. |

## `[bounce]`

Delivery status notifications (RFC 3464) are sent from `MAILER-DAEMON@<server.hostname>` with the null sender `<>`. They contain an explanation, a machine-readable report, and the headers of the original message (not its body).

| Key | Type | Default | Description |
|---|---|---|---|
| `double_bounce_recipient` | email address | unset | Where to report a notification, or any other message from the null sender, that could not be delivered. Unset: such double bounces are only logged. A failed double-bounce report is never reported again. |

## `[log]`

| Key | Type | Default | Description |
|---|---|---|---|
| `level` | `debug` \| `info` \| `notice` \| `warning` \| `error` | `info` | Minimum level written. |
| `format` | `text` \| `json` | `text` | `text` writes classic log lines; `json` writes one JSON object per line. See [Logging](logging.md). |
| `directory` | absolute path | unset | Write logs to rotating files in this directory, created if missing. Unset: log to standard output. The keys below only apply when this is set. |
| `file_name` | file name pattern | `sovite.{date}.{n}.log` | `{date}` is replaced with the date formatted with `date_format`; `{n}` with the file number, which starts at 1 and goes up with each rotation. `{n}` is required. |
| `date_format` | strftime format | `%Y-%m-%d` | Format of `{date}` ([`Calendar.strftime/2`](https://hexdocs.pm/elixir/Calendar.html#strftime/3)). Must not produce a `/`. |
| `max_size` | size | `100M` | Start a new file before the current one would grow past this size. A number of bytes, or a number with a `K`, `M`, or `G` suffix (1024-based), such as `512M` or `1G`. |
| `rotation` | `never` \| `hourly` \| `daily` \| `weekly` \| `monthly` | `daily` | Also start a new file when the hour, day, ISO week, or month changes. |
| `max_files` | integer | `14` | Number of log files to keep, including the current one. Older files matching `file_name` are deleted after each rotation. `0` keeps all. |
| `symlink` | file name | unset | Name of a symlink in `directory` that always points to the current file, for `tail -F`. |

---

## Starting the MTA

The `:sovite` OTP application starts the MTA only when the `:start_mta` application env is `true`:

- Production releases (`MIX_ENV=prod`) set it in `config/runtime.exs`.
- In development: `SOVITE_START_MTA=1 SOVITE_CONFIG=./sovite.toml iex -S mix`.
- When Sovite is a dependency of another project, the MTA never starts on its own. To embed it, add `{Sovite.Core.Supervisor, config_path: "..."}` to your supervision tree.
