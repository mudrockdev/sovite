# Sovite Structure

Every part of the codebase can be used as a library for other projects. The codebase is structured in a way that allows for modularity and reusability. Each module or component can be imported and utilized independently, making it easy to integrate into different applications or systems.

---

## 1. Layout

```
lib/
  sovite.ex          # Base application: starts the full MTA
  core/              # Sovite-only parts (the MTA itself)
  <component>/       # Reusable components, one folder each
```

| Location | Purpose | Reusable? |
|---|---|---|
| `lib/sovite.ex` | Application entry point. Starts the MTA supervision tree from `core/`. | No |
| `lib/core/` | Everything that only makes sense inside the Sovite MTA: config file, wiring, orchestration, CLI. | No |
| `lib/<component>/` | Self-contained building blocks (SMTP, DKIM, SPF, ...) usable by any Elixir project. | Yes |

---

## 2. Reusable Components

Each folder maps to one namespace: `lib/<component>/` → `Sovite.<Component>`.
Everything lives under `Sovite.*` to avoid module name clashes in projects that depend on Sovite.

### Layer 0: Primitives (pure, no processes, no I/O)

| Folder | Namespace | Contents |
|---|---|---|
| `validators/` | `Sovite.Validators` | Syntax checks for addresses (RFC 5321/5322), domains, hostnames, IP literals, HELO names |
| `net/` | `Sovite.Net` | IP address and CIDR network parsing and matching |

### Layer 1: Formats & Infrastructure

| Folder | Namespace | Contents |
|---|---|---|
| `message/` | `Sovite.Message` | RFC 5322 header parsing/folding, address lists (rewriting addresses in `From:`/`To:`/...), MIME, `Received:` / `Date:` / `Message-ID:` builders, trace fields (`Return-Path:`, `Delivered-To:`, hop counting), streaming body handling |
| `dns/` | `Sovite.DNS` | Resolver behaviour, default resolver, cache, MX / TXT / TLSA helpers, Null MX |
| `ldap/` | `Sovite.LDAP` | LDAP connections (StartTLS/LDAPS), bind, search, RFC 4515 filters with injection-safe placeholders, DN escaping |
| `sasl/` | `Sovite.SASL` | PLAIN, LOGIN, SCRAM-SHA-256, OAUTHBEARER (both server and client side) |
| `proxy_protocol/` | `Sovite.ProxyProtocol` | HAProxy PROXY v1/v2 parser |
| `maildir/` | `Sovite.Maildir` | Crash-safe Maildir delivery (`tmp/` then `new/`) |
| `pipe/` | `Sovite.Pipe` | Run an external command with a file on standard input: no shell, clean environment, timeout, output limit |

### Layer 2: Protocols & Mail Authentication

| Folder | Namespace | Contents |
|---|---|---|
| `smtp/` | `Sovite.SMTP` | Command/reply codec, enhanced status codes, server session state machine, client state machine, LMTP (client over TCP and Unix sockets, and server mode), extensions |
| `dsn/` | `Sovite.DSN` | Build and parse delivery status notifications (RFC 3464 / 6522) |
| `spf/` | `Sovite.SPF` | SPF evaluation (RFC 7208) |
| `dkim/` | `Sovite.DKIM` | DKIM signing and verification (RFC 6376, 8301, 8463) |
| `dmarc/` | `Sovite.DMARC` | DMARC record parsing, alignment, policy evaluation, aggregate reports |
| `arc/` | `Sovite.ARC` | ARC verification and sealing (RFC 8617) |
| `auth_results/` | `Sovite.AuthResults` | `Authentication-Results:` header build/parse (RFC 8601) |
| `srs/` | `Sovite.SRS` | Sender Rewriting Scheme (SRS0/SRS1) addresses for forwarded mail |
| `tls/` | `Sovite.TLS` | Certificate store with SNI, ACME, DANE verification, MTA-STS policies (discovery, fetch, MX matching, a policy server), TLS-RPT reports |
| `milter/` | `Sovite.Milter` | Milter protocol client |
| `policy/` | `Sovite.Policy` | Postfix policy delegation protocol (client **and** server, so policy servers can be written in Elixir) |
| `abuse/` | `Sovite.Abuse` | DNSBL/RHSBL scoring, greylisting, rate limiting, pre-greet detection |
| `queue/` | `Sovite.Queue` | Durable mail spool with storage behaviour, crash recovery, retry scheduler |
| `listener/` | `Sovite.Listener` | TCP/TLS listener with connection limits and PROXY protocol support |

### Layer 3: Sovite Only

| Folder | Namespace | Contents |
|---|---|---|
| `core/` | `Sovite.Core` | Config file schema/loading/reload, supervision tree, database (Ecto repo, migrations, schemas), routing (domain classes, aliases, address rewriting, transports, next-hop selection), restriction chains, submission fixes, delivery orchestration (per-destination concurrency; SMTP, LMTP, Maildir, and pipe transports), email authentication of received and sent mail (SPF, DKIM, ARC, DMARC, SRS) and DMARC reports, transport security policies (DANE, MTA-STS cache, REQUIRETLS) and TLS-RPT reports, bounce service, CLI (`sovitectl`), `sendmail` compatibility, Postfix config migration |

New components are added as new folders, placed in the lowest layer their dependencies allow.

### Inside `core/`

```
lib/core/
  repo.ex            # Sovite.Core.Repo: picks the adapter, migrates at startup
  repo/
    migrations/      # one migration module per table (Sovite.Core.Repo.Migrations.*)
    schemas/         # one typed Ecto schema per table (Sovite.Core.Repo.Schemas.*)
    tables/          # one module per table that reads and writes it (Sovite.Core.Repo.Tables.*)
    data.ex          # helpers shared by the table modules
  config/            # config schema and cross-key checks
  cli/               # sovitectl commands
  delivery.ex        # Sovite.Core.Delivery: runs one job, SMTP here
  delivery/          # LMTP, local (Maildir and pipe), TLS policies, and the shared transaction/result code
  mail_auth.ex       # Sovite.Core.MailAuth: SPF/DKIM/ARC/DMARC checks, signing, sealing
  dmarc_reports.ex   # Sovite.Core.DMARCReports: aggregate report sender
  mta_sts.ex         # Sovite.Core.MTASTS: MTA-STS policies of recipient domains, cached
  tls_reports.ex     # Sovite.Core.TLSReports: TLS-RPT report sender
  ...                # routing, rewriting, restrictions, queue manager
```

Every database table has its own migration, schema, and table module. Code outside `core/repo/`, including `sovitectl`, reaches the database only through the table modules (see `AGENTS.md`).

---

## 3. Dependency Rules

1. **Dependencies only point downward.** A component may depend on components in the same or lower layers, never higher.
2. **Reusable components never depend on `core/` or `sovite.ex`.** If a reusable component needs something from `core/`, that something is either moved into a reusable component or injected via a behaviour/option.
3. **No dependency cycles** between components, even within the same layer.
4. **Enforced in CI** with `mix xref graph --format cycles` and a check that no reusable folder references `Sovite.Core`. The `boundary` library can make these compile-time errors.

---

## 4. Rules for Reusable Components

These rules are what make a component usable by other projects.

### Configuration
- No `Application.get_env/2` inside reusable components. All configuration is passed explicitly as function arguments or `start_link` options.
- Options are validated and documented (NimbleOptions-style schemas).

### Processes
- Reusable components **never start processes on their own**. Stateful components expose a `child_spec/1` so the caller places them in **their own** supervision tree.
- Every process accepts a `:name` option. No hard-coded global names, so several instances can run in the same VM (multiple servers, tests running concurrently, multi-tenant setups).
- Prefer pure functions; keep processes at the edges. Example: the SMTP session is a pure state machine (`command + state → replies + new state + actions`); the socket process around it is a thin shell.

### Extension Points
- Anything environment-specific is a **behaviour** with a default implementation:
  - DNS resolver
  - Queue storage
  - Lookup table backend
  - SASL credential backend
  - SMTP server handler (callbacks for connect, HELO, MAIL, RCPT, DATA). This lets an app embed an SMTP receiver without the Sovite queue.
  - Delivery transport
- Tests use the same behaviours (fakes via Mox).

### Observability
- Reusable components emit `:telemetry` events (`[:sovite, <component>, ...]`) instead of writing logs. The host application decides what to log.
- Pure layers (0 and most of 1) don't log at all.

### API Style
- Return `{:ok, value}` / `{:error, reason}`, with `!` variants where useful. Error reasons are documented structs or atoms, never raw strings.
- Message bodies are handled as streams / iodata, never required to be fully in memory.
- Never create atoms from untrusted input.
- Public modules have `@moduledoc` and `@doc`; internal modules are marked `@moduledoc false` and are not covered by semver.

### Dependencies
- Keep required dependencies minimal.
- Heavy or backend-specific dependencies (PostgreSQL, MySQL, etc.) are declared `optional: true`; the modules that need them are only compiled when the dependency is present.

---

## 5. Base Application (`lib/sovite.ex`)

- `lib/sovite.ex` is the application entry point and starts the MTA tree from `core/`.
- When Sovite is used **as a library dependency**, the full MTA must not start automatically. The MTA only starts when explicitly enabled (for example by the release's runtime config); otherwise the application starts nothing and the reusable components are used directly.
- The MTA can also be embedded: the `core/` supervisor exposes a `child_spec/1` so another application can run Sovite inside its own supervision tree.

---

## 6. Tests

Tests mirror the source layout:

```
test/
  core/
  <component>/
  support/          # fake DNS, fake remote MTA, SMTP test client
```

- Each reusable component is tested in isolation, with no dependency on `core/`.
- `core/` tests cover wiring and end-to-end mail flow.

---

## 7. Packaging

- Published as a single Hex package: `sovite`.
- Each component folder is kept self-contained so it could later be extracted into its own package (e.g. `sovite_dkim`) without breaking its public API.
- Docs (ExDoc) group modules by component, using `groups_for_modules` that match the folder layout.
