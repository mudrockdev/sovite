# Sovite Structure

Every part of the codebase can be used as a library for other projects. The codebase is structured in a way that allows for modularity and reusability. Each module or component can be imported and utilized independently, making it easy to integrate into different applications or systems.

---

## 1. Layout

```
lib/
  sovite.ex          # Base application: starts the stack
  core/              # Sovite-only code: what the parts share
    mta/             # the MTA part (Postfix replacement)
    filter/          # the filter part (Rspamd replacement, 2.0)
    mailbox/         # the mailbox part (Dovecot replacement, 3.0)
  <component>/       # Reusable components, one folder each
```

| Location | Purpose | Reusable? |
|---|---|---|
| `lib/sovite.ex` | Application entry point. Starts the supervision tree from `core/`. | No |
| `lib/core/` | What every part shares: the config file, the database, the supervision tree, config reload and draining, the cluster, the CLI (`sovitectl`) and web UI shells, logging, telemetry, metrics, traces, certificates, and tenants. | No |
| `lib/core/mta/` | The MTA part: receiving, queueing, routing, and delivering mail, and everything around it. | No |
| `lib/core/filter/`, `lib/core/mailbox/` | The filter and mailbox parts, when they come (see `ROADMAP.md`). | No |
| `lib/<component>/` | Self-contained building blocks (SMTP, DKIM, SPF, ...) usable by any Elixir project. | Yes |

The parts share one database and one schema. Each table belongs to one part, or to all of them, and a part reaches another part's data only through that part's interface, never its tables or internals.

---

## 2. Reusable Components

Each folder maps to one namespace: `lib/<component>/` → `Sovite.<Component>`.
Everything lives under `Sovite.*` to avoid module name clashes in projects that depend on Sovite.

### Layer 0: Primitives (pure, no processes, no I/O)

| Folder | Namespace | Contents |
|---|---|---|
| `validators/` | `Sovite.Validators` | Syntax checks for addresses (RFC 5321/5322, and internationalized ones per RFC 6531), domains, hostnames, IP literals, HELO names |
| `idna/` | `Sovite.IDNA` | Internationalized domain names (IDNA2008, RFC 5890–5893): Punycode, U-label/A-label conversion, code point, contextual, and Bidi rules |
| `net/` | `Sovite.Net` | IP address and CIDR network parsing and matching |

### Layer 1: Formats & Infrastructure

| Folder | Namespace | Contents |
|---|---|---|
| `message/` | `Sovite.Message` | RFC 5322 header parsing/folding, address lists (rewriting addresses in `From:`/`To:`/...), MIME, `Received:` / `Date:` / `Message-ID:` builders, trace fields (`Return-Path:`, `Delivered-To:`, hop counting), streaming body handling |
| `dns/` | `Sovite.DNS` | Resolver behaviour, default resolver, cache, MX / TXT / TLSA helpers, Null MX |
| `ldap/` | `Sovite.LDAP` | LDAP connections (StartTLS/LDAPS), bind, search, RFC 4515 filters with injection-safe placeholders, DN escaping |
| `sasl/` | `Sovite.SASL` | PLAIN, LOGIN, SCRAM-SHA-256, OAUTHBEARER (both server and client side) |
| `proxy_protocol/` | `Sovite.ProxyProtocol` | HAProxy PROXY protocol v1/v2: header parser (TLVs, CRC32C check), encoder, and a socket reader that never reads past the header |
| `maildir/` | `Sovite.Maildir` | Crash-safe Maildir delivery (`tmp/` then `new/`) |
| `pipe/` | `Sovite.Pipe` | Run an external command with a file on standard input: no shell, clean environment, timeout, output limit |
| `metrics/` | `Sovite.Metrics` | Counters, sums, gauges, and histograms computed from `:telemetry` events, with bounded label sets, and the Prometheus text format |
| `systemd/` | `Sovite.Systemd` | The systemd protocol without libsystemd: `sd_notify` (ready, reloading, stopping, status), the watchdog, socket activation |

### Layer 2: Protocols & Mail Authentication

| Folder | Namespace | Contents |
|---|---|---|
| `smtp/` | `Sovite.SMTP` | Command/reply codec, enhanced status codes, server session state machine (with greeting delay, tarpit, pipelining checks, `SMTPUTF8`, `CHUNKING`/`BINARYMIME`, `DSN`, `ETRN`, `MT-PRIORITY`, `FUTURERELEASE`, `DELIVERBY`, `RRVS`, and Postfix's `XCLIENT` and `XFORWARD`), client state machine (with `SMTPUTF8`, `BDAT`, DSN and the other extension parameters, and `XFORWARD`), xtext and ESMTP parameter values, LMTP (client over TCP and Unix sockets, and server mode), extensions |
| `dsn/` | `Sovite.DSN` | Build and parse delivery status notifications (RFC 3464 / 6522), internationalized ones too (RFC 6533) |
| `spf/` | `Sovite.SPF` | SPF evaluation (RFC 7208) |
| `dkim/` | `Sovite.DKIM` | DKIM signing and verification (RFC 6376, 8301, 8463) |
| `dmarc/` | `Sovite.DMARC` | DMARC record parsing, alignment, policy evaluation, aggregate reports |
| `arc/` | `Sovite.ARC` | ARC verification and sealing (RFC 8617) |
| `auth_results/` | `Sovite.AuthResults` | `Authentication-Results:` header build/parse (RFC 8601) |
| `srs/` | `Sovite.SRS` | Sender Rewriting Scheme (SRS0/SRS1) addresses for forwarded mail |
| `tls/` | `Sovite.TLS` | Certificate store with SNI, ACME, DANE verification, MTA-STS policies (discovery, fetch, MX matching, a policy server), TLS-RPT reports |
| `milter/` | `Sovite.Milter` | Milter protocol client (version 6, for Rspamd, OpenDKIM, OpenDMARC, ClamAV-milter, ...), packet codec, applying a milter's header changes with libmilter index rules |
| `policy/` | `Sovite.Policy` | Postfix policy delegation protocol: a client (TCP, Unix socket, or a program on standard input and output, as for policyd-spf), access(5) action parsing, and a server, so policy servers can be written in Elixir |
| `abuse/` | `Sovite.Abuse` | Failed-login penalties, DNSBL/DNSWL/RHSBL scoring, reverse DNS (FCrDNS) checks, greylisting decisions, rate limiting, an expiring cache |
| `queue/` | `Sovite.Queue` | Durable mail spool with storage behaviour, crash recovery, retry scheduler |
| `listener/` | `Sovite.Listener` | TCP/TLS listener with connection limits, PROXY protocol support, draining, live option updates, and inherited sockets |
| `tracing/` | `Sovite.Tracing` | OpenTelemetry traces from `:telemetry` events, sampled, batched, and exported with OTLP/HTTP (JSON) |
| `cluster/` | `Sovite.Cluster` | A cluster of BEAM nodes over Partisan, without Distributed Erlang: TLS 1.3 with mutual authentication, joining known peers, messages and calls to named processes on other nodes, node up/down notifications. Partisan is one per VM and configured through its application env, so this component is the exception to the rules on configuration and global state |

### Layer 3: Sovite Only

| Folder | Namespace | Contents |
|---|---|---|
| `core/` | `Sovite.Core` | What the parts share: config file schema/loading/reload, supervision tree, database (Ecto repo, migrations, schemas, table modules), CLI (`sovitectl`), operations (web UI and admin API on Plug and Cowboy, metrics and trace definitions, config reload, graceful drain, systemd), clustering (membership, the shared configuration, shared rate limits, bans, and greylisting), certificates (ACME), and tenants |
| `core/mta/` | `Sovite.Core.MTA` | The MTA: the SMTP session handler, routing (domain classes, aliases, address rewriting, transports, next-hop selection), restriction chains, submission fixes, the queue manager and delivery orchestration (per-destination concurrency; SMTP, LMTP, Maildir, and pipe transports), email authentication of received and sent mail (SPF, DKIM, ARC, DMARC, SRS) and DMARC reports, transport security policies (DANE, MTA-STS cache, REQUIRETLS) and TLS-RPT reports, anti-abuse (postscreen-like client screen, greylisting, rate limits, suspension of compromised accounts), milters, policy servers, after-queue content filters, bounce service, `sendmail` compatibility, Postfix config migration, queue inspection, message traces and reports from the logs, queue copies and takeover in a cluster, placement of deliveries, and outbound IP pools with warm-up schedules |

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
  config.ex          # Sovite.Core.Config: loading, validating, and storing the config file
  config/            # config schema and cross-key checks
  sovite_supervisor.ex # Sovite.Core.Supervisor: the supervision tree
  control.ex         # Sovite.Core.Control: config reload, graceful drain, systemd notifications, status
  cli.ex, cli/       # sovitectl and its commands
  web.ex             # Sovite.Core.Web: the web server (Plug and Cowboy): UI, admin API, protections
  web/               # its router, API, pages, and security plugs
  cluster.ex         # Sovite.Core.Cluster: runs as a cluster node; the shared configuration
  cluster/           # the shared configuration, sharing anti-abuse state
  tenants.ex         # Sovite.Core.Tenants: tenants, their limits and keys
  acme.ex            # Sovite.Core.ACME: ACME certificates
  metrics.ex         # Sovite.Core.Metrics: the Prometheus metrics
  tracing.ex         # Sovite.Core.Tracing: the OpenTelemetry spans
  logging.ex         # Sovite.Core.Logging: the [log] section, log files, syslog
  log_reader.ex      # Sovite.Core.LogReader: reading Sovite's logs back
  telemetry.ex       # Sovite.Core.Telemetry: the event catalog, logged by default
  address.ex         # Sovite.Core.Address: splitting addresses, Maildir folders
  stack.ex           # Sovite.Core.Stack: which parts run where
  stack/             # the parts' interfaces: Sovite.Core.Stack.Mailbox (the user directory, delivery to the store)
  mailbox/           # the mailbox part: its user directory, the Maildir store, and the server other nodes deliver to
  mta/
    smtp_handler.ex  # Sovite.Core.MTA.SMTPHandler: the SMTP session's policy and spooling
    queue_manager.ex # Sovite.Core.MTA.QueueManager: schedules queued mail
    delivery.ex      # Sovite.Core.MTA.Delivery: runs one job, SMTP here
    delivery/        # LMTP, local (Maildir and pipe), TLS policies, and the shared transaction/result code
    mail_auth.ex     # Sovite.Core.MTA.MailAuth: SPF/DKIM/ARC/DMARC checks, signing, sealing
    dmarc_reports.ex # Sovite.Core.MTA.DMARCReports: aggregate report sender
    mta_sts.ex       # Sovite.Core.MTA.MTASTS: MTA-STS policies of recipient domains, cached
    tls_reports.ex   # Sovite.Core.MTA.TLSReports: TLS-RPT report sender
    screen.ex        # Sovite.Core.MTA.Screen: anti-abuse checks of SMTP clients
    greylist.ex      # Sovite.Core.MTA.Greylist: greylisting, stored in the database
    outbound.ex      # Sovite.Core.MTA.Outbound: suspends users whose mail fails too often
    milters.ex       # Sovite.Core.MTA.Milters: the milters of an SMTP session
    policy_service.ex # Sovite.Core.MTA.PolicyService: check_policy_service in the restriction chains
    sendmail.ex      # Sovite.Core.MTA.Sendmail: sendmail(1), mailq(1), newaliases(1)
    ip_pools.ex      # Sovite.Core.MTA.IPPools: outbound IP pools and warm-up schedules
    queue_info.ex    # Sovite.Core.MTA.QueueInfo: reading the queue for sovitectl and the API
    route_info.ex    # Sovite.Core.MTA.RouteInfo: how an address is routed, for sovitectl route
    trace.ex, log_report.ex # message traces and traffic reports from the logs
    cluster/         # queue copies and takeover, which node delivers what
    postfix/         # reading Postfix's main.cf, master.cf, and tables, for sovitectl migrate postfix
    ...              # routing, rewriting, recipients, restrictions, bounces
```

Every database table has its own migration, schema, and table module. Code outside `core/repo/`, including `sovitectl`, reaches the database only through the table modules (see `AGENTS.md`).

---

## 3. Dependency Rules

1. **Dependencies only point downward.** A component may depend on components in the same or lower layers, never higher.
2. **Reusable components never depend on `core/` or `sovite.ex`.** If a reusable component needs something from `core/`, that something is either moved into a reusable component or injected via a behaviour/option.
3. **No dependency cycles** between components, even within the same layer.
4. **The parts never reference each other.** `core/mta/`, `core/filter/`, and `core/mailbox/` meet only through the shared interfaces in `Sovite.Core.Stack`, so each part can be turned off, or run on other nodes.
5. **Each table belongs to one part, or is shared.** Only its part uses a part's table modules, besides `core/repo/` and the operator surfaces of every part, `sovitectl` (`core/cli*`) and the admin API (`core/web/`). The MTA's tables: access rules, address rewrites, aliases, BCC rules, DMARC and TLS report entries, greylist entries, IP address counts, MTA-STS policies, relocated users, sender relays, and transports. Shared: domains (every part serves them), and users and mailboxes (identity, which the mailbox part owns once it exists). The list is in `scripts/check_boundaries.sh`; add a new table to it.
6. **Enforced in CI** with `mix xref graph --format cycles` and `scripts/check_boundaries.sh`, which checks that no reusable folder references `Sovite.Core`, that the parts stay apart, and the table owners. The `boundary` library can make these compile-time errors.

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
  fuzz/             # fuzz tests, tagged :fuzz (mix fuzz)
  support/          # fake DNS, fake remote MTA, SMTP test client, fuzz generators
```

- Each reusable component is tested in isolation, with no dependency on `core/`.
- `core/` tests cover wiring and end-to-end mail flow.
- `fuzz/` tests feed untrusted input (from clients, servers, DNS, milters, policy servers, authentication backends, local users, and files) to the code that reads it, as random bytes and mutations of real input (`Sovite.Test.Fuzz`). They check that it never crashes, that what it lets through is safe to store and send, and that splitting input differently changes nothing. A failure prints the shrunk input: add it to the module's regular tests when fixing it.

---

## 7. Packaging

- Published as a single Hex package: `sovite`.
- Each component folder is kept self-contained so it could later be extracted into its own package (e.g. `sovite_dkim`) without breaking its public API.
- Docs (ExDoc) group modules by component, using `groups_for_modules` that match the folder layout.
