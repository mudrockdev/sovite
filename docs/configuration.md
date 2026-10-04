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

## `[queue]`

| Key | Type | Default | Description |
|---|---|---|---|
| `directory` | absolute path | `/var/spool/sovite` | Spool directory, created with mode `0700` if missing. Must be owned by the Sovite user. Accepted messages are in `incoming/`. |

## `[[listener]]`

An array of tables: one per address and port to accept SMTP on. Without any `[[listener]]` table, Sovite listens on `0.0.0.0:25`. Write `listener = []` (before the first table) to listen nowhere.

```toml
[[listener]]
address = "0.0.0.0"
port = 25

[[listener]]
address = "::"
port = 25
```

| Key | Type | Default | Description |
|---|---|---|---|
| `address` | IP address | `0.0.0.0` | Address to bind. IPv6 listeners are IPv6-only, so add both `0.0.0.0` and `::` for dual stack. |
| `port` | integer | `25` | TCP port. Ports below 1024 need `CAP_NET_BIND_SERVICE` or socket activation, see [Security](security.md). |

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

1. `postmaster` at a local domain, or a bare `<Postmaster>`, is always accepted (RFC 5321 §4.5.1).
2. Local domain: accepted if `local_recipients` is unset or lists the address.
3. Relay domain: accepted.
4. Any other domain: accepted only from `trusted_networks`, otherwise `554 5.7.1 Relay access denied`.

Domains are compared case-insensitively, and only the domain of the parsed address counts: tricks like `user%other.example@local` or source routes never relay. The default config trusts no one, so a fresh install is never an open relay.

A message is accepted with `250 2.0.0 Ok: queued as <queue ID>` only after it is written and `fsync`ed in the queue directory.

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
