# Operations

Running Sovite: the queue, the configuration, message traces and log reports, the admin API, metrics and traces, stopping and reloading, systemd, and packages.

## `sovitectl`

`sovitectl` reads the config file (`--config PATH`, `$SOVITE_CONFIG`, or `/etc/sovite/sovite.toml`). Commands that only read files work whether or not the server runs. Commands that change the running server go through the [admin API](#the-admin-api), with the token in `admin.token_file`, so run them as root or as the user Sovite runs as.

| Command | Reads | Needs the server |
|---|---|---|
| `queue list [QUEUE]`, `queue show ID` | the queue directory | no |
| `queue flush`, `hold`, `release`, `delete`, `requeue` | | yes |
| `config check`, `config show`, `config diff OLD NEW` | config files | no |
| `config diff [PATH]`, `config reload` | | yes |
| `route ADDRESS [SENDER]` | the config file and the database | no |
| `status` | | yes |
| `trace ID [LOG...]`, `report [LOG...]` | log files | no |

A command that needs the server prints `sovite is not running` when it cannot reach it; `status` then exits with `3`.

### The queue

```
$ sovitectl queue list
-Queue ID-     -Queue-   --Size-- ----Arrival Time---- -Sender/Recipient-------
8CboABCDEFGHIJ deferred      1532 Sun Oct 04 12:00:00  alice@example.org
                                                       (451 4.7.1 Greylisted, try again later)
                                                       bob@example.net

-- 1 Kbytes in 1 message.
```

`queue list deferred` lists one queue: `incoming`, `active`, `deferred`, `hold`, or `corrupt`. `queue show ID` prints the envelope (client, `HELO` name, login, extension parameters), each recipient's status and last reply, and the header fields.

| Command | Postfix | What it does |
|---|---|---|
| `queue flush` | `postqueue -f` | Retry every deferred message now. |
| `queue flush ID...` | `postqueue -i ID` | Retry these messages now. |
| `queue hold ID...` | `postsuper -h` | Move messages to `hold/`: they are not delivered until released. |
| `queue release ID...` | `postsuper -H` | Move held messages back to `deferred/`. |
| `queue delete ID...` | `postsuper -d` | Delete messages, without notifying anyone. |
| `queue requeue ID...` | `postsuper -r` | Route messages again, with the current aliases and routing tables, and retry them now. Works for held and corrupt messages too. |

An `ID` of `-` reads IDs from standard input, one per line. A message being delivered is held or deleted once its running deliveries end; deliveries that had not started are dropped. A message on hold for `FUTURERELEASE` stays on hold until its release time, even when flushed.

`mailq` (`sendmail -bp`) lists the queue the way Postfix does.

### The configuration

`config show` prints every setting with its value, from the file or the default, like `postconf`; `config show -n` only those set in the file, like `postconf -n`. Keys are dotted paths, values are TOML, and secrets are shown as `"********"`:

```
$ sovitectl config show -n
server.hostname = "mx.example.org"
listener[0].port = 25
smtp.max_message_size = "50M"
```

`config diff` prints what reloading the file would change in the running server, and `config diff OLD NEW` the difference between two files:

```
$ sovitectl config diff
- smtp.max_recipients = 100
+ smtp.max_recipients = 200
```

`config reload` reloads the running server and waits for it; see [Stopping and reloading](#stopping-and-reloading).

### Routing

`route ADDRESS` shows how the server would handle mail for an address: recipient rewriting, the domain's class, alias expansion, and for each final address its transport and next hop, or why it is deferred or refused. `SENDER` matters for sender-dependent relay hosts. Nothing is looked up in DNS.

```
$ sovitectl route sales@example.com
address: sales@example.com
domain: example.com (aliased)
expands to: alice@example.com, bob@partner.example
  alice@example.com: deliver via lmtp to /run/dovecot/lmtp
  bob@partner.example: deliver via smtp to partner.example
```

### Status

```
$ sovitectl status
sovite 0.2.0 on mx.example.org
up 3d 4h 12m, since 2026-10-01T08:00:00Z
config: /etc/sovite/sovite.toml, reloaded 2026-10-03T16:20:11Z
queue: 0 incoming, 2 active, 14 deferred, 0 hold, 0 corrupt
deliveries: 2 running, 0 waiting
listeners:
  smtp/0.0.0.0:25: 31 connections
  submission/0.0.0.0:587: 2 connections
```

### Tracing a message

`trace` follows a message through the logs, by queue ID or `Message-ID`: the session it came in on (the client, its login, rejected commands), its acceptance, every delivery attempt, the notifications sent about it (which are traced too), and its removal. If it is still queued, it says where.

```
$ sovitectl trace '<20261004120000.abc@example.org>'
... queue_id=8CboABCDEFGHIJ session_id=k2x... remote_ip=192.0.2.7 event=smtp.message.accepted smtp.message.accepted: helo=client.example.org, message_id=<20261004120000.abc@example.org>, ...
... queue_id=8CboABCDEFGHIJ event=smtp.client.delivery.stop smtp.client.delivery.stop: recipient=bob@example.net, relay=mx.example.net[192.0.2.25], reply=250 2.0.0 Ok, status=delivered
... queue_id=8CboABCDEFGHIJ event=queue.message.removed queue.message.removed: reason=delivered
```

It reads the log files of `[log] directory`, or the files given, or standard input for `-`. Every log format works, also through syslog or journald:

```sh
journalctl -u sovite -o short-iso | sovitectl trace 8CboABCDEFGHIJ -
```

Lines below `[log] level` are not in the logs: at `info`, a session's accepted commands are not, but its rejected ones are.

### Log reports

`report` summarizes the logs like Postfix's `pflogsumm`: messages received, recipients delivered, deferred, and bounced, rejected commands, held, discarded, expired, and deleted messages, bytes, senders and recipient domains, traffic per hour (or per day), delivery delays per domain, and the most common deferral, bounce, and rejection reasons, warnings, and failed logins.

```sh
sovitectl report --date yesterday           # e.g. from cron, mailed to postmaster
sovitectl report --top 20 /var/log/sovite/sovite.2026-10-0*.log
```

Compressed (`.gz`) files are read too.

## The admin API

An HTTP API on `127.0.0.1:9025` (`[admin]`), for `sovitectl`, monitoring, and status pages. Requests must come from `admin.allowed_networks` and carry the token from `admin.token_file`, which the server creates on its first start:

```sh
curl -H "Authorization: Bearer $(cat /var/lib/sovite/admin.token)" http://127.0.0.1:9025/api/status
```

| Request | |
|---|---|
| `GET /api/status` | Version, uptime, config file and last reload, listeners and their connections, queue sizes, deliveries |
| `GET /api/queue` | Queued messages; `?queue=deferred` for one queue, `?limit=n` |
| `GET /api/queue/ID` | One message: envelope, recipients, header fields |
| `POST /api/queue/flush` | Retry every deferred message |
| `POST /api/queue/ID/retry`, `/hold`, `/release`, `/delete`, `/requeue` | As the `sovitectl queue` commands |
| `GET /api/config` | The running settings, secrets hidden |
| `POST /api/config/reload` | Reload the config file: `200`, `422` with the errors of an invalid file, or `409` for changes that need a restart |
| `GET /api/route?address=A&sender=S` | As `sovitectl route` |
| `GET /api/trace?id=ID` | As `sovitectl trace`, with `[log] directory` |
| `GET /metrics` | Prometheus metrics |

Responses are JSON; errors are `{"error": "..."}`. With `admin.web_root` set, other `GET` requests serve the files in that directory, so a status UI built as static files can be served next to the API it calls.

## Metrics and traces

`/metrics` serves Prometheus metrics (`[metrics]`): connections, commands and their replies, logins, TLS handshakes, messages received, deferred, and removed, delivery results and times, notifications, anti-abuse actions, queue sizes, running deliveries, open connections, and the Erlang VM's memory and processes. The list is in `Sovite.Core.Metrics`. Counters start from zero when the server starts.

With `[tracing]`, SMTP sessions and deliveries are sent as OpenTelemetry traces over OTLP/HTTP. Each session is a trace, with a span per command; each message is a trace with a span per delivery attempt, so every attempt is in the same trace however far apart. The `message accepted` event of the session names the message's queue ID. See `Sovite.Core.Tracing`.

Both come from the `:telemetry` events of `Sovite.Core.Telemetry`. Applications embedding Sovite can attach their own handlers to the same events.

## Stopping and reloading

### Stopping

On `SIGTERM` (`systemctl stop`, `podman stop`), the server drains:

1. The SMTP listeners stop accepting connections.
2. Idle sessions get `421 4.3.2 Service shutting down` and are closed. Sessions in a transaction finish it first, then get the `421`.
3. No new deliveries start; running ones get to end.
4. After `server.shutdown_timeout` (30 seconds by default), whatever is left is cut off. Messages that were being delivered stay in the queue and are delivered after the next start, so nothing is lost; at worst a recipient gets a message twice, which SMTP allows.

Give the service manager more time than `shutdown_timeout` before it kills the server: the systemd unit sets `TimeoutStopSec=60`, the compose file `stop_grace_period: 40s`.

### Reloading

`systemctl reload sovite`, `sovitectl config reload`, or `SIGHUP` reload the config file without stopping:

- An invalid file changes nothing: `sovitectl config reload` prints the errors and fails, and `SIGHUP` logs them.
- Listeners keep their sockets and open connections. New connections get the new settings: limits, restrictions, TLS settings, milters, and the rest. A listener whose address or port changed is a new listener: the old one is drained and removed, the new one started. Changing `smtp.max_connections` drains the listeners and restarts them, so they refuse connections for a moment; a listener on a socket from systemd keeps its old limit until the next restart.
- The queue manager takes its new settings for the messages it picks up from then on.
- Everything else whose settings changed is restarted with them.
- `[database]` and `queue.directory` changes need a restart: the reload is refused.

## systemd

The release ships units in `share/systemd/` (the packages install them):

- `sovite.service`: `Type=notify`. The server tells systemd when it is ready, reloading, and stopping, with a status line (`systemctl status sovite`), and pings the watchdog (`WatchdogSec=60`): a server that stops answering is restarted. `ExecReload` runs `sovitectl config reload`, so `systemctl reload` fails on an invalid file. The unit runs as the `sovite` user with a strict sandbox: read-only system, private `/tmp` and devices, no new privileges, only `CAP_NET_BIND_SERVICE` for ports 25, 465, and 587, and a system call filter.
- `sovite.socket`: socket activation. systemd opens the SMTP ports, and connections that arrive while the server restarts wait instead of being refused. Each `ListenStream=` must match a `[[listener]]`, address and port; listeners without a socket open their own. Enable it instead of the service: `systemctl enable --now sovite.socket`.
- `sovite-sysusers.conf` and `sovite-tmpfiles.conf`: the `sovite` user, and the queue, state, log, and config directories.

`Type=notify-reload` is not needed: reloads are synchronous through `ExecReload`.

## Packages and images

Releases are built with `mix release`; `scripts/package.sh` builds:

- `dist/sovite-VERSION-linux-ARCH.tar.gz`: the release, with the Erlang runtime. Unpack it in `/opt/sovite`.
- `.deb` and `.rpm` packages, when [nfpm](https://nfpm.goreleaser.com) is installed (`packaging/nfpm.yaml`). They install the release in `/opt/sovite`, the systemd units, `/usr/bin/sovitectl`, and `/etc/sovite/sovite.toml`, and create the `sovite` user. Build them on the distribution release they are for: the runtime links to its OpenSSL.

The `Containerfile` builds an image that runs the release as the `sovite` user, with the config in `/etc/sovite/sovite.toml`, and volumes for `/var/lib/sovite` and `/var/spool/sovite`. Logs go to standard output, and the health check runs `sovitectl status`. `Container/docker-compose.yaml` runs it with Compose:

```sh
podman build -t sovite -f Containerfile .
podman run -d --name sovite -p 25:25 -p 587:587 -v ./sovite.toml:/etc/sovite/sovite.toml:ro \
  -v sovite-data:/var/lib/sovite -v sovite-queue:/var/spool/sovite sovite
podman exec sovite sovitectl queue list
```
