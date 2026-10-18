# Operations

Running Sovite: the queue, the configuration, message traces and log reports, the web UI and admin API, metrics and traces, stopping and reloading, clusters, systemd, and packages.

## `sovitectl`

`sovitectl` reads the config file (`--config PATH`, `$SOVITE_CONFIG`, or `/etc/sovite/sovite.toml`). Commands that only read files work whether or not the server runs. Commands that change the running server go through the [admin API](#the-web-ui-and-admin-api), with the token in `admin.token_file`, so run them as root or as the user Sovite runs as.

| Command | Reads | Needs the server |
|---|---|---|
| `queue list [QUEUE]`, `queue show ID` | the queue directory | no |
| `queue flush`, `hold`, `release`, `delete`, `requeue` | | yes |
| `config check`, `config show`, `config diff OLD NEW` | config files | no |
| `config diff [PATH]`, `config reload` | | yes |
| `route ADDRESS [SENDER]` | the config file and the database | no |
| `status` | | yes |
| `trace ID [LOG...]`, `report [LOG...]` | log files | no |
| `cluster status`, `join NODE`, `leave`, `config push FILE` | | yes |
| `ip-pool status` | | yes |

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

## The web UI and admin API

One web server, built on Plug and Cowboy, listens on `127.0.0.1:9025` (`[admin]`). `/` serves the web UI, the static build of `lib/core/sovite_web` (shipped in the release as `priv/web`, or from `admin.web_root`); `/api` serves the admin API, for `sovitectl`, monitoring, and the UI; `/metrics` the Prometheus metrics. Ports 80 and 443 stay with ACME and the MTA-STS policy server.

Requests must come from `admin.allowed_networks`. API requests carry the token from `admin.token_file`, which the server creates on its first start:

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
| `GET /api/cluster` | The cluster's nodes, as this one sees them, with the version, host name, uptime, and queue sizes of those connected; the shared configuration's version; the copies of other nodes' messages held here. `{"enabled": false}` without a cluster |
| `POST /api/cluster/config` | `{"content": "TOML"}`: send it to every node as the shared configuration: `200` with the new `version`, or `422` with the `errors` it has on this node |
| `POST /api/cluster/join` | `{"peer": "name@host:port"}`: join the cluster that node is in |
| `POST /api/cluster/leave` | Drain this node, hand its queue to the others, and leave the cluster |
| `GET /api/ip_pools` | The IP pools, with the messages each address sent today and today's limit |
| `GET /metrics` | Prometheus metrics |

Responses are JSON; errors are `{"error": "..."}`.

The UI will have users of its own, so the web server treats clients as untrusted:

- Clients outside `admin.allowed_networks` get `403`.
- The token is compared in constant time. A wrong token is a failed login: it is logged as `auth.failure` with `mechanism=TOKEN`, ready for fail2ban, and after `auth.max_failures` within `auth.failure_window` the client gets `429` for `auth.ban_time`.
- `POST` requests from another site (by `Origin` or `Sec-Fetch-Site`) get `403`, and no CORS access is granted.
- Responses carry a strict `Content-Security-Policy` (the UI's own files, its inline scripts by their hash, no framing), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, same-origin opener and resource policies, a `Permissions-Policy` that turns off device access, and with `admin.tls`, `Strict-Transport-Security`. API responses are never cached.
- Request lines, headers, and connections are limited; slow clients time out.

The web server reads the configuration on each request, so a reload applies at once without restarting it; changing `[admin]` `address`, `port`, `tls`, or `token_file` restarts it.

To reach the UI from other machines, set `admin.address` (and `admin.tls = true`) and add their networks to `admin.allowed_networks`.

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

## Clusters

Sovite servers can form a cluster (`[cluster]`, see [the reference](configuration.md#clusters-cluster)). The nodes:

- share a configuration file, pushed to all of them at once;
- share rate limits, tenant limits, failed-login bans, suspended accounts, and with SQLite, greylisting;
- keep copies of each other's queued messages, and deliver those of a node that stays down;
- hand mail to the node whose IP pool it goes out from, or, with `destination_affinity`, to the node that owns its destination;
- hand their queue to the others when they leave.

They talk over [Partisan](https://hexdocs.pm/partisan), on port 4370, with TLS 1.3 both ways: each node has a certificate from the cluster's own CA, and accepts only peers with one. There is no plaintext mode: a peer can send any node any message, so the CA must sign the cluster's certificates and nothing else, and the port should only be reachable from the other nodes (a private network, or firewall rules). Distributed Erlang stays off.

### Setting one up

A CA, and a certificate for each node (here with OpenSSL; any CA tooling works):

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
  -subj "/CN=Sovite cluster CA" -keyout ca.key -out ca.pem
for node in mx1 mx2 mx3; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=$node" -keyout $node.key -out $node.csr
  openssl x509 -req -in $node.csr -CA ca.pem -CAkey ca.key -days 825 -out $node.pem
done
```

Copy `ca.pem` and each node's `.pem` and `.key` to `/etc/sovite/cluster/` on that node, readable by the `sovite` user, and keep `ca.key` offline. Then, on each node:

```toml
[cluster]
enabled = true
node_name = "mx1@10.0.0.1"
address = "10.0.0.1"
seeds = ["mx2@10.0.0.2"]
cert_file = "/etc/sovite/cluster/mx1.pem"
key_file = "/etc/sovite/cluster/mx1.key"
ca_file = "/etc/sovite/cluster/ca.pem"
shared_config = "/var/lib/sovite/cluster.toml"
```

Restart the nodes; they join each other within `join_interval`. `sovitectl cluster status` shows them:

```
Node:           mx1@10.0.0.1
Shared config:  version 3, from mx2@10.0.0.2

-Node-                          -State- -Details-
mx1@10.0.0.1                    self
mx2@10.0.0.2                    up      mx2.example.com, sovite 0.2.0, active=0 corrupt=0 deferred=4 hold=0 incoming=0, since 2026-10-18T09:12:44Z
```

A new node needs only one seed that is up: `sovitectl cluster join mx2@10.0.0.2:4370` joins a running node without a restart.

### The shared configuration

Put the settings all nodes share in a file, and send it to every node:

```sh
sovitectl cluster config push /etc/sovite/cluster.toml
```

Each node checks it with its own config file, writes it to `cluster.shared_config`, and reloads, as `sovitectl config reload` does. A node that cannot run with it keeps its version and logs `cluster.config.rejected`; the push itself fails when the node it is sent from cannot. A node's own file wins, so leave in it what is its own: `[server] hostname`, `[[listener]]`, `[cluster]`, `[database]`, and paths. Nodes that were down, or join later, get the newest version when they connect.

### When a node goes down

Each queued message is copied to `queue_replicas` other nodes when it is queued, and again when it is deferred or held, so the copy has its delivery records; the copies go when the message is done. After a node has been down for `handover_after`, the first of each message's copy holders that is up queues it and delivers it, under the same queue ID (`cluster.queue.taken_over`). When the node comes back, it is told which of its messages were taken over, and deletes them.

SMTP delivers mail at least once, and a cluster can deliver some messages twice: when a node is cut off from the others without being down, when it comes back while its messages are being taken over, or when a copy missed its last update. A longer `handover_after` makes this rarer; a node that is down for maintenance should leave the cluster instead.

### Leaving

```sh
sovitectl cluster leave
systemctl stop sovite
```

`leave` drains the node (it stops accepting and delivering mail), hands every queued message to the other nodes, and takes the node out of the cluster. Messages that could not be handed over stay in its queue.

### IP pools in a cluster

An `[[ip_pool.address]]` with `node` is used by that node only. Mail whose pool has no address on the node it was queued on is handed to a node that has one, as a new message with only those recipients: its recipients count as delivered on the first node (`handed to cluster node ... as ID` in its log), and the second node delivers it and sends the notifications. `sovitectl ip-pool status` shows what each address sent today, and its limit:

```
shared (overflow: spare)
  192.0.2.10                                     812  on mx1@10.0.0.1
  192.0.2.11                                  37/200  on mx2@10.0.0.2
```

## systemd

The release ships units in `share/systemd/` (the packages install them):

- `sovite.service`: `Type=notify`. The server tells systemd when it is ready, reloading, and stopping, with a status line (`systemctl status sovite`), and pings the watchdog (`WatchdogSec=60`): a server that stops answering is restarted. `ExecReload` runs `sovitectl config reload`, so `systemctl reload` fails on an invalid file. The unit runs as the `sovite` user with a strict sandbox: read-only system, private `/tmp` and devices, no new privileges, only `CAP_NET_BIND_SERVICE` for ports 25, 465, and 587, and a system call filter.
- `sovite.socket`: socket activation. systemd opens the SMTP ports, and connections that arrive while the server restarts wait instead of being refused. Each `ListenStream=` must match a `[[listener]]`, address and port; listeners without a socket open their own. Enable it instead of the service: `systemctl enable --now sovite.socket`.
- `sovite-sysusers.conf` and `sovite-tmpfiles.conf`: the `sovite` user, and the queue, state, log, and config directories.

`Type=notify-reload` is not needed: reloads are synchronous through `ExecReload`.

## Packages and images

### The single binary

`mix build.release.x86` and `mix build.release.aarch64` build Sovite as one executable for Linux on x86_64 or aarch64, with [Burrito](https://github.com/burrito-elixir/burrito), and its `.deb` and `.rpm` packages, into `release/`:

- `sovite-VERSION-linux-ARCH`: the executable. It holds the Erlang runtime (built against musl, with its own OpenSSL), the web UI, and everything else, and runs on any Linux distribution of its architecture, glibc or musl. It unpacks itself on its first run, into `~/.local/share/.burrito` (or `$XDG_DATA_HOME/.burrito`).
- `sovite_VERSION_ARCH.deb` and `sovite-VERSION-1.ARCH.rpm`: the executable in `/usr/lib/sovite`, unpacked there once at install time for every user, `/usr/bin/sovite` and `/usr/bin/sovitectl`, `sendmail`, `mailq`, and `newaliases` in `/usr/lib/sovite/bin`, the systemd units, and `/etc/sovite/sovite.toml`. They only need CA certificates from the system.
- `sovite-VERSION-linux-ARCH.sha256`: their SHA-256 sums.

The build runs in a container (`packaging/Containerfile.release`) with podman, or docker with buildx (`--engine docker`), so the host needs neither Zig nor nfpm, and both targets build on either architecture.

One executable is the server and every command:

```sh
sovite                       # the server (config: $SOVITE_CONFIG or /etc/sovite/sovite.toml)
sovite ctl status            # sovitectl status
sovite sendmail -t < message
sovite mailq
sovite version
```

The executable runs the Erlang VM as its child. systemd stops both; run by hand, stop it with Ctrl+C, or signal it: the VM drains and stops when the executable goes away.

The Erlang runtime loads the musl C library from a fixed path in `/tmp`, which the executable writes there when it is missing. On a machine with untrusted local users, another user could put their own file there first. The packages handle it: systemd-tmpfiles creates the file as root at boot, the service has a private `/tmp`, and the commands refuse to run if the file there belongs to another user, can be changed by another user, or is not the packaged one. Run the bare executable only as a user that owns its `/tmp`, or with a private one.

### The release

Releases are built with `mix release`; `scripts/package.sh` builds:

- `dist/sovite-VERSION-linux-ARCH.tar.gz`: the release, with the Erlang runtime and the web UI (built with bun first). Unpack it in `/opt/sovite`.
- `.deb` and `.rpm` packages, when [nfpm](https://nfpm.goreleaser.com) is installed (`packaging/nfpm.yaml`). They install the release in `/opt/sovite`, the systemd units, `/usr/bin/sovitectl`, and `/etc/sovite/sovite.toml`, and create the `sovite` user. Build them on the distribution release they are for: the runtime links to its OpenSSL.

The `Containerfile` builds an image that runs the release as the `sovite` user, with the config in `/etc/sovite/sovite.toml`, and volumes for `/var/lib/sovite` and `/var/spool/sovite`. Logs go to standard output, and the health check runs `sovitectl status`. `Container/docker-compose.yaml` runs it with Compose:

```sh
podman build -t sovite -f Containerfile .
podman run -d --name sovite -p 25:25 -p 587:587 -v ./sovite.toml:/etc/sovite/sovite.toml:ro \
  -v sovite-data:/var/lib/sovite -v sovite-queue:/var/spool/sovite sovite
podman exec sovite sovitectl queue list
```
