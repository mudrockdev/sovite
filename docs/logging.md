# Logging and Telemetry

## Conventions

- **One message, one ID.** Each message gets a queue ID when it is accepted. Every log line about that message carries the ID in the `queue_id` metadata key, from `250 OK` to final delivery or bounce. `grep <queue_id>` shows a message's full history.
- **One connection, one session ID.** SMTP sessions carry `session_id`, so lines about a connection that never produced a message can still be traced.
- **Standard metadata keys:** `queue_id`, `session_id`, `remote_ip`, `event`. Both log formats include them.
- **No secrets.** Passwords, SASL exchanges, private keys, and message bodies are never logged at any level.
- **Untrusted input is quoted.** Values received from the network (`EHLO` names, addresses) are logged with `inspect/1` or as JSON strings, so they cannot inject fake log lines.

## Formats

`[log] format = "text"`:

```
2026-10-04 12:00:00.123 [info] queue_id=4Xb2Kq event=queue.message.enqueued queue.message.enqueued: recipients=2, sender=a@example.com, size=1024
```

`[log] format = "json"`, one object per line:

```json
{"time":"2026-10-04T12:00:00.123456Z","level":"info","msg":"queue.message.enqueued: recipients=2, sender=a@example.com, size=1024","queue_id":"4Xb2Kq","event":"queue.message.enqueued"}
```

A delivered message, from acceptance to removal:

```
[info] queue_id=8CboABCDEFGHIJ event=queue.message.enqueued queue.message.enqueued: recipients=1, sender=alice@example.org, size=1532
[info] queue_id=8CboABCDEFGHIJ event=smtp.client.delivery.stop smtp.client.delivery.stop: duration=412, recipient=bob@example.net, relay=mx.example.net[192.0.2.25], reply=250 2.0.0 Ok: queued as 4Xb2Kq, status=delivered
[info] queue_id=8CboABCDEFGHIJ event=queue.message.removed queue.message.removed: reason=delivered
```

## Log Files

By default, logs go to standard output, for systemd or a container runtime to collect. Set `[log] directory` to write rotating files instead, similar to pino-roll:

```toml
[log]
directory = "/var/log/sovite"
file_name = "sovite.{date}.{n}.log"
date_format = "%Y-%m-%d"
max_size = "1G"
rotation = "daily"
max_files = 14
symlink = "current.log"
```

This produces:

```
sovite.2026-10-04.1.log
sovite.2026-10-04.2.log    # the first file reached 1G
sovite.2026-10-05.1.log    # a new day
current.log -> sovite.2026-10-05.1.log
```

- A new file starts before the current one would exceed `max_size`, and when the `rotation` period changes. Lines are never split across files.
- After each rotation, only the newest `max_files` files that match `file_name` are kept. Other files in the directory are left alone.
- After a restart, Sovite continues the newest file for the current date if it is not full.
- Dates use local time, or UTC when `config :logger, utc_log: true` is set.
- New files are created with mode `0640`, since logs contain email addresses.
- If the current file is deleted or renamed (for example by logrotate), it is reopened within 5 seconds.
- While file logging runs, nothing is written to standard output. Errors writing the log file itself go to standard error, and opening it is retried every second.
- Under overload, logging blocks callers, then drops events. The number of dropped events is written to the log once the writer catches up.

All keys are in the [configuration reference](configuration.md#log).

## Telemetry

Reusable components never write logs. They emit `:telemetry` events named `[:sovite, component, ...]`, and the host application decides what to do with them. Sovite itself attaches `Sovite.Core.Telemetry`, which logs each event:

- message lifecycle events (enqueue, delivery result per recipient, deferral, notifications sent, removal) at `info`
- corrupt queue files and notifications that could not be sent anywhere (double bounces) at `warning`
- SMTP commands that were rejected (4xx/5xx replies), with the command, its argument, and the reply, at `info`
- everything else at `debug`

The full event catalog, with measurements and metadata, is in the `Sovite.Core.Telemetry` module docs. Metrics exporters (Prometheus, OpenTelemetry; roadmap Phase 12) attach to the same events.
