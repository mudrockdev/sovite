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

## Telemetry

Reusable components never write logs. They emit `:telemetry` events named `[:sovite, component, ...]`, and the host application decides what to do with them. Sovite itself attaches `Sovite.Core.Telemetry`, which logs each event:

- message lifecycle events (enqueue, removal, delivery results) at `info`
- everything else at `debug`

The full event catalog, with measurements and metadata, is in the `Sovite.Core.Telemetry` module docs. Metrics exporters (Prometheus, OpenTelemetry; roadmap Phase 12) attach to the same events.
