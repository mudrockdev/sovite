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
| `directory` | absolute path | `/var/spool/sovite` | Spool directory. Must be owned by the Sovite user with mode `0700`. |

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
