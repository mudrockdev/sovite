# Sovite

A modern, secure Mail Transfer Agent written in Elixir/OTP, meant as an alternative to Postfix.

> **Status:** early development. Sovite receives mail over SMTP, queues it durably, and relays it to other servers with retries and bounces (Phases 1–2). TLS, authentication, and local delivery are next. See the [roadmap](ROADMAP.md).

Sovite is also a library: its components (address validators, DNS and MX resolution, an SMTP server and client, delivery status notifications, and later DKIM, SPF, ...) can be used from any Elixir project without running the MTA. See [STRUCTURE.md](STRUCTURE.md).

## Development

Requires Erlang/OTP 29 and Elixir 1.20 (see `mise.toml`).

```sh
mix deps.get
mix test            # tests, including property tests
mix lint            # format check, warnings as errors, credo, xref cycles
mix dialyzer
```

Run the MTA locally:

```sh
cp rel/overlays/etc/sovite.toml.example sovite.toml   # edit as needed
SOVITE_START_MTA=1 SOVITE_CONFIG=./sovite.toml iex -S mix
```

Build a release:

```sh
MIX_ENV=prod mix release
_build/prod/rel/sovite/bin/sovitectl config check _build/prod/rel/sovite/etc/sovite.toml.example
SOVITE_CONFIG=/etc/sovite/sovite.toml _build/prod/rel/sovite/bin/sovite start
```

## Documentation

- [Configuration](docs/configuration.md)
- [Logging and telemetry](docs/logging.md)
- [Security model](docs/security.md) and [vulnerability reporting](SECURITY.md)

## License

AGPL-3.0. See [LICENSE](LICENSE).
