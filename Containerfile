# Sovite container image.
#
#   podman build -t sovite -f Containerfile .
#   podman run -d --name sovite -p 25:25 -p 465:465 -p 587:587 \
#     -v ./sovite.toml:/etc/sovite/sovite.toml:ro \
#     -v sovite-data:/var/lib/sovite -v sovite-queue:/var/spool/sovite sovite
#   podman exec sovite sovitectl status
#
# Logs go to standard output. The web UI and admin API listen inside the
# container only (127.0.0.1:9025), for sovitectl; to reach the UI from
# outside, set [admin] address and allowed_networks, and publish 9025.

ARG ELIXIR_VERSION=1.20.4
ARG OTP_VERSION=29.0
ARG DEBIAN_VERSION=trixie-slim
ARG BUN_VERSION=1.4

# The web UI: a static build, served from priv/web.
FROM docker.io/oven/bun:${BUN_VERSION} AS web
WORKDIR /build
COPY package.json bun.lock bunfig.toml ./
COPY lib/core/sovite_web lib/core/sovite_web
RUN bun install --frozen-lockfile && bun run build

FROM docker.io/hexpm/elixir:${ELIXIR_VERSION}-erlang-${OTP_VERSION}-debian-${DEBIAN_VERSION} AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
ENV MIX_ENV=prod
RUN mix local.hex --force && mix local.rebar --force

COPY mix.exs mix.lock ./
RUN mix deps.get --only prod && mix deps.compile

COPY config config
COPY lib lib
COPY rel rel
COPY --from=web /build/lib/core/sovite_web/build priv/web
RUN mix release

FROM docker.io/library/debian:${DEBIAN_VERSION}

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libssl3t64 libtinfo6 libstdc++6 ca-certificates libcap2-bin tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system sovite \
 && useradd --system --gid sovite --home-dir /var/lib/sovite --shell /usr/sbin/nologin sovite \
 && install -d -o sovite -g sovite -m 0750 /var/lib/sovite \
 && install -d -o sovite -g sovite -m 0700 /var/spool/sovite \
 && install -d -o root -g sovite -m 0750 /etc/sovite

COPY --from=build /build/_build/prod/rel/sovite /opt/sovite
COPY rel/overlays/etc/sovite.toml.example /etc/sovite/sovite.toml

# Bind ports 25, 465, and 587 without running as root.
RUN setcap cap_net_bind_service=+ep "$(find /opt/sovite/erts-*/bin -name beam.smp)" \
 && ln -s /opt/sovite/bin/sovitectl /usr/local/bin/sovitectl \
 && chgrp sovite /etc/sovite/sovite.toml && chmod 0640 /etc/sovite/sovite.toml

ENV SOVITE_CONFIG=/etc/sovite/sovite.toml \
    RELEASE_DISTRIBUTION=none \
    HOME=/var/lib/sovite \
    LANG=C.UTF-8

USER sovite
VOLUME ["/var/lib/sovite", "/var/spool/sovite"]
EXPOSE 25 465 587

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s \
  CMD ["/opt/sovite/bin/sovitectl", "status"]

# The VM drains on SIGTERM; give it server.shutdown_timeout to do so
# (podman stop --time 40).
STOPSIGNAL SIGTERM
CMD ["/opt/sovite/bin/sovite", "start"]
