#!/bin/sh
# After installing or upgrading the package.
set -e
if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers /usr/lib/sysusers.d/sovite.conf
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/sovite.conf /usr/lib/tmpfiles.d/sovite-runtime.conf
fi
chgrp sovite /etc/sovite/sovite.toml 2>/dev/null || true

# Unpack the binary once, as root, into /usr/lib/sovite, for every user
# and the service (whose /usr is read-only). This also removes the
# unpacked copy of the version this one replaces.
/usr/bin/sovite version >/dev/null

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  # An upgrade: restart a running server on the new version.
  systemctl try-restart sovite.service || true
fi
