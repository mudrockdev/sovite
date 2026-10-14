#!/bin/sh
# After installing or upgrading the package.
set -e
if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers /usr/lib/sysusers.d/sovite.conf
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/sovite.conf
fi
chgrp sovite /etc/sovite/sovite.toml 2>/dev/null || true
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  # An upgrade: restart a running server on the new release.
  systemctl try-restart sovite.service || true
fi
