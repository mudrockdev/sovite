#!/bin/sh
# After removing the package (or the old one, on an upgrade). The queue,
# database, and config are kept.
set -e
case "$1" in
  remove|purge|0)
    rm -rf /usr/lib/sovite/.burrito
    rmdir /usr/lib/sovite/bin /usr/lib/sovite 2>/dev/null || true
    ;;
esac
