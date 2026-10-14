#!/bin/sh
# Before removing the package. The queue, database, and config are kept.
set -e
if [ -d /run/systemd/system ]; then
  case "$1" in
    remove|0) systemctl disable --now sovite.service sovite.socket || true ;;
  esac
fi
