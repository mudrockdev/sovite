#!/bin/sh
# Enforces the dependency rules from STRUCTURE.md §3:
# reusable components (lib/<component>/) must never reference Sovite.Core.
set -eu
cd "$(dirname "$0")/.."

violations=$(grep -rnE '\bSovite\.Core\b|alias Sovite\.\{[^}]*\bCore\b' lib --include='*.ex' \
  | grep -v '^lib/core/' | grep -v '^lib/sovite\.ex:' || true)

if [ -n "$violations" ]; then
  echo "Reusable components must not depend on Sovite.Core:" >&2
  echo "$violations" >&2
  exit 1
fi

echo "Boundaries OK"
