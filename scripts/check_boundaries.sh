#!/bin/sh
# Enforces the dependency rules from STRUCTURE.md §3:
#
#   1. Reusable components (lib/<component>/) never reference Sovite.Core.
#   2. The parts of the stack (lib/core/mta/, lib/core/filter/,
#      lib/core/mailbox/) never reference each other: they meet only
#      through the shared interfaces in Sovite.Core.Stack.
#   3. Each table belongs to one part, or is shared. Only that part uses
#      a part's table modules, besides the database code itself
#      (lib/core/repo/) and the operator surfaces of every part:
#      sovitectl (lib/core/cli*) and the admin API (lib/core/web/).
set -eu
cd "$(dirname "$0")/.."

status=0

report() {
  if [ -n "$2" ]; then
    echo "$1" >&2
    echo "$2" >&2
    status=1
  fi
}

# 1. Components.
violations=$(grep -rnE '\bSovite\.Core\b|alias Sovite\.\{[^}]*\bCore\b' lib --include='*.ex' \
  | grep -v '^lib/core/' | grep -v '^lib/sovite\.ex:' || true)
report "Reusable components must not depend on Sovite.Core:" "$violations"

# 2. Parts.
for part in mta:MTA filter:Filter mailbox:Mailbox; do
  dir=${part%%:*}
  for other in MTA Filter Mailbox; do
    [ "$other" = "${part#*:}" ] && continue
    [ -d "lib/core/$dir" ] || continue
    violations=$(grep -rnE "\bSovite\.Core\.$other\b|alias Sovite\.Core\.\{[^}]*\b$other\b" \
      "lib/core/$dir" --include='*.ex' || true)
    report "lib/core/$dir/ must not use the $other part (go through Sovite.Core.Stack):" "$violations"
  done
done

# 3. Tables. A table that is not listed is shared.
mta_tables="AccessRules AddressRewrites Aliases BccRules DMARCReportEntries GreylistEntries
IPAddressCounts MTASTSPolicies RelocatedUsers SenderRelays TLSReportEntries Transports"
filter_tables="FilterThresholds"
mailbox_tables="Mailboxes Users"

# The files outside the owner that use a table module. Each file is read
# as one line, so grouped aliases over several lines are found too.
table_users() {
  find lib -name '*.ex' | sort | grep -v "^lib/core/$1/" | grep -v '^lib/core/repo/' \
    | grep -v '^lib/core/cli' | grep -v '^lib/core/web/' | while read -r file; do
      if tr '\n' ' ' <"$file" | grep -qE "\bTables\.($2\b|\{[^}]*\b$2\b)"; then
        echo "  $file"
      fi
    done
}

check_tables() {
  dir=$1
  shift
  for table in "$@"; do
    report "The $table table belongs to lib/core/$dir/, but these use it:" "$(table_users "$dir" "$table")"
  done
}

# shellcheck disable=SC2086
check_tables mta $mta_tables
# shellcheck disable=SC2086
check_tables filter $filter_tables
# shellcheck disable=SC2086
check_tables mailbox $mailbox_tables

[ "$status" -eq 0 ] && echo "Boundaries OK"
exit "$status"
