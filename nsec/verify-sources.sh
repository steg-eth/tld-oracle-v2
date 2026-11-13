#!/bin/sh
# Verify a build tree's dnssec-oracle sources against upstream at the pinned commit.
# Usage: ./verify-sources.sh <dir containing contracts/dnssec-oracle/...>
# Exit 0 means every file matches. Anything else means do not trust that tree's tests.
set -e
LOCK="$(dirname "$0")/UPSTREAM-SOURCES.lock"
ROOT="${1:?usage: verify-sources.sh <tree-root>}"
fail=0; ok=0
while read -r want path; do
  case "$want" in \#*|"") continue;; esac
  f="$ROOT/$path"
  if [ ! -f "$f" ]; then echo "MISSING  $path"; fail=$((fail+1)); continue; fi
  got=$(shasum -a 256 "$f" | cut -d' ' -f1)
  if [ "$got" = "$want" ]; then ok=$((ok+1)); else echo "DIFFERS  $path"; fail=$((fail+1)); fi
done < "$LOCK"
echo "$ok match, $fail bad"
[ "$fail" -eq 0 ]
