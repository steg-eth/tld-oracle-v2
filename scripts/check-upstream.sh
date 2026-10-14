#!/usr/bin/env bash
# Compare each pin in reference/UPSTREAM.lock with the live ref upstream.
# Read-only. Exit 1 when any pin has moved or its ref is gone.
set -euo pipefail
lock="$(cd "$(dirname "$0")/.." && pwd)/reference/UPSTREAM.lock"
status=0
while IFS=$'\t' read -r repo ref sha mirror note; do
  [[ -z "$repo" || "$repo" == \#* ]] && continue
  live=$(git ls-remote "https://github.com/$repo" "$ref" "$ref^{}" 2>/dev/null | cut -f1 | tr '\n' ' ')
  if [[ -z "${live// /}" ]]; then
    printf 'GONE       %-26s %-22s pinned %s  %s\n' "$repo" "$ref" "${sha:0:8}" "$note"; status=1
  elif [[ "$live" == *"$sha"* ]]; then
    printf 'unchanged  %-26s %-22s %s\n' "$repo" "$ref" "${sha:0:8}"
  else
    printf 'MOVED      %-26s %-22s pinned %s, live %s  %s\n' "$repo" "$ref" "${sha:0:8}" "${live:0:8}" "$note"; status=1
  fi
done < "$lock"
exit $status
