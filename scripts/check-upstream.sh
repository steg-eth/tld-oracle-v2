#!/usr/bin/env bash
# Compare each pin in reference/UPSTREAM.lock with the live ref upstream.
# Read-only. Exit 1 when a pin has moved, its ref is gone, or a pinned pull
# request was closed without a merge.
#
# A pull request keeps its head ref after it closes, so the sha comparison
# alone cannot see a dead pin. Rows of the form refs/pull/<n>/head get a state
# check through `gh`. The check is skipped when `gh` is not installed.
set -euo pipefail
lock="$(cd "$(dirname "$0")/.." && pwd)/reference/UPSTREAM.lock"
status=0

pr_state() { # repo ref -> OPEN | CLOSED | MERGED, or empty when unavailable
  local repo=$1 ref=$2 n
  [[ $ref =~ ^refs/pull/([0-9]+)/head$ ]] || return 0
  command -v gh >/dev/null 2>&1 || return 0
  n=${BASH_REMATCH[1]}
  gh pr view "$n" --repo "$repo" --json state --jq .state 2>/dev/null || true
}

while IFS=$'\t' read -r repo ref sha mirror note; do
  [[ -z "$repo" || "$repo" == \#* ]] && continue
  live=$(git ls-remote "https://github.com/$repo" "$ref" "$ref^{}" 2>/dev/null | cut -f1 | tr '\n' ' ')
  state=$(pr_state "$repo" "$ref")
  tag=${state:+" [$state]"}
  if [[ -z "${live// /}" ]]; then
    printf 'GONE       %-26s %-22s pinned %s%s  %s\n' "$repo" "$ref" "${sha:0:8}" "$tag" "$note"; status=1
  elif [[ "$live" == *"$sha"* ]]; then
    printf 'unchanged  %-26s %-22s %s%s\n' "$repo" "$ref" "${sha:0:8}" "$tag"
  else
    printf 'MOVED      %-26s %-22s pinned %s, live %s%s  %s\n' "$repo" "$ref" "${sha:0:8}" "${live:0:8}" "$tag" "$note"; status=1
  fi
  if [[ "$state" == CLOSED ]]; then
    printf 'CLOSED     %-26s %-22s the pinned pull request closed without a merge  %s\n' "$repo" "$ref" "$note"; status=1
  fi
done < "$lock"
exit $status
