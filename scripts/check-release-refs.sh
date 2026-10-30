#!/usr/bin/env bash
# Checks what a release's tree must hold: every reusable workflow calls
# factory's own workflows and action at VERSION, and defaults
# factory-version to VERSION, so a caller pinning app.yml (or any of them)
# at the release gets that release's workflows and binary, never main's.
# scripts/release.sh runs it after moving the refs; release.yml runs it on
# the tagged tree, and fails the release if it fails.
#
# Usage: scripts/check-release-refs.sh vX.Y.Z
set -euo pipefail
version=${1:?usage: scripts/check-release-refs.sh vX.Y.Z}
cd "$(dirname "$0")/.."
status=0
for f in .github/workflows/*.yml; do
  awk -v v="$version" -v f="$f" '
    # A call (uses:, not a comment) of factory, a workflow or the action.
    /^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*northcutted\/clearcutt-factory[\/@]/ {
      ref = $0; sub(/^[^@]*@/, "", ref); sub(/[[:space:]].*$/, "", ref)
      what = $0; sub(/^.*uses:[[:space:]]*/, "", what); sub(/@.*$/, "", what)
      if (ref != v) { printf "%s:%d: calls %s at %s, not %s\n", f, NR, what, ref, v; bad = 1 }
    }
    # factory-version defaults (the only version-shaped input defaults).
    /^[[:space:]]+default:[[:space:]]*v[0-9]/ {
      d = $2
      if (d != v) { printf "%s:%d: defaults to %s, not %s\n", f, NR, d, v; bad = 1 }
    }
    END { exit bad }' "$f" || status=1
done
if [ "$status" != 0 ]; then
  echo "the workflows above don't all name $version" >&2
fi
exit "$status"
