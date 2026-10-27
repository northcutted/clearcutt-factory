#!/usr/bin/env bash
# Runs the "Publish from this ref?" step of images.yml, fleet.yml,
# update-locks.yml, and reattest.yml, as the workflows have them, for each event and ref, and
# checks that only the default branch (and the publish-ref input's ref)
# publishes (#4). The copies must be the same.
#
# Usage: .github/scripts/publish-ref_test.sh (needs bash, jq, and yq v4)
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for wf in images:manifests fleet:apps update-locks:manifests reattest:manifests; do
  yq -e ".jobs.${wf#*:}.steps[] | select(.name == \"Publish from this ref?\") | .run" "$root/.github/workflows/${wf%:*}.yml" > "$tmp/${wf%:*}.sh"
done
cmp "$tmp/images.sh" "$tmp/fleet.sh"
cmp "$tmp/images.sh" "$tmp/update-locks.sh"
cmp "$tmp/images.sh" "$tmp/reattest.sh"

fail=0
# event ref default-branch publish-ref want
while IFS='|' read -r event ref default publish_ref want; do
  if [ -n "$default" ]; then
    jq -n --arg d "$default" '{repository: {default_branch: $d}}' > "$tmp/event.json"
  else
    echo '{"schedule": "41 5 * * *"}' > "$tmp/event.json"
  fi
  : > "$tmp/output"
  GITHUB_EVENT_NAME=$event GITHUB_REF=$ref GITHUB_EVENT_PATH=$tmp/event.json GITHUB_OUTPUT=$tmp/output PUBLISH_REF=$publish_ref \
    bash -e "$tmp/images.sh" > /dev/null
  got=$(sed -n 's/^publish=//p' "$tmp/output")
  if [ "$got" != "$want" ]; then
    echo "FAIL: $event $ref (default ${default:-none}, publish-ref '${publish_ref}'): publish=$got, want $want"
    fail=1
  fi
done <<'CASES'
push|refs/heads/main|main||true
workflow_dispatch|refs/heads/main|main||true
workflow_dispatch|refs/heads/feature|main||false
push|refs/heads/feature|main||false
push|refs/heads/main|trunk||false
push|refs/tags/v1.0.0|main||false
push|refs/tags/v1.0.0|main|refs/tags/v1.0.0|true
workflow_dispatch|refs/heads/release/1.x|main|refs/heads/release/*|true
workflow_dispatch|refs/heads/release-evil|main|refs/heads/release|false
workflow_dispatch|refs/heads/release|main|refs/heads/release|true
pull_request|refs/pull/7/merge|main||false
pull_request|refs/pull/7/merge|main|*|false
pull_request_target|refs/heads/main|main||false
merge_group|refs/heads/gh-readonly-queue/main/pr-7|main||false
schedule|refs/heads/main|||true
repository_dispatch|refs/heads/main|main||true
workflow_run|refs/heads/main|main||true
repository_dispatch|refs/heads/main|||true
CASES
if [ "$fail" = 0 ]; then
  echo "publish-ref: ok"
fi
exit "$fail"
