#!/usr/bin/env bash
# Runs app.yml's "What this event runs" step, as the workflow has it, for
# each event, and checks which of factory's workflows it runs: images on
# pull requests and pushes (and the fleet after a push), the full lock
# update on the weekly schedule, the fleet, the stack update, and the
# rescan on the daily one, each ClearCutt dispatch its own, a manual run
# what it names; and that auto-merge reaches each workflow in its own kinds.
#
# Usage: .github/scripts/app-plan_test.sh (needs bash, jq, and yq v4)
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
yq -e '.jobs.plan.steps[] | select(.name == "What this event runs") | .run' "$root/.github/workflows/app.yml" > "$tmp/step.sh"

fail=0
# event|payload (JSON)|run input|reattest|auto-merge|want: images fleet update reattest fleet-auto-merge locks-auto-merge (or "error")
while IFS='|' read -r event payload run reattest merge want; do
  printf '%s' "$payload" > "$tmp/event.json"
  : > "$tmp/output"
  if GITHUB_EVENT_NAME=$event GITHUB_EVENT_PATH=$tmp/event.json GITHUB_OUTPUT=$tmp/output \
    WEEKLY="23 6 * * 1" RUN=$run REATTEST=$reattest AUTO_MERGE=$merge \
    bash --noprofile --norc -eo pipefail "$tmp/step.sh" > /dev/null 2>&1; then
    got=$(for k in images fleet update reattest fleet-auto-merge locks-auto-merge; do
      v=$(sed -n "s/^$k=//p" "$tmp/output"); printf '%s ' "${v:--}"; done)
    got=${got% }
  else
    got=error
  fi
  if [ "$got" != "$want" ]; then
    echo "FAIL: $event $payload run='$run' auto-merge='$merge': got '$got', want '$want'"
    fail=1
  fi
done <<'CASES'
pull_request|{}||true||true false - false - -
merge_group|{}||true||true false - false - -
push|{}||true||true true - false - -
schedule|{"schedule": "23 6 * * 1"}||true||false false all false - -
schedule|{"schedule": "41 5 * * *"}||true||false true stack true - -
schedule|{"schedule": "41 5 * * *"}||false||false true stack false - -
repository_dispatch|{"action": "clearcutt.run-image-published"}||true||false true - false - -
repository_dispatch|{"action": "clearcutt.build-image-published"}||true||false false stack false - -
repository_dispatch|{"action": "clearcutt.stack-published"}||true||false false stack false - -
repository_dispatch|{"action": "clearcutt.profile-published"}||true||false false all false - -
repository_dispatch|{"action": "something-else"}||true||false false - false - -
workflow_dispatch|{}||true||true true all false - -
workflow_dispatch|{"inputs": {"run": "fleet"}}||true||false true - false - -
workflow_dispatch|{"inputs": {"run": "fleet"}}|reattest|true||false false - true - -
workflow_dispatch|{}|images,update-locks|true||true false all false - -
workflow_dispatch|{}|everything|true||error
workflow_run|{}||true||false false - false - -
push|{}||true|pin update|true true - false pin update
push|{}||true|rebuild|true true - false rebuild rebuild
push|{}||true|all|true true - false all all
push|{}||true|pin rebuild update|true true - false pin rebuild rebuild update
push|{}||true|merge|error
CASES
if [ "$fail" = 0 ]; then
  echo "app-plan: ok"
fi
exit "$fail"
