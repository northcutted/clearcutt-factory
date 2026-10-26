#!/usr/bin/env bash
# Runs the "What to announce" step of notify.yml, as the workflow has it, on
# a published array and checks which repository_dispatch events it sends,
# with what payload: a build image (roles has build) gets
# clearcutt.build-image-published, a run image (roles has run) or one no
# stack names (no roles, as older images.yml outputs have)
# clearcutt.run-image-published, an image that is both gets both; a stack
# and a profile get their own; an app, or an entry without a digest, nothing.
#
# Usage: .github/scripts/notify-events_test.sh (needs bash, jq, and yq v4)
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

yq -e '.jobs.notify.steps[] | select(.name == "What to announce") | .run' "$root/.github/workflows/notify.yml" > "$tmp/step.sh"

published='[
  {"manifest": "images/build-go/image.yaml", "kind": "image", "image": "r/build-go@sha256:b", "repository": "r/build-go", "digest": "sha256:b", "tags": ["1"], "roles": ["build"]},
  {"manifest": "images/run-go/image.yaml", "kind": "image", "image": "r/run-go@sha256:r", "repository": "r/run-go", "digest": "sha256:r", "tags": ["1", "latest"], "roles": ["run"]},
  {"manifest": "images/both/image.yaml", "kind": "image", "image": "r/both@sha256:2", "repository": "r/both", "digest": "sha256:2", "tags": [], "roles": ["Build", "run"]},
  {"manifest": "images/tools/image.yaml", "kind": "image", "image": "r/tools@sha256:t", "repository": "r/tools", "digest": "sha256:t", "tags": ["latest"], "roles": []},
  {"manifest": "images/old/image.yaml", "kind": "Image", "image": "r/old@sha256:o", "digest": "sha256:o"},
  {"manifest": "apps/svc/app.yaml", "kind": "app", "image": "r/svc@sha256:a", "repository": "r/svc", "digest": "sha256:a", "tags": ["latest"], "roles": []},
  {"kind": "stack", "image": "r/stacks/go@sha256:s", "repository": "r/stacks/go", "digest": "sha256:s", "tags": ["1"]},
  {"kind": "profile", "image": "r/profile@sha256:p", "digest": "sha256:p"},
  {"kind": "image", "image": "r/none", "repository": "r/none", "roles": ["build"]}
]'
: > "$tmp/output"
PUBLISHED=$published RUNNER_TEMP=$tmp GITHUB_REPOSITORY=acme/platform GITHUB_OUTPUT=$tmp/output \
  bash --noprofile --norc -eo pipefail "$tmp/step.sh" > /dev/null
got=$(jq -r '[.event_type, .client_payload.image, .client_payload.repository, .client_payload.digest, (.client_payload.tags | join(",")), (.client_payload.roles // ["-"] | join(",")), .client_payload.source] | join(" ")' "$tmp/events")
want='clearcutt.build-image-published r/build-go@sha256:b r/build-go sha256:b 1 build acme/platform
clearcutt.run-image-published r/run-go@sha256:r r/run-go sha256:r 1,latest run acme/platform
clearcutt.build-image-published r/both@sha256:2 r/both sha256:2  build,run acme/platform
clearcutt.run-image-published r/both@sha256:2 r/both sha256:2  build,run acme/platform
clearcutt.run-image-published r/tools@sha256:t r/tools sha256:t latest  acme/platform
clearcutt.run-image-published r/old@sha256:o r/old sha256:o   acme/platform
clearcutt.stack-published r/stacks/go@sha256:s r/stacks/go sha256:s 1 - acme/platform
clearcutt.profile-published r/profile@sha256:p r/profile sha256:p  - acme/platform'
fail=0
if [ "$got" != "$want" ]; then
  echo "FAIL: events differ"
  diff <(echo "$want") <(echo "$got") || true
  fail=1
fi
if ! grep -qx 'any=true' "$tmp/output"; then
  echo "FAIL: any=true not written"
  fail=1
fi
# Each line is a complete dispatch body.
if ! jq -s -e 'length > 0 and all(has("event_type") and (.client_payload | has("image") and has("digest") and has("source")))' "$tmp/events" > /dev/null; then
  echo "FAIL: a dispatch body lacks a field"
  fail=1
fi

# Nothing to announce: no any=true, no events.
: > "$tmp/output"
PUBLISHED='[{"kind": "app", "image": "r/svc@sha256:a", "digest": "sha256:a"}]' RUNNER_TEMP=$tmp GITHUB_REPOSITORY=acme/platform GITHUB_OUTPUT=$tmp/output \
  bash --noprofile --norc -eo pipefail "$tmp/step.sh" > /dev/null
if [ -s "$tmp/events" ] || grep -q 'any=' "$tmp/output"; then
  echo "FAIL: an app alone was announced"
  fail=1
fi
if [ "$fail" = 0 ]; then
  echo "notify-events: ok"
fi
exit "$fail"
