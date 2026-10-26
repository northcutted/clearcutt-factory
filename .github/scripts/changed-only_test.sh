#!/usr/bin/env bash
# Runs images.yml's "Find the manifests" step, as the workflow has it, in a
# git repository whose HEAD is a pull request's merge commit (first parent
# the base branch, as GitHub makes it), with clearcutt-factory built from
# this source, and checks which manifests a pull request builds under
# changed-only: those its changes affect, every one when it changes a file
# no manifest owns or when that can't be told, none when it only deletes
# such a file; and every one without changed-only.
#
# Usage: .github/scripts/changed-only_test.sh (needs bash, git, go, jq, and yq v4)
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

yq -e '.jobs.manifests.steps[] | select(.name == "Find the manifests") | .run' "$root/.github/workflows/images.yml" > "$tmp/find.sh"
mkdir -p "$tmp/bin" "$tmp/old"
(cd "$root" && go build -o "$tmp/bin/clearcutt-factory" ./cmd/clearcutt-factory)
# A release without affected: an unknown command is a usage error.
printf '#!/bin/sh\necho "error: unknown command \\"$1\\"" >&2\nexit 2\n' > "$tmp/old/clearcutt-factory"
chmod +x "$tmp/old/clearcutt-factory"

repo=$tmp/repo
image() { printf 'apiVersion: factory.clearcutt.dev/v1alpha1\nkind: Image\nmetadata: {name: %s}\nspec: {base: cgr.dev/chainguard/wolfi-base:latest}\n' "$1"; }
git init -q -b main "$repo"
cd "$repo"
git config user.email test@example.com
git config user.name test
printf 'apiVersion: factory.clearcutt.dev/v1alpha1\nkind: OrgProfile\nregistry: r.example/p\nsigning: {mode: none}\n' > factory.org.yaml
for n in a b c; do
  mkdir -p "images/$n"
  image "$n" > "images/$n/image.yaml"
  echo lock > "images/$n/image.lock.yaml"
done
echo readme > README.md
echo stray > stray.txt
git add -A
git commit -q -m base

# pr BRANCH COMMANDS: a pull request branch from main that runs COMMANDS,
# and the merge commit GitHub would test, checked out detached.
pr() {
  git checkout -q -B "$1" main
  eval "$2"
  git add -A
  git commit -q -m "$1"
  git checkout -q --detach main
  git merge -q --no-ff -m "Merge $1 into main" "$1"
}

fail=0
# check NAME CHANGED_ONLY PATH WANT [PUBLISHED]: run the step and compare
# its manifests output with WANT (a JSON array).
check() {
  : > "$tmp/output"
  if ! PATH="$3:$PATH" GITHUB_OUTPUT=$tmp/output RUNNER_TEMP=$tmp CHANGED_ONLY=$2 MANIFESTS='images/*/image.yaml' PUBLISHED=${5:-} \
    bash -e "$tmp/find.sh" > "$tmp/log" 2>&1; then
    echo "FAIL: $1: the step failed:"
    cat "$tmp/log"
    fail=1
    return
  fi
  got=$(sed -n 's/^manifests=//p' "$tmp/output")
  if [ "$got" != "$4" ]; then
    echo "FAIL: $1: manifests=$got, want $4"
    cat "$tmp/log"
    fail=1
  fi
}
all='["images/a/image.yaml","images/b/image.yaml","images/c/image.yaml"]'

pr lock 'echo new > images/a/image.lock.yaml'
check "a lock" true "$tmp/bin" '["images/a/image.yaml"]'
check "a lock, changed-only off" false "$tmp/bin" "$all"
check "a lock, changed-only empty (not a workflow_call)" "" "$tmp/bin" "$all"
check "a lock, a release without affected" true "$tmp/old" "$all"
grep -q '::warning::changed-only: could not tell' "$tmp/log" || { echo "FAIL: no warning for a release without affected"; fail=1; }
check "reproducing what was published" true "$tmp/bin" '["images/b/image.yaml"]' '[{"manifest":"images/b/image.yaml"}]'

pr two 'echo new > images/b/image.lock.yaml; git mv images/c/image.lock.yaml images/a/moved.yaml'
check "two images and a rename between them" true "$tmp/bin" "$all"
pr readme 'echo new > README.md'
check "a file no manifest owns" true "$tmp/bin" "$all"
grep -q 'README.md changed, which no manifest owns' "$tmp/log" || { echo "FAIL: the file that made it every manifest is not named"; fail=1; }
pr org 'echo "# x" >> factory.org.yaml'
check "the org profile" true "$tmp/bin" "$all"
pr gone 'git rm -q stray.txt'
check "a deleted file no manifest owns" true "$tmp/bin" '[]'
pr gone-image 'git rm -q -r images/c; echo new > images/b/image.lock.yaml'
check "a deleted image and a lock" true "$tmp/bin" '["images/b/image.yaml"]'

git checkout -q --detach lock
check "not a merge commit" true "$tmp/bin" "$all"
grep -q "is not the pull request's merge commit" "$tmp/log" || { echo "FAIL: no warning without a merge commit"; fail=1; }

if [ "$fail" = 0 ]; then
  echo "changed-only: ok"
fi
exit "$fail"
