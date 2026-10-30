#!/usr/bin/env bash
# Runs scripts/release.sh in a copy of a small repository and checks what
# it commits and tags: the reusable workflows call factory's own at the new
# tag (app.yml's @main included), and default factory-version to it; a ref
# the rewrite misses (a branch, a ref with a comment after it) fails the
# release before anything is committed or tagged. scripts/check-release-refs.sh,
# which release.yml also runs on the tagged tree, is checked on its own too.
#
# Usage: .github/scripts/release_test.sh (needs bash, git, and perl)
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# go stands in for the toolchain (release.sh runs init's tests).
mkdir -p "$tmp/bin"
printf '#!/bin/sh\nexit 0\n' > "$tmp/bin/go"
chmod +x "$tmp/bin/go"
export PATH="$tmp/bin:$PATH"

# repo DIR APP_YML: a repository with release.sh, app.yml as given, and
# images.yml calling the action, committed.
repo() {
  local dir=$1
  mkdir -p "$dir/scripts" "$dir/.github/workflows" "$dir/docs"
  cp "$root/scripts/release.sh" "$root/scripts/check-release-refs.sh" "$dir/scripts/"
  printf '# Changelog\n\n## v0.9.0\n\n- the release\n' > "$dir/CHANGELOG.md"
  printf '%s\n' "$2" > "$dir/.github/workflows/app.yml"
  cat > "$dir/.github/workflows/images.yml" <<'YML'
on:
  workflow_call:
    inputs:
      factory-version:
        type: string
        default: v0.8.0
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: northcutted/clearcutt-factory@v0.8.0
YML
  printf -- '- uses: northcutted/clearcutt-factory@v0.8.0\n' > "$dir/action.yml"
  printf 'v=v0.8.0 sh install.sh\n' > "$dir/README.md"
  printf 'uses: northcutted/clearcutt-factory/.github/workflows/app.yml@v0.8.0\n' > "$dir/docs/adopting.md"
  git -C "$dir" init -q -b main
  git -C "$dir" add -A
  GIT_CONFIG_GLOBAL=/dev/null git -C "$dir" -c user.name=t -c user.email=t@example.com commit -q -m init
}
app() { # the ref each of app.yml's two calls ends with
  printf 'on: {workflow_call: {inputs: {factory-version: {type: string, default: v0.8.0}}}}\njobs:\n  images:\n    uses: northcutted/clearcutt-factory/.github/workflows/images.yml@%s\n  fleet:\n    uses: northcutted/clearcutt-factory/.github/workflows/fleet.yml@%s\n' "$1" "$2"
}
release() { # dir: runs release.sh v0.9.0 there, as a user would (without their git config)
  (cd "$1" && GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com \
    GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com scripts/release.sh v0.9.0) > "$1.log" 2>&1
}

fail=0
# From main, and from the last release: the release names v0.9.0 everywhere.
for from in "main main" "v0.8.0 v0.8.0"; do
  # shellcheck disable=SC2086
  repo "$tmp/ok" "$(app $from)"
  if ! release "$tmp/ok"; then
    echo "FAIL: release from $from failed"; cat "$tmp/ok.log"; fail=1
  elif ! git -C "$tmp/ok" rev-parse -q --verify refs/tags/v0.9.0 > /dev/null; then
    echo "FAIL: release from $from: no tag"; fail=1
  else
    got=$(git -C "$tmp/ok" show v0.9.0:.github/workflows/app.yml | grep -c '@v0\.9\.0$' || true)
    if [ "$got" != 2 ] || git -C "$tmp/ok" show v0.9.0:.github/workflows/images.yml | grep -q 'v0\.8\.0'; then
      echo "FAIL: release from $from: the tagged workflows don't all name v0.9.0"
      git -C "$tmp/ok" show v0.9.0:.github/workflows/app.yml v0.9.0:.github/workflows/images.yml; fail=1
    fi
    if ! (cd "$tmp/ok" && scripts/check-release-refs.sh v0.9.0 > /dev/null); then
      echo "FAIL: release from $from: check-release-refs refuses the tagged tree"; fail=1
    fi
  fi
  rm -rf "$tmp/ok" "$tmp/ok.log"
done

# A ref the rewrite misses: nothing committed or tagged.
for refs in "main main # pinned" "feature/x v0.8.0" "v0.8.0 0123456789abcdef0123456789abcdef01234567"; do
  repo "$tmp/bad" "$(app "${refs%% *}" "${refs#* }")"
  head=$(git -C "$tmp/bad" rev-parse HEAD)
  if release "$tmp/bad"; then
    echo "FAIL: release with app.yml at '$refs' passed"; cat "$tmp/bad.log"; fail=1
  fi
  if git -C "$tmp/bad" rev-parse -q --verify refs/tags/v0.9.0 > /dev/null || [ "$(git -C "$tmp/bad" rev-parse HEAD)" != "$head" ]; then
    echo "FAIL: release with app.yml at '$refs': committed or tagged anyway"; fail=1
  fi
  if ! grep -q 'app.yml:.*not v0.9.0' "$tmp/bad.log"; then
    echo "FAIL: release with app.yml at '$refs': the offending ref isn't named"; cat "$tmp/bad.log"; fail=1
  fi
  rm -rf "$tmp/bad" "$tmp/bad.log"
done

# check-release-refs on this repository: between releases app.yml calls
# main, which a release tag must not.
if (cd "$root" && scripts/check-release-refs.sh v0.0.0-never > /dev/null 2>&1); then
  echo "FAIL: check-release-refs accepts this tree for a version it doesn't name"; fail=1
fi

if [ "$fail" = 0 ]; then
  echo "release: ok"
fi
exit "$fail"
