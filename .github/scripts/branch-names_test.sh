#!/usr/bin/env bash
# Runs the pull request steps of update-locks.yml and fleet.yml, as the
# workflows have them, with open-pr.sh stubbed, and checks the branch, title,
# and paths each manifest gets: valid branch names for manifests at the
# repository root (#51), and only those manifests' own files.
#
# Usage: .github/scripts/branch-names_test.sh (needs bash, git, and yq v4)
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

step() { # workflow job step-name
  yq -e ".jobs.$2.steps[] | select(.name == \"$3\") | .run" "$root/.github/workflows/$1" > "$tmp/$2.sh"
}
step update-locks.yml update "Open, update, or close the pull request"
step fleet.yml rebase "Pin the lock to the same base"

mkdir -p "$tmp/factory/.github/scripts"
cat > "$tmp/factory/.github/scripts/open-pr.sh" <<'EOF'
#!/usr/bin/env bash
branch=$1 title=$2
shift 3
printf '%s|%s|%s\n' "$branch" "$title" "$*" > "$OPEN_PR_CALL"
EOF
chmod +x "$tmp/factory/.github/scripts/open-pr.sh"

repo=$tmp/repo
mkdir -p "$repo/examples/hello-app" "$repo/.config" "$repo/my apps/web"
touch "$repo/app.yaml" "$repo/app.lock.yaml" "$repo/app.Containerfile" "$repo/image.yaml" "$repo/image.lock.yaml" \
  "$repo/examples/hello-app/app.yaml" "$repo/.config/app.yaml" "$repo/my apps/web/app.yaml"
git -C "$repo" init -q
git -C "$repo" add -A
git -C "$repo" -c user.name=t -c user.email=t@example.com commit -qm init
# What the jobs leave in the checkout besides the lock: out/ and the
# factory's own checkout (for callers).
mkdir -p "$repo/out/app-rebase" "$repo/.clearcutt-factory"
touch "$repo/out/app-rebase/result.json" "$repo/.clearcutt-factory/action.yml"
echo "  base: moved" > "$tmp/lock.out"
echo "rebased" > "$tmp/rebase.out"

failures=0
# run job manifest [failed]: prints the open-pr.sh call (branch|title|paths), or nothing.
run() {
  rm -f "$tmp/call"
  (cd "$repo" && env MANIFEST="$2" APP="$2" FAILED="${3:-false}" REPEAT=success IMAGE=r@sha256:x RUN_URL=u \
    RUNNER_TEMP="$tmp" FACTORY_DIR="$tmp/factory" OPEN_PR_CALL="$tmp/call" bash --noprofile --norc -eo pipefail "$tmp/$1.sh" > /dev/null)
  if [ -f "$tmp/call" ]; then cat "$tmp/call"; fi
}
check() { # job manifest want [failed]
  local got branch
  got=$(run "$1" "$2" "${4:-}")
  if [ "$got" != "$3" ]; then
    echo "FAIL $1 $2: got '$got', want '$3'"
    failures=$((failures + 1))
    return
  fi
  branch=${got%%|*}
  if [ -n "$branch" ] && ! git -C "$repo" check-ref-format --branch "$branch" > /dev/null 2>&1; then
    echo "FAIL $1 $2: $branch is not a valid branch name"
    failures=$((failures + 1))
    return
  fi
  echo "ok   $1 $2${4:+ (failed=$4)}: ${got:-no pull request}"
}

check update app.yaml "factory/update/root-app|Update the pinned inputs of app.yaml|app.yaml app.lock.yaml app.Containerfile"
check update ./image.yaml "factory/update/root-image|Update the pinned inputs of image.yaml|image.yaml image.lock.yaml"
check update examples/hello-app/app.yaml "factory/update/examples-hello-app|Update the pinned inputs of examples/hello-app|examples/hello-app"
check update ./examples/hello-app/app.yaml "factory/update/examples-hello-app|Update the pinned inputs of examples/hello-app|examples/hello-app"
check update .config/app.yaml "factory/update/config|Update the pinned inputs of .config|.config"
check update "my apps/web/app.yaml" "factory/update/my-apps-web|Update the pinned inputs of my apps/web|my apps/web"
check rebase app.yaml "factory/rebase/root-app|Pin app.yaml to the newest run image|app.yaml app.lock.yaml app.Containerfile"
check rebase ./app.yaml "factory/rebase/root-app|Pin app.yaml to the newest run image|app.yaml app.lock.yaml app.Containerfile"
check rebase examples/hello-app/app.yaml "factory/rebase/examples-hello-app|Pin examples/hello-app to the newest run image|examples/hello-app"
# A failed rebase that left the lock alone keeps any pull request: out/ and
# .clearcutt-factory/ at the root don't count as changes to a root app.
check rebase app.yaml "" true
echo "  base: moved" >> "$repo/app.lock.yaml"
check rebase app.yaml "factory/rebase/root-app|Pin app.yaml to the newest run image|app.yaml app.lock.yaml app.Containerfile" true

if [ "$failures" -gt 0 ]; then
  echo "$failures failed"
  exit 1
fi
