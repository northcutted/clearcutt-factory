#!/usr/bin/env bash
# Runs open-pr.sh in a repository with a bare remote and a stub gh, and
# checks that it opens a pull request with the changed files, updates an
# open one, closes it when nothing is left to change, and turns on
# auto-merge only for the kinds AUTO_MERGE lists (and off for any other),
# warning (not failing) when GitHub refuses.
#
# Usage: .github/scripts/open-pr_test.sh (needs bash and git)
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# gh: logs every call; GH_STATE is the pull request's state (OPEN or none),
# GH_AUTO_ON says it already has auto-merge, GH_MERGE_FAILS makes the
# enablePullRequestAutoMerge mutation fail with that message, and "gh pr
# merge" (which merges at once a pull request already mergeable) fails the
# test.
mkdir -p "$tmp/bin"
cat > "$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
case "$1 $2 ${5:-}" in
  "pr view state"*) [ "${GH_STATE:-}" = OPEN ] && echo OPEN || exit 1 ;;
  "pr view id,autoMergeRequest"*) echo "PR_kwID ${GH_AUTO_ON:-false}" ;;
  "pr merge"*) echo "gh pr merge called" >&2; exit 3 ;;
  "pr create"*) case "$*" in *--label*) [ "${GH_LABEL_FAILS:-}" != true ] || exit 1 ;; esac ;;
  "api graphql"*)
    case "$*" in *enablePullRequestAutoMerge*) if [ -n "${GH_MERGE_FAILS:-}" ]; then echo "$GH_MERGE_FAILS" >&2; exit 1; fi ;; esac
    case "$*" in *"id=PR_kwID"*) ;; *) echo "no pull request id" >&2; exit 1 ;; esac
    echo '{}'
    ;;
esac
STUB
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" GH_LOG="$tmp/gh.log"

git init -q --bare "$tmp/remote"
repo=$tmp/repo
git init -q -b main "$repo"
git -C "$repo" remote add origin "$tmp/remote"
mkdir -p "$repo/apps/web"
echo a > "$repo/apps/web/app.lock.yaml"; echo b > "$repo/other.txt"
git -C "$repo" add -A
git -C "$repo" -c user.name=t -c user.email=t@example.com commit -qm init
git -C "$repo" push -q origin HEAD:main
echo body > "$tmp/body.md"

failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
# change: the lock moves (a new value each time: open-pr.sh commits the
# previous one onto the branch).
n=0
change() { n=$((n + 1)); echo "moved $n" > "$repo/apps/web/app.lock.yaml"; }
# run [env…]: open-pr.sh for apps/web on branch factory/update/apps-web,
# stdout+stderr in $tmp/out; then back to main, as a fresh job would be.
run() {
  : > "$GH_LOG"
  local rc=0
  (cd "$repo" && env "$@" bash "$root/.github/scripts/open-pr.sh" factory/update/apps-web "Update apps/web" "$tmp/body.md" apps/web > "$tmp/out" 2>&1) || rc=$?
  git -C "$repo" switch -q --detach main
  return "$rc"
}
calls() { grep -c "^pr $1 " "$GH_LOG" || true; }
# mutations NAME: how many times the GraphQL mutation NAME ran.
mutations() { grep -c "^api graphql .*$1" "$GH_LOG" || true; }

# Nothing changed: no pull request, nothing pushed.
run X=1
if [ "$(calls create)" != 0 ] || ! grep -q "nothing to propose" "$tmp/out"; then fail "unchanged: $(cat "$tmp/out")"; fi
# Nothing changed and a pull request is open: closed.
run GH_STATE=OPEN
if [ "$(calls close)" != 1 ]; then fail "unchanged with an open pull request: $(cat "$GH_LOG")"; fi

# The lock changed: a pull request with only that directory's files, and
# no auto-merge unless asked.
change; echo stray > "$repo/other.txt"
run X=1
if [ "$(calls create)" != 1 ] || [ "$(mutations AutoMerge)" != 0 ]; then fail "changed: $(cat "$GH_LOG")"; fi
if [ "$(git -C "$tmp/remote" show factory/update/apps-web:apps/web/app.lock.yaml)" != "moved 1" ] || [ "$(git -C "$tmp/remote" show factory/update/apps-web:other.txt)" != b ]; then
  fail "the branch should carry apps/web only"
fi
git -C "$repo" checkout -q -- other.txt
# The dependencies label may not exist: created without it.
change; run GH_LABEL_FAILS=true
if [ "$(calls create)" != 2 ]; then fail "label fallback: $(cat "$GH_LOG")"; fi
# Open already: edited, not created.
change; run GH_STATE=OPEN
if [ "$(calls create)" != 0 ] || [ "$(calls edit)" != 1 ]; then fail "open: $(cat "$GH_LOG")"; fi

# Auto-merge: only for the kinds listed, through the GraphQL mutation (gh
# pr merge --auto merges a pull request that is mergeable already at once).
change; run AUTO_MERGE="pin rebuild" PR_KIND=update
if [ "$(mutations AutoMerge)" != 0 ]; then fail "update is not listed: $(cat "$GH_LOG")"; fi
change; run AUTO_MERGE="pin,update" PR_KIND=update
if [ "$(mutations enablePullRequestAutoMerge)" != 1 ] || ! grep -q "auto-merge is on" "$tmp/out" || ! grep -q "mergeMethod: MERGE" "$GH_LOG"; then fail "update listed: $(cat "$GH_LOG") $(cat "$tmp/out")"; fi
change; run AUTO_MERGE="pin
  update" PR_KIND=update
if [ "$(mutations enablePullRequestAutoMerge)" != 1 ]; then fail "a list on several lines: $(cat "$GH_LOG")"; fi
change; run AUTO_MERGE=all PR_KIND=rebuild
if [ "$(mutations enablePullRequestAutoMerge)" != 1 ]; then fail "all: $(cat "$GH_LOG")"; fi
change; run AUTO_MERGE=all PR_KIND=rebuild GH_AUTO_ON=true
if [ "$(mutations AutoMerge)" != 0 ] || ! grep -q "auto-merge is on" "$tmp/out"; then fail "already on: $(cat "$GH_LOG") $(cat "$tmp/out")"; fi
change; run AUTO_MERGE=all
if [ "$(mutations AutoMerge)" != 0 ]; then fail "no kind: $(cat "$GH_LOG")"; fi
# A pin pull request with auto-merge became a rebuild, which isn't listed:
# auto-merge is turned off, so the rebuild doesn't merge by itself.
change; run AUTO_MERGE=pin PR_KIND=rebuild GH_AUTO_ON=true
if [ "$(mutations disablePullRequestAutoMerge)" != 1 ] || [ "$(mutations enablePullRequestAutoMerge)" != 0 ] || ! grep -q "auto-merge is off" "$tmp/out"; then fail "unlisted kind with auto-merge on: $(cat "$GH_LOG") $(cat "$tmp/out")"; fi
change; run PR_KIND=update GH_AUTO_ON=true
if [ "$(mutations disablePullRequestAutoMerge)" != 1 ]; then fail "auto-merge off, a pull request with it on: $(cat "$GH_LOG")"; fi
# GitHub refuses (auto-merge not allowed, or no required checks: "clean
# status"): a warning, exit 0, the pull request open and unmerged.
change
if ! run AUTO_MERGE=update PR_KIND=update GH_MERGE_FAILS="Pull request is in clean status"; then fail "a refused auto-merge failed the job: $(cat "$tmp/out")"; fi
if ! grep -q '^::warning::auto-merge could not be turned on' "$tmp/out" || ! grep -q "clean status" "$tmp/out" || [ "$(calls close)" != 0 ] || [ "$(calls merge)" != 0 ]; then fail "refused: $(cat "$tmp/out")"; fi

if [ "$failures" -gt 0 ]; then
  echo "$failures failed"
  exit 1
fi
echo "open-pr: ok"
