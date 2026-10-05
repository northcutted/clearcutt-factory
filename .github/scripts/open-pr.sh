#!/usr/bin/env bash
# Opens, or updates, a pull request with the changes under PATH... on BRANCH
# (recreated from the current commit each time, so it never goes stale).
#
# Usage: open-pr.sh BRANCH TITLE BODY_FILE PATH...
set -euo pipefail
branch=$1 title=$2 body=$3
shift 3

if git diff --quiet -- "$@" && [ -z "$(git ls-files --others --exclude-standard -- "$@")" ]; then
  echo "no changes under $*; nothing to propose"
  exit 0
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git switch -C "$branch"
git add -- "$@"
git commit -q -m "$title"
git push -q --force origin "$branch"

if [ "$(gh pr view "$branch" --json state --jq .state 2>/dev/null || true)" = OPEN ]; then
  gh pr edit "$branch" --title "$title" --body-file "$body"
else
  gh pr create --head "$branch" --title "$title" --body-file "$body" --label dependencies ||
    gh pr create --head "$branch" --title "$title" --body-file "$body"
fi
