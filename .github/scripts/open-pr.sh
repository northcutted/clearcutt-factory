#!/usr/bin/env bash
# Opens, or updates, a pull request with the changes under PATH... on BRANCH
# (recreated from the current commit each time, so it never goes stale), and
# closes the pull request once there is nothing left to change.
#
# Usage: open-pr.sh BRANCH TITLE BODY_FILE PATH...
#
# With AUTO_MERGE naming the pull request's kind (PR_KIND: pin, rebuild, or
# update; AUTO_MERGE lists kinds, space- or comma-separated, or all), GitHub
# auto-merge (merge commit) is turned on for it, so it merges by itself once
# the base branch's required checks pass. That needs "Allow auto-merge" in
# the repository settings and branch protection (or a ruleset) with required
# status checks on the base branch, and an opener whose pull requests get CI
# (a GitHub App or token, not GITHUB_TOKEN). When it can't be turned on, the
# pull request stays open, with a warning: never a failed job.
set -euo pipefail
branch=$1 title=$2 body=$3
shift 3

open=$(gh pr view "$branch" --json state --jq .state 2>/dev/null || true)

if git diff --quiet -- "$@" && [ -z "$(git ls-files --others --exclude-standard -- "$@")" ]; then
  echo "no changes under $*; nothing to propose"
  if [ "$open" = OPEN ]; then
    gh pr close "$branch" --delete-branch --comment "Nothing to change anymore; closing."
  fi
  exit 0
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git switch -C "$branch"
git add -- "$@"
git commit -q -m "$title"
git push -q --force origin "$branch"

if [ "$open" = OPEN ]; then
  gh pr edit "$branch" --title "$title" --body-file "$body"
else
  gh pr create --head "$branch" --title "$title" --body-file "$body" --label dependencies ||
    gh pr create --head "$branch" --title "$title" --body-file "$body"
fi

# Auto-merge for the kinds asked for, through GitHub's
# enablePullRequestAutoMerge, which refuses a pull request that is
# mergeable already (no required checks) rather than merge it at once, as
# "gh pr merge --auto" does. A pull request that already has it keeps it
# (a new push doesn't turn it off). One of a kind not listed has it turned
# off: fleet.yml's branch holds a pin, then a rebuild, and auto-merge turned
# on for the pin would otherwise merge the rebuild.
kinds=" $(printf '%s' "${AUTO_MERGE:-}" | tr -s ',[:space:]' ' ') "
listed=false
case "${PR_KIND:-}" in
  pin | rebuild | update)
    case "$kinds" in *" all "* | *" $PR_KIND "*) listed=true ;; esac
    ;;
esac
pr=$(gh pr view "$branch" --json id,autoMergeRequest --jq '"\(.id) \(.autoMergeRequest != null)"' 2>/dev/null || true)
id=${pr% *} on=${pr##* }
if [ "$listed" != true ]; then
  if [ "$on" = true ]; then
    if gh api graphql -f query='mutation($id: ID!) { disablePullRequestAutoMerge(input: {pullRequestId: $id}) { clientMutationId } }' -f id="$id" > /dev/null; then
      echo "auto-merge is off for $branch: ${PR_KIND:-this kind of pull request} is not among the kinds to merge by themselves (${AUTO_MERGE:-none})"
    else
      echo "::warning::auto-merge is on for $branch, a ${PR_KIND:-pull request} not among the kinds to merge by themselves (${AUTO_MERGE:-none}), and could not be turned off: turn it off by hand"
    fi
  fi
  exit 0
fi
if [ "$on" = true ]; then
  echo "auto-merge is on for $branch: it merges by itself once the required checks pass"
  exit 0
fi
if [ -n "$id" ] && out=$(gh api graphql -f query='mutation($id: ID!) { enablePullRequestAutoMerge(input: {pullRequestId: $id, mergeMethod: MERGE}) { clientMutationId } }' -f id="$id" 2>&1); then
  echo "auto-merge is on for $branch: it merges by itself once the required checks pass"
else
  echo "::warning::auto-merge could not be turned on for $branch; the pull request stays open for a person to merge. It needs \"Allow auto-merge\" in the repository settings, branch protection with required status checks on the base branch (without them a pull request is mergeable at once, and nothing would gate it), and an opener whose pull requests get CI (a GitHub App or CLEARCUTT_BOT_TOKEN). GitHub said: ${out//$'\n'/ }"
fi
