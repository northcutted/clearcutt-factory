#!/usr/bin/env bash
# Cuts a release: points the reusable workflows, the action examples, and the
# docs at VERSION, commits that, and tags it. Pushing the tag runs
# .github/workflows/release.yml, which builds, signs, and publishes.
#
# Usage: scripts/release.sh vX.Y.Z   (then: git push origin main vX.Y.Z)
set -euo pipefail
version=${1:?usage: scripts/release.sh vX.Y.Z}
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "not a version: $version" >&2; exit 1; }
cd "$(dirname "$0")/.."
grep -q "^## $version" CHANGELOG.md || { echo "CHANGELOG.md has no '## $version' section" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "working tree is not clean" >&2; exit 1; }

# Reusable workflow defaults and every pinned reference to this repository:
# the action, the reusable workflows (also as certificate identities, at
# @refs/tags/), and go install. (The only version-shaped input defaults are
# factory-version's.)
semver='v\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?'
perl -pi -e 's/^(\s+default: )'"$semver"'$/${1}'"$version"'/' .github/workflows/*.yml
perl -pi -e 's#(northcutted/clearcutt-factory(?:/\.github/workflows/[a-z-]+\.yml|/cmd/clearcutt-factory)?\@(?:refs/tags/)?)'"$semver"'#${1}'"$version"'#g' \
  .github/workflows/*.yml action.yml README.md docs/*.md
# app.yml calls this repository's reusable workflows at the release it is
# part of: from main (before the first release) to the tag.
perl -pi -e 's#(northcutted/clearcutt-factory/\.github/workflows/[a-z-]+\.yml\@)main$#${1}'"$version"'#' .github/workflows/app.yml
# The release the install instructions download (v=… in docs/adopting.md).
perl -pi -e 's/^v='"$semver"'(?= )/v='"$version"'/' README.md docs/*.md
# Nothing a rewrite missed (a ref with a comment after it, a branch): every
# workflow must call factory's own at the new tag, or nothing is committed.
if ! scripts/check-release-refs.sh "$version"; then
  echo "release.sh: nothing committed or tagged; fix the refs above (git checkout -- . undoes the rewrite)" >&2
  exit 1
fi

go test ./internal/factory -run TestInit >/dev/null
git add -A
if ! git diff --cached --quiet; then
  git commit -q -m "Release $version"
fi
git tag -a "$version" -m "$version"
echo "tagged $version; push with: git push origin main $version"
