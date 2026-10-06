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

# Reusable workflow defaults and every pinned reference to this repository.
# (The only version-shaped input defaults are factory-version's.)
perl -pi -e 's/^(\s+default: )v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/${1}'"$version"'/' .github/workflows/*.yml
perl -pi -e 's#(northcutted/clearcutt-factory(?:/\.github/workflows/[a-z-]+\.yml)?)\@v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?#$1\@'"$version"'#g' \
  .github/workflows/*.yml action.yml README.md docs/*.md

go test ./internal/factory -run TestInit >/dev/null
git add -A
git commit -q -m "Release $version"
git tag -a "$version" -m "$version"
echo "tagged $version; push with: git push origin main $version"
